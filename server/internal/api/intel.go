package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entintel "openxdr/server/ent/intel"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/intel"
)

const (
	maxIntelBodyBytes   = 1 << 20
	maxIntelImportBytes = 10 << 20
	intelBatchChunk     = 1000
)

var (
	// RFC 6598 共享地址与 240.0.0.0/4 保留地址不属于 IsPrivate / !IsGlobalUnicast 覆盖范围
	intelCGNAT      = netip.MustParsePrefix("100.64.0.0/10")
	intelReservedV4 = netip.MustParsePrefix("240.0.0.0/4")
)

// validIntelIP 校验并规范化情报 IP：拒绝非法地址及私网、回环、链路本地、CGNAT、保留地址，避免误封内网。
func validIntelIP(raw string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || intelCGNAT.Contains(addr) || intelReservedV4.Contains(addr) {
		return "", false
	}
	return addr.String(), true
}

func validIntelSeverity(s int16) bool { return s >= 1 && s <= 5 }

func decodeIntelBody(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, limit)).Decode(dst)
}

func writeBodyError(w http.ResponseWriter, err error, badMsg string) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		http.Error(w, "请求体超过大小上限", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, badMsg, http.StatusBadRequest)
}

// existingIntelKeys 按导入集合分批查库中已存在的 (kind, value) 键，避免整表加载。
func existingIntelKeys(ctx context.Context, db *ent.Client, byKind map[string][]string) (map[string]bool, error) {
	seen := make(map[string]bool)
	for kind, vals := range byKind {
		for start := 0; start < len(vals); start += intelBatchChunk {
			end := min(start+intelBatchChunk, len(vals))
			rows, err := db.Intel.Query().
				Where(entintel.KindEQ(entintel.Kind(kind)), entintel.ValueIn(vals[start:end]...)).
				Select(entintel.FieldKind, entintel.FieldValue).
				All(ctx)
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				seen[string(row.Kind)+":"+row.Value] = true
			}
		}
	}
	return seen, nil
}

type intelRow struct {
	ID            uuid.UUID  `json:"id"`
	CreatedAt     time.Time  `json:"createdAt"`
	Kind          string     `json:"kind"`
	Value         string     `json:"value"`
	Source        string     `json:"source"`
	Severity      int16      `json:"severity"`
	Note          *string    `json:"note"`
	ExpiresAt     *time.Time `json:"expiresAt"`
	MatchedCount  int        `json:"matchedCount"`
	LastMatchedAt *time.Time `json:"lastMatchedAt"`
}

func toIntelRow(r *ent.Intel) intelRow {
	return intelRow{
		ID: r.ID, CreatedAt: r.CreatedAt, Kind: string(r.Kind), Value: r.Value,
		Source: r.Source, Severity: r.Severity, Note: r.Note, ExpiresAt: r.ExpiresAt,
		MatchedCount: r.MatchedCount, LastMatchedAt: r.LastMatchedAt,
	}
}

func mapIntel(api *http.ServeMux, db *ent.Client, store *intel.Store) {
	api.HandleFunc("GET /api/intel", func(w http.ResponseWriter, r *http.Request) {
		// 订阅条目成千上万，单独在订阅卡片里看，列表只放手工与导入的情报
		rows, err := db.Intel.Query().
			Where(entintel.Not(entintel.SourceHasPrefix("feed:"))).
			Order(ent.Desc(entintel.FieldCreatedAt)).
			Limit(500).
			All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]intelRow, len(rows))
		for i, row := range rows {
			out[i] = toIntelRow(row)
		}
		writeJSON(w, out)
	})

	// 批量导入：一行一个 IOC，类型自动识别。适合直接粘贴情报源导出的清单。
	api.HandleFunc("POST /api/intel/import", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Text     string `json:"text"`
			Source   string `json:"source"`
			Severity int16  `json:"severity"`
			// 有效期天数，0 表示长期有效
			ExpiresInDays int `json:"expiresInDays"`
		}
		if err := decodeIntelBody(w, r, maxIntelImportBytes, &body); err != nil {
			writeBodyError(w, err, "text 必填")
			return
		}
		if strings.TrimSpace(body.Text) == "" {
			http.Error(w, "text 必填", http.StatusBadRequest)
			return
		}
		if body.Source == "" {
			body.Source = "import"
		}
		if body.Severity == 0 {
			body.Severity = 4
		}
		if !validIntelSeverity(body.Severity) {
			http.Error(w, "severity 必须在 1 到 5 之间", http.StatusBadRequest)
			return
		}
		var expires *time.Time
		if body.ExpiresInDays > 0 {
			t := time.Now().AddDate(0, 0, body.ExpiresInDays)
			expires = &t
		}

		type candidate struct{ kind, value string }
		var candidates []candidate
		byKind := map[string][]string{}
		inBatch := map[string]bool{}
		var skipped int
		for _, line := range strings.Split(body.Text, "\n") {
			rawVal := strings.TrimSpace(line)
			if rawVal == "" || strings.HasPrefix(rawVal, "#") {
				continue
			}
			kind, value := detectKind(rawVal)
			if kind == "ip" {
				norm, ok := validIntelIP(value)
				if !ok {
					skipped++
					continue
				}
				value = norm
			}
			key := kind + ":" + value
			if inBatch[key] {
				skipped++
				continue
			}
			inBatch[key] = true
			candidates = append(candidates, candidate{kind, value})
			byKind[kind] = append(byKind[kind], value)
		}
		if len(candidates)+skipped == 0 {
			http.Error(w, "没有可导入的条目", http.StatusBadRequest)
			return
		}

		existing, err := existingIntelKeys(r.Context(), db, byKind)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var fresh []candidate
		for _, c := range candidates {
			if existing[c.kind+":"+c.value] {
				skipped++
				continue
			}
			fresh = append(fresh, c)
		}
		// 分块写入放在同一事务里：某块失败就整体回滚，不留下半截导入
		if len(fresh) > 0 {
			err := withTx(r, db, func(tx *ent.Tx) error {
				for start := 0; start < len(fresh); start += intelBatchChunk {
					creates := make([]*ent.IntelCreate, 0, intelBatchChunk)
					for _, c := range fresh[start:min(start+intelBatchChunk, len(fresh))] {
						creates = append(creates, tx.Intel.Create().
							SetKind(entintel.Kind(c.kind)).
							SetValue(c.value).
							SetSource(body.Source).
							SetSeverity(body.Severity).
							SetNillableExpiresAt(expires))
					}
					if _, err := tx.Intel.CreateBulk(creates...).Save(r.Context()); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			store.Reload(r.Context())
		}
		imported := len(fresh)
		audit.Log(r.Context(), db, r, "intel_imported", body.Source, "")
		writeJSON(w, map[string]int{"imported": imported, "skipped": skipped})
	})

	api.HandleFunc("POST /api/intel", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Kind     string `json:"kind"`
			Value    string `json:"value"`
			Source   string `json:"source"`
			Severity int16  `json:"severity"`
			Note     string `json:"note"`
			// 有效期天数，0 表示长期有效
			ExpiresInDays int `json:"expiresInDays"`
		}
		if err := decodeIntelBody(w, r, maxIntelBodyBytes, &body); err != nil {
			writeBodyError(w, err, "value 必填")
			return
		}
		if strings.TrimSpace(body.Value) == "" {
			http.Error(w, "value 必填", http.StatusBadRequest)
			return
		}
		if body.Severity != 0 && !validIntelSeverity(body.Severity) {
			http.Error(w, "severity 必须在 1 到 5 之间", http.StatusBadRequest)
			return
		}
		kind, value := detectKind(strings.TrimSpace(body.Value))
		if body.Kind != "" {
			kind = body.Kind
		}
		if kind != "ip" && kind != "domain" && kind != "hash" {
			http.Error(w, "kind 只能是 ip / domain / hash", http.StatusBadRequest)
			return
		}
		if kind == "ip" {
			norm, ok := validIntelIP(value)
			if !ok {
				http.Error(w, "IP 地址无效或属于私网/保留地址", http.StatusBadRequest)
				return
			}
			value = norm
		}

		create := db.Intel.Create().
			SetKind(entintel.Kind(kind)).
			SetValue(value)
		if body.Source != "" {
			create.SetSource(body.Source)
		}
		if body.Severity != 0 {
			create.SetSeverity(body.Severity)
		}
		if body.Note != "" {
			create.SetNote(body.Note)
		}
		if body.ExpiresInDays > 0 {
			create.SetExpiresAt(time.Now().AddDate(0, 0, body.ExpiresInDays))
		}
		row, err := create.Save(r.Context())
		if ent.IsConstraintError(err) {
			http.Error(w, "该 IOC 已存在", http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		store.Reload(r.Context())
		audit.Log(r.Context(), db, r, "intel_created", row.ID.String(), kind+":"+value)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, toIntelRow(row))
	})

	api.HandleFunc("DELETE /api/intel/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 id", http.StatusBadRequest)
			return
		}
		err = db.Intel.DeleteOneID(id).Exec(r.Context())
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		store.Reload(r.Context())
		audit.Log(r.Context(), db, r, "intel_deleted", id.String(), "")
		w.WriteHeader(http.StatusNoContent)
	})
}

// detectKind 按取值形态识别 IOC 类型：IP 字面量 / 十六进制哈希（MD5、SHA-1、SHA-256）/
// 其余当域名。域名与哈希统一小写，与匹配侧的归一化保持一致。
func detectKind(v string) (string, string) {
	if _, err := netip.ParseAddr(v); err == nil {
		return "ip", v
	}
	lower := strings.ToLower(v)
	if l := len(lower); (l == 32 || l == 40 || l == 64) && isHex(lower) {
		return "hash", lower
	}
	return "domain", strings.TrimSuffix(lower, ".")
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
