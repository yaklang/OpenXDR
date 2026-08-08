package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entintel "openxdr/server/ent/intel"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/intel"
)

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
		rows, err := db.Intel.Query().
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
		if json.NewDecoder(r.Body).Decode(&body) != nil || strings.TrimSpace(body.Text) == "" {
			http.Error(w, "text 必填", http.StatusBadRequest)
			return
		}
		if body.Source == "" {
			body.Source = "import"
		}
		if body.Severity == 0 {
			body.Severity = 4
		}
		var expires *time.Time
		if body.ExpiresInDays > 0 {
			t := time.Now().AddDate(0, 0, body.ExpiresInDays)
			expires = &t
		}

		// 重复条目直接跳过，反复导入同一份情报源不报错。
		// 情报表本就整表进内存索引，查一遍现有键的代价可以忽略。
		existing, err := db.Intel.Query().All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		seen := make(map[string]bool, len(existing))
		for _, row := range existing {
			seen[string(row.Kind)+":"+row.Value] = true
		}

		var creates []*ent.IntelCreate
		var imported, skipped int
		for _, line := range strings.Split(body.Text, "\n") {
			value := strings.TrimSpace(line)
			if value == "" || strings.HasPrefix(value, "#") {
				continue
			}
			kind, value := detectKind(value)
			if seen[kind+":"+value] {
				skipped++
				continue
			}
			seen[kind+":"+value] = true
			imported++
			creates = append(creates, db.Intel.Create().
				SetKind(entintel.Kind(kind)).
				SetValue(value).
				SetSource(body.Source).
				SetSeverity(body.Severity).
				SetNillableExpiresAt(expires))
		}
		if imported+skipped == 0 {
			http.Error(w, "没有可导入的条目", http.StatusBadRequest)
			return
		}
		if len(creates) > 0 {
			if _, err := db.Intel.CreateBulk(creates...).Save(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			store.Reload(r.Context())
		}
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
		if json.NewDecoder(r.Body).Decode(&body) != nil || strings.TrimSpace(body.Value) == "" {
			http.Error(w, "value 必填", http.StatusBadRequest)
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
	if net.ParseIP(v) != nil {
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
