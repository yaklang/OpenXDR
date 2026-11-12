package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/fact"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/sshkeys"
)

// SSHKeys 钥匙盘点 REST 接口：观测列表（按组可见）、管理员认领（写 key 事实与审计）、生成移除提议（走现有审批）。
func SSHKeys(db *ent.Client, svc *sshkeys.Service) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/ssh-keys", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		var filterAsset *uuid.UUID
		if v := strings.TrimSpace(r.URL.Query().Get("assetId")); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				http.Error(w, "无效的 assetId", http.StatusBadRequest)
				return
			}
			if !s.has(id) {
				writeJSON(w, sshkeys.ListResult{Keys: []sshkeys.KeyRow{}, HostConfigs: []sshkeys.HostKeyConfig{}})
				return
			}
			filterAsset = &id
		}
		visible, err := sshkeys.FilterVisibleAssets(r.Context(), db, s.asset(), filterAsset)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		res, err := sshkeys.List(r.Context(), db, visible, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, res)
	})

	// 认领钥匙：仅平台管理员可确认持有人、所在机器与用途，确认后写入权威 key 事实并留审计。
	mux.HandleFunc("POST /api/ssh-keys/claim", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var body struct {
			Fingerprint   string     `json:"fingerprint"`
			Holder        string     `json:"holder"`
			Machine       string     `json:"machine"`
			Purpose       string     `json:"purpose"`
			GroupID       *uuid.UUID `json:"groupId"`
			AssetID       *uuid.UUID `json:"assetId"`
			ExpiresInDays int        `json:"expiresInDays"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		fp := strings.TrimSpace(body.Fingerprint)
		holder := sanitizeInline(body.Holder, 256)
		machine := sanitizeInline(body.Machine, 256)
		purpose := sanitizeInline(body.Purpose, 600)
		if !sshkeys.ValidFingerprint(fp) {
			http.Error(w, "公钥指纹应形如 SHA256:<43 位 base64>", http.StatusBadRequest)
			return
		}
		if holder == "" {
			http.Error(w, "持有人不能为空", http.StatusBadRequest)
			return
		}
		if machine == "" {
			http.Error(w, "所在机器不能为空", http.StatusBadRequest)
			return
		}
		if purpose == "" {
			http.Error(w, "用途不能为空", http.StatusBadRequest)
			return
		}
		if body.ExpiresInDays < 0 || body.ExpiresInDays > 3650 {
			http.Error(w, errBadExpiry.Error(), http.StatusBadRequest)
			return
		}
		if body.AssetID != nil {
			a, err := db.Asset.Get(r.Context(), *body.AssetID)
			if err != nil {
				http.Error(w, "资产不存在", http.StatusBadRequest)
				return
			}
			body.GroupID = a.GroupID
		}
		content := fmt.Sprintf("所在机器：%s；用途：%s", machine, purpose)
		if err := facts.ValidateFact("key", fp, body.AssetID, content); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		actor := auth.From(r.Context()).Username
		now := time.Now()
		errConflict := errors.New("该钥匙已认领，如需变更请在事实页修改")
		var row *ent.Fact
		err := withTx(r, db, func(tx *ent.Tx) error {
			dupQ := tx.Fact.Query().Where(
				fact.KindEQ("key"),
				fact.SubjectEQ(fp),
				facts.Live(now),
			)
			if body.AssetID != nil {
				dupQ.Where(fact.AssetIDEQ(*body.AssetID))
			} else if body.GroupID != nil {
				dupQ.Where(fact.AssetIDIsNil(), fact.GroupIDEQ(*body.GroupID))
			} else {
				dupQ.Where(fact.AssetIDIsNil(), fact.GroupIDIsNil())
			}
			exists, err := dupQ.Exist(r.Context())
			if err != nil {
				return err
			}
			if exists {
				return errConflict
			}

			c := tx.Fact.Create().
				SetKind("key").
				SetSubject(fp).
				SetNillableGroupID(body.GroupID).
				SetNillableAssetID(body.AssetID).
				SetHolder(holder).
				SetContent(content).
				SetSource("human").
				SetCreatedBy(actor)
			if body.ExpiresInDays > 0 {
				c.SetExpiresAt(now.AddDate(0, 0, body.ExpiresInDays))
			}
			if row, err = c.Save(r.Context()); err != nil {
				return err
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor, audit.RemoteAddr(r), "fact_created", row.ID.String(),
				fmt.Sprintf("key %s 持有人=%s：%s", fp, holder, content))
		})
		if errors.Is(err, errConflict) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := toFactRow(row, hostnamesOf(r.Context(), db, assetIDs(row)))
		out.HolderName = principalNames(r.Context(), db, row.Holder)[row.Holder]
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, out)
	})

	// 为指定钥匙观测生成一条待批移除提议（走 commandgate 审批，从不自动删除）。
	mux.HandleFunc("POST /api/ssh-keys/{id}/propose-removal", func(w http.ResponseWriter, r *http.Request) {
		obs, ok := getByPath(w, r, "id", "ssh-key", db.SSHKeyObservation.Get)
		if !ok {
			return
		}
		assetRow, err := db.Asset.Get(r.Context(), obs.AssetID)
		if err != nil {
			http.Error(w, "资产不存在", http.StatusNotFound)
			return
		}
		u := auth.From(r.Context())
		if assetRow.GroupID == nil {
			if u.Role != "admin" {
				http.Error(w, "只有平台管理员可操作未分组资产", http.StatusForbidden)
				return
			}
			http.Error(w, "资产尚未归入资产组，无法进入组审批队列", http.StatusBadRequest)
			return
		}
		if !auth.Allowed(auth.GroupRole(r.Context(), db, u, *assetRow.GroupID), "admin") {
			http.Error(w, "只有组管理员可以提议移除钥匙", http.StatusForbidden)
			return
		}
		if svc == nil {
			http.Error(w, "钥匙盘点服务未启用", http.StatusServiceUnavailable)
			return
		}
		ap, err := svc.EnsureRemovalProposal(r.Context(), obs.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, ap)
	})

	return mux
}

func sanitizeInline(s string, maxRunes int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxRunes {
			break
		}
		if unicode.IsControl(r) {
			b.WriteByte(' ')
		} else {
			b.WriteRune(r)
		}
		n++
	}
	return strings.TrimSpace(b.String())
}
