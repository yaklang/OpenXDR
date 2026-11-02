package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
	"unicode"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/deception/contract"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/decoydeployment"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/decoy"
	"path"
	"strings"
)

func mapSSHDecoys(mux *http.ServeMux, db *ent.Client) {
	// 旧 SSH 路径保留兼容，通用路径共用权限与事务处理。
	mux.HandleFunc("/api/decoys", func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		clone.URL.Path = "/api/ssh-decoys"
		mux.ServeHTTP(w, clone)
	})
	mux.HandleFunc("POST /api/decoys/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(r.Context())
		clone.URL.Path = "/api/ssh-decoys/" + r.PathValue("id") + "/revoke"
		mux.ServeHTTP(w, clone)
	})
	mux.HandleFunc("GET /api/decoy-profiles", func(w http.ResponseWriter, r *http.Request) {
		if decoyAuthenticated(w, r) {
			writeJSON(w, decoy.Profiles())
		}
	})
	mapDecoyRuntimeManagement(mux, db)
	mapDecoyReview(mux, db)
	mapDeceptionManagement(mux, db)

	mux.HandleFunc("GET /api/ssh-decoy-profiles", func(w http.ResponseWriter, r *http.Request) {
		if decoyAuthenticated(w, r) {
			writeJSON(w, contract.SSHProfiles())
		}
	})
	mux.HandleFunc("GET /api/ssh-decoys", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		groupID, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", 400)
			return
		}
		if !requireGroup(w, r, db, groupID, "viewer") {
			return
		}
		offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
		if r.URL.Query().Get("offset") == "" {
			offset, err = 0, nil
		}
		if err != nil || offset < 0 || offset > 1000000 {
			http.Error(w, "offset 无效", 400)
			return
		}
		rows, err := db.DecoyDeployment.Query().Where(func(s *sql.Selector) {
			assets := sql.Table(asset.Table)
			s.Where(sql.In(s.C(decoydeployment.FieldAssetID), sql.Select(assets.C(asset.FieldID)).From(assets).Where(sql.EQ(assets.C(asset.FieldGroupID), groupID))))
		}).Order(ent.Desc(decoydeployment.FieldCreatedAt), ent.Desc(decoydeployment.FieldID)).Offset(offset).Limit(51).All(r.Context())
		if err != nil {
			http.Error(w, "查询诱饵登记失败", 500)
			return
		}
		more := len(rows) > 50
		if more {
			rows = rows[:50]
		}
		type deploymentView struct {
			*ent.DecoyDeployment
			RuntimeStatus     string `json:"runtime_status"`
			RemoteInstallable bool   `json:"remote_installable"`
			Hosted            bool   `json:"hosted"`
		}
		items := make([]deploymentView, 0, len(rows))
		now := time.Now()
		for _, row := range rows {
			if row.InstallState == decoydeployment.InstallStateInstalling && row.InstallStartedAt != nil && now.Sub(*row.InstallStartedAt) > 3*time.Minute {
				row.InstallState = decoydeployment.InstallStateUnconfirmed
			}
			hosted := false
			if row.ActiveRevisionID != nil {
				if rev, e := db.DecoyRevision.Get(r.Context(), *row.ActiveRevisionID); e == nil {
					if cfg, e := revisionConfig(rev); e == nil {
						hosted = cfg.Hosted
					}
				}
			}
			items = append(items, deploymentView{row, decoyRuntimeStatus(row, now), row.ActiveRevisionID == nil && row.Status == decoydeployment.StatusRegistered && row.InstallState == decoydeployment.InstallStateIdle && row.RuntimeInstanceID == nil && row.TokenHash == "" && row.Kind != decoydeployment.KindShell && (row.Port == 0 || row.Port >= 1024), hosted})
		}
		writeJSON(w, struct {
			Items []deploymentView `json:"items"`
			More  bool             `json:"more"`
		}{items, more})
	})
	mux.HandleFunc("POST /api/ssh-decoys", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		var body struct {
			AssetID  uuid.UUID `json:"assetId"`
			Profile  string    `json:"profile"`
			Port     int       `json:"port"`
			Kind     string    `json:"kind"`
			Resource string    `json:"resource"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF || body.AssetID == uuid.Nil || body.Port < 0 || body.Port > 65535 {
			http.Error(w, "资产、策略或端口无效", 400)
			return
		}
		if body.Kind == "" {
			body.Kind = "ssh"
		}
		profile, err := decoy.Lookup(body.Kind, body.Profile)
		if err != nil || !validDecoyResource(body.Kind, body.Resource, body.Port) {
			http.Error(w, "载体、策略或资源无效", 400)
			return
		}
		tx, err := db.Tx(r.Context())
		if err != nil {
			http.Error(w, "开启事务失败", 500)
			return
		}
		defer tx.Rollback()
		if !lockDecoyAsset(w, r, tx, body.AssetID) {
			return
		}
		row, err := tx.DecoyDeployment.Create().SetAssetID(body.AssetID).SetKind(decoydeployment.Kind(body.Kind)).SetResource(body.Resource).SetProfile(profile.ID).SetTemplate(profile.Template).SetPort(body.Port).SetCreatedBy(auth.From(r.Context()).Username).Save(r.Context())
		if ent.IsConstraintError(err) {
			http.Error(w, "该资产端口已有未撤销登记", 409)
			return
		}
		if err == nil {
			err = decoyAudit(r, tx, "decoy_registered", row.ID)
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			http.Error(w, "保存诱饵登记失败", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		writeJSON(w, row)
	})
	mux.HandleFunc("POST /api/ssh-decoys/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "id 无效", 400)
			return
		}
		tx, err := db.Tx(r.Context())
		if err != nil {
			http.Error(w, "开启事务失败", 500)
			return
		}
		defer tx.Rollback()
		row, err := tx.DecoyDeployment.Get(r.Context(), id)
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "查询诱饵登记失败", 500)
			return
		}
		if !lockDecoyAsset(w, r, tx, row.AssetID) {
			return
		}
		n, err := tx.DecoyDeployment.Update().Where(decoydeployment.IDEQ(id), decoydeployment.StatusEQ(decoydeployment.StatusRegistered)).SetStatus(decoydeployment.StatusRevoked).ClearTokenHash().ClearTokenExpiresAt().ClearTokenGroupID().ClearTokenRevisionID().SetRevokedAt(time.Now()).SetRevokedBy(auth.From(r.Context()).Username).Save(r.Context())
		if err == nil && n > 0 {
			err = decoyAudit(r, tx, "decoy_registration_revoked", id)
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			http.Error(w, "撤销诱饵登记失败", 500)
			return
		}
		w.WriteHeader(204)
	})
}

func decoyAuthenticated(w http.ResponseWriter, r *http.Request) bool {
	if auth.From(r.Context()) == nil {
		http.Error(w, "请先登录", 401)
		return false
	}
	return true
}

// 锁住资产直到登记与审计一并提交，避免迁组与授权检查之间发生竞争。
func lockDecoyAsset(w http.ResponseWriter, r *http.Request, tx *ent.Tx, id uuid.UUID) bool {
	return lockDecoyAssetAs(w, r, tx, id, "admin")
}
func lockDecoyAssetAs(w http.ResponseWriter, r *http.Request, tx *ent.Tx, id uuid.UUID, role string) bool {
	if !auth.Allowed(auth.From(r.Context()).Role, "analyst") {
		http.Error(w, "当前角色无此权限", 403)
		return false
	}
	a, err := tx.Asset.Query().Where(asset.IDEQ(id), func(s *sql.Selector) { s.ForUpdate() }).Only(r.Context())
	if ent.IsNotFound(err) {
		http.NotFound(w, r)
		return false
	}
	if err != nil {
		http.Error(w, "查询资产失败", 500)
		return false
	}
	if a.GroupID == nil {
		http.Error(w, "请先将资产分组", 409)
		return false
	}
	return requireGroup(w, r, tx.Client(), *a.GroupID, role)
}
func decoyAudit(r *http.Request, tx *ent.Tx, action string, id uuid.UUID) error {
	u := auth.From(r.Context())
	if u == nil {
		return errors.New("未登录")
	}
	return audit.Checked(r.Context(), tx.AuditLog.Create(), u.Username, audit.RemoteAddr(r), action, id.String(), "仅变更登记；不启动或停止远程 SSH 服务")
}

func validDecoyResource(kind, resource string, port int) bool {
	switch kind {
	case "ssh", "http":
		return port > 0 && resource == ""
	case "file":
		return port == 0 && len(resource) <= 128 && strings.HasSuffix(resource, ".md") && path.Base(resource) == resource && !strings.ContainsAny(resource, "\\:\x00") && resource != ".md" && strings.IndexFunc(resource, unicode.IsControl) < 0
	case "shell":
		return port == 0 && resource == "simulated-shell"
	}
	return false
}
