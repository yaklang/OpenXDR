package feishuapproval

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/hostimport"
)

func jsonReply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/approvals/feishu", s.status)
	mux.HandleFunc("PUT /api/settings/feishu-approval", s.saveConfig)
	mux.HandleFunc("POST /api/approvals/feishu/bind", func(w http.ResponseWriter, r *http.Request) {
		u := auth.From(r.Context())
		if u == nil {
			http.Error(w, "未登录", 401)
			return
		}
		code, err := s.bindingCode(r.Context(), u)
		if err != nil {
			http.Error(w, "生成绑定码失败，请检查配置", 409)
			return
		}
		jsonReply(w, map[string]any{"code": code, "expires_in": 600})
	})
	mux.HandleFunc("DELETE /api/approvals/feishu/bind", func(w http.ResponseWriter, r *http.Request) {
		u := auth.From(r.Context())
		if u == nil {
			http.Error(w, "未登录", 401)
			return
		}
		if err := s.unbind(r.Context(), u); err != nil {
			http.Error(w, "解绑失败", 500)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /api/approvals/feishu/test", s.testMessage)
}

func (s *Service) status(w http.ResponseWriter, r *http.Request) {
	u := auth.From(r.Context())
	if u == nil {
		http.Error(w, "未登录", 401)
		return
	}
	c, err := readConfig(r.Context(), s.SQL, false)
	if err != nil {
		http.Error(w, "读取配置失败", 500)
		return
	}
	var bound bool
	err = s.SQL.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM feishu_approval_bindings WHERE app_id=$1 AND user_id=$2)`, c.AppID, u.ID).Scan(&bound)
	if err != nil {
		http.Error(w, "读取绑定失败", 500)
		return
	}
	var tested bool
	_ = s.SQL.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM feishu_approval_deliveries WHERE app_id=$1 AND revision=$2 AND user_id=$3 AND approval_id IS NULL AND outcome<>'')`, c.AppID, c.Revision, u.ID).Scan(&tested)
	result := map[string]any{"enabled": c.Enabled, "app_id": c.AppID, "secret_set": len(c.Sealed) > 0, "bound": bound, "connection": s.getState(), "callback_verified": tested}
	if u.Role == "admin" {
		result["diagnostic"] = s.diagnostics()
	}
	jsonReply(w, result)
}

func (s *Service) saveConfig(w http.ResponseWriter, r *http.Request) {
	u := auth.From(r.Context())
	if u == nil || u.Role != "admin" {
		http.Error(w, "仅管理员可以配置", 403)
		return
	}
	var body struct {
		Enabled bool   `json:"enabled"`
		AppID   string `json:"app_id"`
		Secret  string `json:"app_secret"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body) != nil || !regexp.MustCompile(`^cli_[a-zA-Z0-9]{8,80}$`).MatchString(body.AppID) || len(body.Secret) > 512 {
		http.Error(w, "配置格式无效", 400)
		return
	}
	tx, err := s.SQL.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "配置保存失败", 500)
		return
	}
	defer tx.Rollback()
	// 同一把事务锁串行化配置编辑，避免覆盖另一个管理员保存的密钥。
	_, err = tx.ExecContext(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended('openxdr:feishu-config',0))`)
	c := Config{}
	if err == nil {
		c, err = readConfig(r.Context(), tx, false)
	}
	if err == nil && c.AppID != body.AppID {
		c.Sealed = nil
	}
	if err == nil && body.Secret != "" {
		if s.Vault == nil {
			err = errors.New("凭据加密不可用")
		} else {
			c.Sealed, err = s.Vault.Seal(hostimport.Secret{Password: body.Secret}, "feishu-approval:"+body.AppID)
		}
	}
	if err == nil && body.Enabled && len(c.Sealed) == 0 {
		http.Error(w, "请提供应用密钥", 400)
		return
	}
	if err == nil {
		c.AppID = body.AppID
		c.Enabled = body.Enabled
		c.Revision = uuid.NewString()
		raw, _ := json.Marshal(c)
		_, err = tx.ExecContext(r.Context(), `INSERT INTO settings(id,value,updated_at) VALUES($1,$2,now()) ON CONFLICT(id) DO UPDATE SET value=excluded.value,updated_at=now()`, configKey, string(raw))
	}
	if err == nil {
		err = sqlAudit(r.Context(), tx, u.Username, "feishu_configured", body.AppID)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		http.Error(w, "配置保存失败", 500)
		return
	}
	w.WriteHeader(204)
}

func (s *Service) testMessage(w http.ResponseWriter, r *http.Request) {
	u := auth.From(r.Context())
	if u == nil {
		http.Error(w, "未登录", 401)
		return
	}
	tx, err := s.SQL.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "请求失败", 500)
		return
	}
	defer tx.Rollback()
	c, err := readConfig(r.Context(), tx, true)
	if err != nil || !validConfig(c) {
		http.Error(w, "飞书审批尚未启用", 409)
		return
	}
	var tenant, openID string
	err = tx.QueryRowContext(r.Context(), `SELECT tenant,open_id FROM feishu_approval_bindings WHERE app_id=$1 AND user_id=$2 FOR UPDATE`, c.AppID, u.ID).Scan(&tenant, &openID)
	if err != nil {
		http.Error(w, "请先绑定本人飞书账号", 409)
		return
	}
	var recent bool
	err = tx.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM feishu_approval_deliveries WHERE user_id=$1 AND approval_id IS NULL AND created_at>now()-interval '1 minute')`, u.ID).Scan(&recent)
	if err != nil || recent {
		http.Error(w, "请一分钟后再试", 429)
		return
	}
	_, err = tx.ExecContext(r.Context(), `INSERT INTO feishu_approval_deliveries(nonce,user_id,app_id,revision,tenant,open_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.NewString(), u.ID, c.AppID, c.Revision, tenant, openID, time.Now().Add(10*time.Minute))
	if err == nil {
		err = sqlAudit(r.Context(), tx, u.Username, "feishu_private_test_requested", u.ID.String())
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		http.Error(w, "测试请求失败", 500)
		return
	}
	w.WriteHeader(202)
}
