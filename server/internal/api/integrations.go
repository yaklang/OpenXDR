package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/group"
	"openxdr/server/ent/integration"
	"openxdr/server/ent/integrationgroup"
	"openxdr/server/ent/integrationtoken"
	"openxdr/server/ent/user"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/hostimport"
	integrationapi "openxdr/server/internal/integration"
)

type integrationInput struct {
	Name                        string      `json:"name"`
	Purpose                     string      `json:"purpose"`
	OwnerID                     uuid.UUID   `json:"ownerId"`
	Enabled                     bool        `json:"enabled"`
	Scopes                      []string    `json:"scopes"`
	GroupIDs                    []uuid.UUID `json:"groupIds"`
	ResolutionEnabled           bool        `json:"resolutionEnabled"`
	AllowedResolutions          []string    `json:"allowedResolutions"`
	AllowMaliciousFalsePositive bool        `json:"allowMaliciousFalsePositive"`
}
type integrationRow struct {
	ID uuid.UUID `json:"id"`
	integrationInput
	PermissionVersion int64     `json:"permissionVersion"`
	CreatedAt         time.Time `json:"createdAt"`
}
type integrationTokenRow struct {
	ID             uuid.UUID  `json:"id"`
	Prefix         string     `json:"prefix"`
	Scopes         []string   `json:"scopes"`
	CreatedAt      time.Time  `json:"createdAt"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	Revoked        bool       `json:"revoked"`
	LastUsedAt     *time.Time `json:"lastUsedAt"`
	LastRemoteAddr string     `json:"lastRemoteAddr"`
	Token          string     `json:"token,omitempty"`
}

func integrationTokenDTO(t *ent.IntegrationToken) integrationTokenRow {
	return integrationTokenRow{t.ID, t.Prefix, t.Scopes, t.CreatedAt, t.ExpiresAt, t.Revoked, t.LastUsedAt, t.LastRemoteAddr, ""}
}
func integrationDecode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil || dec.Decode(new(any)) != io.EOF {
		integrationapi.Error(w, 400, "invalid_argument", "请求格式无效")
		return false
	}
	return true
}
func integrationFailure(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if ent.IsNotFound(err) {
		integrationapi.Error(w, 404, "not_found", "集成不存在")
	} else {
		integrationapi.Error(w, 503, "unavailable", "集成操作失败")
	}
	return true
}
func integrationID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		integrationapi.Error(w, 404, "not_found", "集成不存在")
	}
	return id, err == nil
}

// Integrations 管理端只接受浏览器管理员，不与机器认证共享身份。
// vault 为空表示没配 HOST_CREDENTIAL_KEY：集成 API 不可用，不签发 Token 也不建订阅。
func Integrations(db *ent.Client, vault *hostimport.Vault, allow *integrationapi.OutboundAllow) http.Handler {
	mux := http.NewServeMux()
	mapIntegrationSubscriptions(mux, db, vault)
	mapOutboundAllow(mux, db, allow)
	mux.HandleFunc("GET /api/system-integrations", func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Integration.Query().Order(ent.Desc(integration.FieldCreatedAt)).All(r.Context())
		if integrationFailure(w, err) {
			return
		}
		grants, err := db.IntegrationGroup.Query().All(r.Context())
		if integrationFailure(w, err) {
			return
		}
		by := map[uuid.UUID][]uuid.UUID{}
		for _, g := range grants {
			by[g.IntegrationID] = append(by[g.IntegrationID], g.GroupID)
		}
		out := make([]integrationRow, 0, len(rows))
		for _, i := range rows {
			ids := by[i.ID]
			if ids == nil {
				ids = []uuid.UUID{}
			}
			out = append(out, integrationRow{i.ID, integrationInput{i.Name, i.Purpose, i.OwnerID, i.Enabled, i.Scopes, ids, i.ResolutionEnabled, i.AllowedResolutions, i.AllowMaliciousFalsePositive}, i.PermissionVersion, i.CreatedAt})
		}
		integrationapi.JSON(w, 200, out)
	})
	save := func(w http.ResponseWriter, r *http.Request) {
		var body integrationInput
		if !integrationDecode(w, r, &body) {
			return
		}
		for _, status := range body.AllowedResolutions {
			if !slices.Contains([]string{"open", "closed", "false_positive"}, status) {
				integrationapi.Error(w, 400, "invalid_argument", "回写状态无效")
				return
			}
		}
		if len(body.AllowedResolutions) > 3 || body.ResolutionEnabled && (!slices.Contains(body.Scopes, "incidents:resolve") || len(body.AllowedResolutions) == 0) {
			integrationapi.Error(w, 400, "invalid_argument", "启用回写必须授权 scope 和允许的状态")
			return
		}
		body.Name = strings.TrimSpace(body.Name)
		body.Purpose = strings.TrimSpace(body.Purpose)
		if body.Name == "" || utf8.RuneCountInString(body.Name) > 100 || utf8.RuneCountInString(body.Purpose) > 1000 || !integrationapi.ValidScopes(body.Scopes) || len(body.GroupIDs) > 1000 {
			integrationapi.Error(w, 400, "invalid_argument", "名称、用途、scope 或组数量无效")
			return
		}
		slices.SortFunc(body.GroupIDs, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
		body.GroupIDs = slices.Compact(body.GroupIDs)
		// Suricata 告警按集成的唯一授权组归属，多组时无从判断写入哪个组
		if (slices.Contains(body.Scopes, "suricata:write") || slices.Contains(body.Scopes, "flows:write")) && len(body.GroupIDs) != 1 {
			integrationapi.Error(w, 400, "invalid_argument", "告警与流量写入须恰好授权一个组")
			return
		}
		tx, err := db.Tx(r.Context())
		if integrationFailure(w, err) {
			return
		}
		defer tx.Rollback()
		if _, err = tx.User.Query().Where(user.IDEQ(body.OwnerID)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(r.Context()); err != nil {
			integrationapi.Error(w, 400, "invalid_argument", "负责人不存在")
			return
		}
		groups, err := tx.Group.Query().Where(group.IDIn(body.GroupIDs...)).Order(ent.Asc(group.FieldID)).Where(func(s *sql.Selector) { s.ForUpdate() }).All(r.Context())
		if integrationFailure(w, err) {
			return
		}
		if len(groups) != len(body.GroupIDs) {
			integrationapi.Error(w, 400, "invalid_argument", "部分组不存在")
			return
		}
		var row *ent.Integration
		if r.Method == http.MethodPost {
			row, err = tx.Integration.Create().SetName(body.Name).SetPurpose(body.Purpose).SetOwnerID(body.OwnerID).SetEnabled(body.Enabled).SetScopes(body.Scopes).SetResolutionEnabled(body.ResolutionEnabled).SetAllowedResolutions(body.AllowedResolutions).SetAllowMaliciousFalsePositive(body.AllowMaliciousFalsePositive).Save(r.Context())
		} else {
			id, ok := integrationID(w, r)
			if !ok {
				return
			}
			_, err = tx.Integration.Query().Where(integration.IDEQ(id)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(r.Context())
			if integrationFailure(w, err) {
				return
			}
			row, err = tx.Integration.UpdateOneID(id).SetName(body.Name).SetPurpose(body.Purpose).SetOwnerID(body.OwnerID).SetEnabled(body.Enabled).SetScopes(body.Scopes).SetResolutionEnabled(body.ResolutionEnabled).SetAllowedResolutions(body.AllowedResolutions).SetAllowMaliciousFalsePositive(body.AllowMaliciousFalsePositive).AddPermissionVersion(1).Save(r.Context())
		}
		if integrationFailure(w, err) {
			return
		}
		_, err = tx.IntegrationGroup.Delete().Where(integrationgroup.IntegrationIDEQ(row.ID)).Exec(r.Context())
		if integrationFailure(w, err) {
			return
		}
		for _, g := range body.GroupIDs {
			if err = tx.IntegrationGroup.Create().SetIntegrationID(row.ID).SetGroupID(g).Exec(r.Context()); integrationFailure(w, err) {
				return
			}
		}
		details, _ := json.Marshal(body)
		err = audit.Checked(r.Context(), tx.AuditLog.Create(), audit.Actor(r.Context()), audit.RemoteAddr(r), "integration_saved", row.ID.String(), string(details))
		if integrationFailure(w, err) {
			return
		}
		if integrationFailure(w, tx.Commit()) {
			return
		}
		code := 200
		if r.Method == http.MethodPost {
			code = 201
		}
		integrationapi.JSON(w, code, integrationRow{row.ID, body, row.PermissionVersion, row.CreatedAt})
	}
	mux.HandleFunc("POST /api/system-integrations", save)
	mux.HandleFunc("PUT /api/system-integrations/{id}", save)
	mux.HandleFunc("GET /api/system-integrations/{id}/tokens", func(w http.ResponseWriter, r *http.Request) {
		id, ok := integrationID(w, r)
		if !ok {
			return
		}
		if _, err := db.Integration.Get(r.Context(), id); integrationFailure(w, err) {
			return
		}
		rows, err := db.IntegrationToken.Query().Where(integrationtoken.IntegrationIDEQ(id)).Order(ent.Desc(integrationtoken.FieldCreatedAt)).All(r.Context())
		if integrationFailure(w, err) {
			return
		}
		out := make([]integrationTokenRow, 0, len(rows))
		for _, t := range rows {
			out = append(out, integrationTokenDTO(t))
		}
		integrationapi.JSON(w, 200, out)
	})
	mux.HandleFunc("POST /api/system-integrations/{id}/tokens", func(w http.ResponseWriter, r *http.Request) {
		id, ok := integrationID(w, r)
		if !ok {
			return
		}
		var body struct {
			Days   int      `json:"days"`
			Scopes []string `json:"scopes"`
		}
		if !integrationDecode(w, r, &body) {
			return
		}
		if body.Days == 0 {
			body.Days = 90
		}
		if body.Days < 1 || body.Days > 365 || !integrationapi.ValidScopes(body.Scopes) {
			integrationapi.Error(w, 400, "invalid_argument", "有效期或 scope 无效")
			return
		}
		if vault == nil {
			integrationapi.Error(w, 409, "unavailable", "未配置 HOST_CREDENTIAL_KEY，集成 API 不可用，签发的 Token 无法使用")
			return
		}
		tx, err := db.Tx(r.Context())
		if integrationFailure(w, err) {
			return
		}
		defer tx.Rollback()
		i, err := tx.Integration.Query().Where(integration.IDEQ(id)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(r.Context())
		if integrationFailure(w, err) {
			return
		}
		for _, scope := range body.Scopes {
			if !slices.Contains(i.Scopes, scope) {
				integrationapi.Error(w, 400, "invalid_argument", "Token scope 超出集成授权")
				return
			}
		}
		secret := make([]byte, 32)
		if _, err = rand.Read(secret); integrationFailure(w, err) {
			return
		}
		plain := "oxi_" + base64.RawURLEncoding.EncodeToString(secret)
		row, err := tx.IntegrationToken.Create().SetIntegrationID(id).SetTokenHash(integrationapi.TokenHash(plain)).SetPrefix(plain[:12]).SetScopes(body.Scopes).SetExpiresAt(time.Now().Add(time.Duration(body.Days) * 24 * time.Hour)).Save(r.Context())
		if integrationFailure(w, err) {
			return
		}
		err = audit.Checked(r.Context(), tx.AuditLog.Create(), audit.Actor(r.Context()), audit.RemoteAddr(r), "integration_token_created", row.ID.String(), id.String())
		if integrationFailure(w, err) {
			return
		}
		if integrationFailure(w, tx.Commit()) {
			return
		}
		out := integrationTokenDTO(row)
		out.Token = plain
		integrationapi.JSON(w, 201, out)
	})
	mux.HandleFunc("DELETE /api/system-integrations/{id}/tokens/{tokenId}", func(w http.ResponseWriter, r *http.Request) {
		id, ok := integrationID(w, r)
		if !ok {
			return
		}
		tokenID, err := uuid.Parse(r.PathValue("tokenId"))
		if err != nil {
			integrationapi.Error(w, 404, "not_found", "令牌不存在")
			return
		}
		tx, err := db.Tx(r.Context())
		if integrationFailure(w, err) {
			return
		}
		defer tx.Rollback()
		n, err := tx.IntegrationToken.Update().Where(integrationtoken.IDEQ(tokenID), integrationtoken.IntegrationIDEQ(id)).SetRevoked(true).Save(r.Context())
		if integrationFailure(w, err) {
			return
		}
		if n == 0 {
			integrationapi.Error(w, 404, "not_found", "令牌不存在")
			return
		}
		err = audit.Checked(r.Context(), tx.AuditLog.Create(), audit.Actor(r.Context()), audit.RemoteAddr(r), "integration_token_revoked", tokenID.String(), id.String())
		if integrationFailure(w, err) {
			return
		}
		if integrationFailure(w, tx.Commit()) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", uuid.NewString())
		w.Header().Set("Cache-Control", "no-store")
		u := auth.From(r.Context())
		if u == nil || u.Role != "admin" {
			integrationapi.Error(w, 403, "forbidden", "仅全局管理员可管理系统集成")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// mapOutboundAllow Webhook 内网目标放行清单。放宽 SSRF 边界属敏感操作：仅全局管理员，同事务审计。
func mapOutboundAllow(mux *http.ServeMux, db *ent.Client, allow *integrationapi.OutboundAllow) {
	type view struct {
		Entries []string `json:"entries"`
		Locked  bool     `json:"locked"`
	}
	mux.HandleFunc("GET /api/system-integrations/outbound-allow", func(w http.ResponseWriter, r *http.Request) {
		entries, locked, err := allow.Entries(r.Context())
		if integrationFailure(w, err) {
			return
		}
		integrationapi.JSON(w, 200, view{entries, locked})
	})
	mux.HandleFunc("PUT /api/system-integrations/outbound-allow", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Entries []string `json:"entries"`
		}
		if !integrationDecode(w, r, &body) {
			return
		}
		entries, err := integrationapi.CleanAllow(body.Entries)
		if err != nil {
			integrationapi.Error(w, 400, "invalid_argument", err.Error())
			return
		}
		tx, err := db.Tx(r.Context())
		if integrationFailure(w, err) {
			return
		}
		defer tx.Rollback()
		err = allow.Save(r.Context(), tx, entries)
		if errors.Is(err, integrationapi.ErrOutboundLocked) {
			integrationapi.Error(w, 409, "locked", err.Error())
			return
		}
		if integrationFailure(w, err) {
			return
		}
		err = audit.Checked(r.Context(), tx.AuditLog.Create(), audit.Actor(r.Context()), audit.RemoteAddr(r), "integration_outbound_allow", "", strings.Join(entries, ","))
		if integrationFailure(w, err) || integrationFailure(w, tx.Commit()) {
			return
		}
		integrationapi.JSON(w, 200, view{entries, false})
	})
}
