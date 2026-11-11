package integration

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/asset"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/facts"
)

// intents 用集成 Token 登记运维意图（凯伊各会话走这里）。登记人是集成身份，只能为事实库里登记在它名下的
// 通道与钥匙登记，主机限于集成被授权的组。Token 不放在纳管主机上，只偷到 SSH 钥匙的人登记不了
func (s *Service) intents(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey{}).(principal)
	var body facts.IntentBody
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&body) != nil {
		Error(w, 400, "invalid_request", "请求无效")
		return
	}
	allowed, err := s.DB.Asset.Query().Where(asset.GroupIDIn(p.Groups...)).IDs(r.Context())
	if err != nil {
		Error(w, 503, "unavailable", "读取授权失败")
		return
	}
	now := time.Now()
	in, err := facts.Register(r.Context(), s.DB, "integration:"+p.Integration.ID.String(), audit.RemoteAddr(r), body.Request(now),
		func(id uuid.UUID) bool { return slices.Contains(allowed, id) }, s.Notify, now)
	var bad facts.ErrInvalid
	switch {
	case errors.As(err, &bad):
		Error(w, 400, "invalid_request", err.Error())
	case errors.Is(err, facts.ErrNotOwner), errors.Is(err, facts.ErrForbiddenHost):
		Error(w, 403, "forbidden", err.Error())
	case err != nil:
		Error(w, 503, "unavailable", "登记失败")
	default:
		JSON(w, 201, map[string]any{"id": in.ID, "ref": facts.Ref("I", in.ID), "startsAt": in.StartsAt, "expiresAt": in.ExpiresAt, "late": in.Late})
	}
}
