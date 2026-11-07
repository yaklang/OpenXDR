// Package integration 为外部系统提供独立身份与有界 API，不使用浏览器用户上下文。
package integration

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"openxdr/server/ent"
	"openxdr/server/ent/group"
	"openxdr/server/ent/integrationgroup"
	"openxdr/server/ent/integrationtoken"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/flowinput"
	"openxdr/server/internal/suricata"
)

// RateLimitedRequests 进程内累计拒绝数；重启清零，按 read/write 区分。
var RateLimitedRequests = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openxdr_integration_rate_limited_total", Help: "集成 API 被限流的请求数"}, []string{"kind"})

var ReadScopes = []string{"assets:read", "incidents:read"}
var AllowedScopes = []string{"assets:read", "incidents:read", "tickets:write", "incidents:resolve", "suricata:write", "flows:write"}

func ValidScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > len(AllowedScopes) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range scopes {
		if !slices.Contains(AllowedScopes, v) || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
func TokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

type principal struct {
	Integration *ent.Integration
	Token       *ent.IntegrationToken
	Groups      []uuid.UUID
}
type principalKey struct{}
type bucket struct {
	tokens float64
	at     time.Time
}
type Service struct {
	Flows     func(context.Context, flowinput.Origin, flowinput.Event) error
	DB        *ent.Client
	CursorKey []byte
	// Suricata 把通过认证的 EVE 告警写入持久事件队列；为空时该接口不可用
	Suricata     func(context.Context, suricata.Origin, suricata.Event) error
	mu           sync.Mutex
	buckets      map[uuid.UUID]bucket
	writeBuckets map[uuid.UUID]bucket
}

func (s *Service) allow(id uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.buckets == nil {
		s.buckets = map[uuid.UUID]bucket{}
	}
	b, ok := s.buckets[id]
	if !ok {
		b = bucket{20, now}
	}
	b.tokens = min(20, b.tokens+now.Sub(b.at).Seconds())
	b.at = now
	allowed := b.tokens >= 1
	if allowed {
		b.tokens--
	}
	s.buckets[id] = b
	if len(s.buckets) > 1000 {
		for k, v := range s.buckets {
			if now.Sub(v.at) > time.Minute {
				delete(s.buckets, k)
			}
		}
	}
	return allowed
}
func (s *Service) allowWrite(id uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeBuckets == nil {
		s.writeBuckets = map[uuid.UUID]bucket{}
	}
	now := time.Now()
	b, ok := s.writeBuckets[id]
	if !ok {
		b = bucket{10, now}
	}
	b.tokens = min(10, b.tokens+now.Sub(b.at).Seconds()/6)
	b.at = now
	allowed := b.tokens >= 1
	if allowed {
		b.tokens--
	}
	s.writeBuckets[id] = b
	if len(s.writeBuckets) > 1000 {
		for k, v := range s.writeBuckets {
			if now.Sub(v.at) > time.Minute {
				delete(s.writeBuckets, k)
			}
		}
	}
	return allowed
}
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func Error(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message, "requestId": w.Header().Get("X-Request-ID")}})
}
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/integration/v1/assets", s.assets)
	mux.HandleFunc("GET /api/integration/v1/assets/{id}", s.assets)
	mux.HandleFunc("GET /api/integration/v1/incidents", s.incidents)
	mux.HandleFunc("GET /api/integration/v1/incidents/{id}", s.incidents)
	mux.HandleFunc("PUT /api/integration/v1/incidents/{id}/tickets/{externalId}", s.putTicket)
	mux.HandleFunc("POST /api/integration/v1/incidents/{id}/resolution", s.resolve)
	mux.HandleFunc("POST /api/integration/v1/suricata/events", s.suricataEvents)
	mux.HandleFunc("POST /api/integration/v1/flows/{source}/events", s.flowEvents)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { Error(w, 404, "not_found", "接口不存在") })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", uuid.NewString())
		// 游标密钥由 HOST_CREDENTIAL_KEY 派生；没配主密钥时整个集成 API 不可用，不退回弱密钥
		if len(s.CursorKey) < 32 {
			Error(w, 503, "unavailable", "未配置 HOST_CREDENTIAL_KEY，集成 API 不可用")
			return
		}
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer oxi_") || len(header) > 256 {
			Error(w, 401, "unauthorized", "凭据无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		token, err := s.DB.IntegrationToken.Query().Where(integrationtoken.TokenHashEQ(TokenHash(strings.TrimPrefix(header, "Bearer "))), integrationtoken.RevokedEQ(false), integrationtoken.ExpiresAtGT(time.Now())).Only(ctx)
		if ent.IsNotFound(err) {
			Error(w, 401, "unauthorized", "凭据无效")
			return
		}
		if err != nil {
			Error(w, 503, "unavailable", "认证暂不可用")
			return
		}
		i, err := s.DB.Integration.Get(ctx, token.IntegrationID)
		if ent.IsNotFound(err) || err == nil && !i.Enabled {
			Error(w, 401, "unauthorized", "集成身份已停用")
			return
		}
		if err != nil {
			Error(w, 503, "unavailable", "认证暂不可用")
			return
		}
		if _, err = s.DB.User.Get(ctx, i.OwnerID); err != nil {
			Error(w, 401, "unauthorized", "集成负责人不可用")
			return
		}
		needed := ""
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/integration/v1/assets") {
			needed = "assets:read"
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/integration/v1/incidents") {
			needed = "incidents:read"
		}
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/integration/v1/incidents/") && strings.Contains(r.URL.Path, "/tickets/") {
			needed = "tickets:write"
		}
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/integration/v1/incidents/") && strings.HasSuffix(r.URL.Path, "/resolution") {
			needed = "incidents:resolve"
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/integration/v1/suricata/events" {
			needed = "suricata:write"
		}
		if r.Method == http.MethodPost && (r.URL.Path == "/api/integration/v1/flows/ntopng/events" || r.URL.Path == "/api/integration/v1/flows/nprobe/events") {
			needed = "flows:write"
		}
		if needed == "" {
			Error(w, 404, "not_found", "接口不存在")
			return
		}
		if !slices.Contains(i.Scopes, needed) || !slices.Contains(token.Scopes, needed) {
			Error(w, 403, "forbidden", "缺少接口授权")
			return
		}
		// 告警写入是持续数据流，由队列背压与报文上限约束，不走面向人工调用的限流
		ingest := needed == "suricata:write" || needed == "flows:write"
		if !ingest && !s.allow(i.ID) {
			RateLimitedRequests.WithLabelValues("all").Inc()
			w.Header().Set("Retry-After", "1")
			Error(w, 429, "rate_limited", "请求过于频繁")
			return
		}
		if !ingest && r.Method != http.MethodGet && !s.allowWrite(i.ID) {
			RateLimitedRequests.WithLabelValues("write").Inc()
			w.Header().Set("Retry-After", "6")
			Error(w, 429, "rate_limited", "写请求过于频繁")
			return
		}
		grants, err := s.DB.IntegrationGroup.Query().Where(integrationgroup.IntegrationIDEQ(i.ID)).All(ctx)
		if err != nil {
			Error(w, 503, "unavailable", "读取授权失败")
			return
		}
		ids := make([]uuid.UUID, 0, len(grants))
		for _, g := range grants {
			ids = append(ids, g.GroupID)
		}
		ids, err = s.DB.Group.Query().Where(group.IDIn(ids...)).IDs(ctx)
		if err != nil {
			Error(w, 503, "unavailable", "读取授权失败")
			return
		}
		if token.LastUsedAt == nil || time.Since(*token.LastUsedAt) > time.Minute {
			_, err = s.DB.IntegrationToken.Update().Where(integrationtoken.IDEQ(token.ID), integrationtoken.Or(integrationtoken.LastUsedAtIsNil(), integrationtoken.LastUsedAtLT(time.Now().Add(-time.Minute)))).SetLastUsedAt(time.Now()).SetLastRemoteAddr(audit.RemoteAddr(r)).Save(ctx)
			if err != nil {
				Error(w, 503, "unavailable", "更新令牌使用信息失败")
				return
			}
		}
		ctx = context.WithValue(ctx, principalKey{}, principal{i, token, ids})
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

// suricataEvents 接收一条 EVE 告警。来源组只能来自集成授权，且须恰好一个组，报文内的身份字段一律不采信。
func (s *Service) suricataEvents(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey{}).(principal)
	if len(p.Groups) != 1 {
		Error(w, 403, "forbidden", "Suricata 写入须恰好授权一个组")
		return
	}
	if s.Suricata == nil {
		Error(w, 503, "unavailable", "告警接入暂不可用")
		return
	}
	origin := suricata.Origin{Observer: p.Integration.ID.String(), GroupID: p.Groups[0]}
	suricata.Accept(w, r, origin, s.Suricata, func(status int, message string) {
		code := map[int]string{400: "invalid_argument", 413: "payload_too_large"}[status]
		Error(w, status, cmp.Or(code, "unavailable"), message)
	})
}
