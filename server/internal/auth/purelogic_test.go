package auth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMinRoleRouteTable(t *testing.T) {
	cases := []struct {
		method, path string
		want         string
	}{
		// 用户与审计管理只有 admin 能碰，GET 也不例外
		{"GET", "/api/users", "admin"},
		{"GET", "/api/system-integrations", "admin"},
		{"POST", "/api/system-integrations/id/tokens", "admin"},
		{"POST", "/api/users", "admin"},
		{"GET", "/api/settings/notify", "admin"},
		{"POST", "/api/settings/notify/test", "admin"},
		{"PUT", "/api/intel/feeds", "admin"},
		{"GET", "/api/intel/feeds", "viewer"},
		{"PUT", "/api/containments/config", "admin"},
		{"GET", "/api/containments/status", "viewer"},
		{"POST", "/api/custom-rules", "admin"},
		{"POST", "/api/custom-rules/check", "admin"},
		{"GET", "/api/custom-rules", "viewer"},
		// 接入令牌按组鉴权，由 handler 检查组 admin
		{"POST", "/api/enroll-tokens", "viewer"},
		{"GET", "/api/audit", "admin"},
		{"DELETE", "/api/audit/123", "admin"},
		{"POST", "/api/assets/export", "viewer"},
		{"POST", "/api/assets/export/other", "analyst"},
		// 其余只读走 viewer，写操作至少 analyst
		{"GET", "/api/intel", "viewer"},
		{"GET", "/api/events", "viewer"},
		{"POST", "/api/intel", "analyst"},
		{"DELETE", "/api/events/1", "analyst"},
		// 组：读按成员身份过滤，写只有 admin
		{"GET", "/api/groups", "viewer"},
		{"POST", "/api/groups", "admin"},
		{"PUT", "/api/groups/1/members/2", "admin"},
		{"DELETE", "/api/groups/1/assets/2", "admin"},
		// 任务：读开放，改只有 admin
		{"GET", "/api/tasks", "viewer"},
		{"PATCH", "/api/tasks/daily", "admin"},
		{"PUT", "/api/tasks/daily/groups/0190d7b0-0000-7000-8000-000000000000", "viewer"},
		{"POST", "/api/tasks/daily/run", "admin"},
		// 初始化状态：人人可读，同意协议与结束引导只有 admin
		{"GET", "/api/setup", "viewer"},
		{"POST", "/api/setup/agreement", "admin"},
		{"POST", "/api/setup/onboarded", "admin"},
	}
	for _, c := range cases {
		if got := minRole(c.method, c.path); got != c.want {
			t.Errorf("minRole(%q, %q) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestValidRole(t *testing.T) {
	for _, role := range []string{"viewer", "analyst", "admin"} {
		if !ValidRole(role) {
			t.Errorf("ValidRole(%q) 应为 true", role)
		}
	}
	for _, role := range []string{"", "superuser", "Admin", "analyst "} {
		if ValidRole(role) {
			t.Errorf("ValidRole(%q) 应为 false", role)
		}
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		remote string
		want   string
	}{
		{"1.2.3.4:5678", "1.2.3.4"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		// 非标准 remote 地址（如走代理没填端口）原样返回，不 panic
		{"1.2.3.4", "1.2.3.4"},
		{"", ""},
	}
	for _, c := range cases {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if got := clientIP(r); got != c.want {
			t.Errorf("clientIP(RemoteAddr=%q) = %q, want %q", c.remote, got, c.want)
		}
	}
}

func TestAuthWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, map[string]string{"hello": "世界"})
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	want := `{"hello":"世界"}` + "\n"
	if rec.Body.String() != want {
		t.Errorf("输出 = %q, want %q", rec.Body.String(), want)
	}
}

func TestAllowed(t *testing.T) {
	cases := []struct {
		role, min string
		want      bool
	}{
		{"admin", "admin", true},
		{"admin", "viewer", true},
		{"analyst", "admin", false},
		{"viewer", "viewer", true},
		{"", "viewer", false}, // 非成员什么都过不了
	}
	for _, c := range cases {
		if got := Allowed(c.role, c.min); got != c.want {
			t.Errorf("Allowed(%q, %q) = %v, want %v", c.role, c.min, got, c.want)
		}
	}
}

func TestSecureCookie(t *testing.T) {
	cases := []struct {
		name  string
		tls   bool
		proto string
		want  bool
	}{
		{"直连 TLS", true, "", true},
		{"代理转发 https", false, "https", true},
		{"代理头带跳数", false, "https, http", true},
		{"代理转发 http", false, "http", false},
		{"无代理头", false, "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
		if c.tls {
			r.TLS = &tls.ConnectionState{}
		}
		if c.proto != "" {
			r.Header.Set("X-Forwarded-Proto", c.proto)
		}
		if got := secureCookie(r); got != c.want {
			t.Errorf("%s: secureCookie = %v, want %v", c.name, got, c.want)
		}
	}
}
