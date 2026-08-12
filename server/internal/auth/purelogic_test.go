package auth

import (
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
		{"POST", "/api/users", "admin"},
		{"GET", "/api/audit", "admin"},
		{"DELETE", "/api/audit/123", "admin"},
		// 其余只读走 viewer，写操作至少 analyst
		{"GET", "/api/intel", "viewer"},
		{"GET", "/api/events", "viewer"},
		{"POST", "/api/intel", "analyst"},
		{"DELETE", "/api/events/1", "analyst"},
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
