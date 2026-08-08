//go:build integration

// 认证与 RBAC 的端到端行为：登录发凭证、角色拦截、审计留痕。
// 放在外部测试包：auth 与 api 互相包裹，内部测试包会构成 import 环。
package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"openxdr/server/ent"
	entauditlog "openxdr/server/ent/auditlog"
	entuser "openxdr/server/ent/user"
	"openxdr/server/internal/api"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// 建三个角色各一个账号，返回测试服务器。
func setup(t *testing.T) (context.Context, *ent.Client, *httptest.Server) {
	t.Helper()
	ctx, client := testdb.New(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"admin", "analyst", "viewer"} {
		if err := client.User.Create().
			SetUsername(role).SetPasswordHash(string(hash)).SetRole(role).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}

	rules := sigma.LoadDir(t.TempDir())
	hub := response.NewHub(client, false)
	store := suppress.New(client, 0)
	ts := httptest.NewServer(auth.Middleware(client, api.Handler(client, rules, t.TempDir(), hub, store, intel.New(client, 0), nil, nil)))
	t.Cleanup(ts.Close)
	return ctx, client, ts
}

// 登录拿会话 cookie。
func login(t *testing.T, ts *httptest.Server, username, password string) *http.Cookie {
	t.Helper()
	resp, err := http.Post(ts.URL+"/api/login", "application/json",
		strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("登录应成功，got %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			return c
		}
	}
	t.Fatal("登录响应没有会话 cookie")
	return nil
}

func request(t *testing.T, ts *httptest.Server, method, path string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestUnauthenticatedRejected(t *testing.T) {
	_, _, ts := setup(t)
	if resp := request(t, ts, http.MethodGet, "/api/incidents", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未登录应 401，got %d", resp.StatusCode)
	}
}

func TestWrongPasswordAudited(t *testing.T) {
	ctx, client, ts := setup(t)
	resp, err := http.Post(ts.URL+"/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"nope-nope"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("错误密码应 401，got %d", resp.StatusCode)
	}
	n, err := client.AuditLog.Query().
		Where(entauditlog.ActionEQ("login_failed"), entauditlog.UsernameEQ("admin")).
		Count(ctx)
	if err != nil || n != 1 {
		t.Fatalf("登录失败应留审计，count=%d err=%v", n, err)
	}
}

func TestRoleEnforcement(t *testing.T) {
	_, _, ts := setup(t)
	viewer := login(t, ts, "viewer", "password1")
	analyst := login(t, ts, "analyst", "password1")
	admin := login(t, ts, "admin", "password1")

	cases := []struct {
		name   string
		cookie *http.Cookie
		method string
		path   string
		want   int
	}{
		{"viewer 可读", viewer, http.MethodGet, "/api/incidents", http.StatusOK},
		{"viewer 禁写", viewer, http.MethodPost, "/api/suppressions", http.StatusForbidden},
		{"viewer 禁审计", viewer, http.MethodGet, "/api/audit", http.StatusForbidden},
		{"analyst 可读", analyst, http.MethodGet, "/api/incidents", http.StatusOK},
		{"analyst 禁用户管理", analyst, http.MethodGet, "/api/users", http.StatusForbidden},
		{"admin 看审计", admin, http.MethodGet, "/api/audit", http.StatusOK},
		{"admin 看用户", admin, http.MethodGet, "/api/users", http.StatusOK},
	}
	for _, c := range cases {
		if resp := request(t, ts, c.method, c.path, c.cookie); resp.StatusCode != c.want {
			t.Errorf("%s: want %d got %d", c.name, c.want, resp.StatusCode)
		}
	}
}

func TestLogoutRevokes(t *testing.T) {
	_, _, ts := setup(t)
	cookie := login(t, ts, "viewer", "password1")
	if resp := request(t, ts, http.MethodGet, "/api/me", cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("登录后 /api/me 应 200，got %d", resp.StatusCode)
	}
	if resp := request(t, ts, http.MethodPost, "/api/logout", cookie); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("登出应 204，got %d", resp.StatusCode)
	}
	if resp := request(t, ts, http.MethodGet, "/api/me", cookie); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("登出后旧 cookie 应失效，got %d", resp.StatusCode)
	}
}

func TestUserLifecycle(t *testing.T) {
	ctx, client, ts := setup(t)
	admin := login(t, ts, "admin", "password1")

	// 建号
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/users",
		strings.NewReader(`{"username":"eve","password":"longenough","role":"analyst"}`))
	req.AddCookie(admin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("建号应 201，got %d", resp.StatusCode)
	}
	eve := login(t, ts, "eve", "longenough")

	// 改密吊销既有会话
	u, err := client.User.Query().Where(entuser.UsernameEQ("eve")).Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/users/"+u.ID.String()+"/password",
		strings.NewReader(`{"password":"newpassword"}`))
	req.AddCookie(admin)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("改密应 204，got %d", resp.StatusCode)
	}
	if r := request(t, ts, http.MethodGet, "/api/me", eve); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("改密后旧会话应失效，got %d", r.StatusCode)
	}

	// 审计应记下 user_created 与 user_password_reset，操作者是 admin
	for _, action := range []string{"user_created", "user_password_reset"} {
		n, err := client.AuditLog.Query().
			Where(entauditlog.ActionEQ(action), entauditlog.UsernameEQ("admin")).
			Count(ctx)
		if err != nil || n != 1 {
			t.Errorf("审计 %s：count=%d err=%v", action, n, err)
		}
	}
}

func TestBootstrapCreatesAdmin(t *testing.T) {
	ctx, client := testdb.New(t)
	t.Setenv("ADMIN_PASSWORD", "bootstrap-secret")
	if err := auth.Bootstrap(ctx, client); err != nil {
		t.Fatal(err)
	}
	// 已有用户时不重复创建
	if err := auth.Bootstrap(ctx, client); err != nil {
		t.Fatal(err)
	}
	n, err := client.User.Query().Count(ctx)
	if err != nil || n != 1 {
		t.Fatalf("应只有一个引导账号，count=%d err=%v", n, err)
	}
}
