package authentik

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// 失败事件取尝试的用户名；口令字段绝不进事件；匿名与没有用户名的不发
func TestEnvelopeMapsLoginsWithoutSecrets(t *testing.T) {
	asset := uuid.New()
	var failed event
	_ = json.Unmarshal([]byte(`{"pk":"p1","action":"login_failed","user":{"username":"AnonymousUser"},
		"client_ip":"203.0.113.9","created":"2026-11-09T08:00:00Z",
		"context":{"username":"alice","password":"********************","geo":{"country":"CN","city":"Beijing"}}}`), &failed)
	env, ok := envelope(failed, asset, "linux")
	if !ok || env.Username != "alice" || env.ClassUID != 3002 || env.Source != "authentik" || *env.AssetID != asset {
		t.Fatalf("失败事件映射不对：%+v", env)
	}
	raw := string(env.Raw)
	if strings.Contains(raw, "password") || strings.Contains(raw, "****") {
		t.Fatalf("口令字段不能进事件：%s", raw)
	}
	for _, want := range []string{`"status_id":2`, `"ip":"203.0.113.9"`, `"country":"CN"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("缺少 %s：%s", want, raw)
		}
	}
	again, _ := envelope(failed, asset, "linux")
	if again.ID != env.ID {
		t.Fatal("同一事件重复拉取要得到同一个 ID，入库靠它去重")
	}
	failed.Context.Username = ""
	if _, ok := envelope(failed, asset, "linux"); ok {
		t.Fatal("说不清尝试哪个用户名的失败不发")
	}
	var ok2 event
	_ = json.Unmarshal([]byte(`{"pk":"p2","action":"login","user":{"username":"alice"},"client_ip":"198.51.100.1","created":"2026-11-09T08:00:05Z"}`), &ok2)
	if env, ok := envelope(ok2, asset, "linux"); !ok || !strings.Contains(string(env.Raw), `"status_id":1`) {
		t.Fatalf("成功事件：%s", env.Raw)
	}
}

type fakeAuthentik struct {
	mu      sync.Mutex
	users   map[int]*user
	patches []string
}

func (f *fakeAuthentik) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer t" {
		w.WriteHeader(403)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/users/":
		var out []user
		for _, u := range f.users {
			if u.Username == r.URL.Query().Get("username") {
				out = append(out, *u)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": out})
	case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/v3/core/users/"):
		var body struct {
			IsActive bool `json:"is_active"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		for pk, u := range f.users {
			if r.URL.Path == "/api/v3/core/users/"+itoa(pk)+"/" {
				u.IsActive = body.IsActive
				f.patches = append(f.patches, u.Username)
			}
		}
		w.WriteHeader(200)
	default:
		w.WriteHeader(404)
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

// 停用只动普通账号：超级管理员、服务账号、保护名单一律拒绝，一次请求都不发
func TestAccountsNeverDisableAdminsOrServiceAccounts(t *testing.T) {
	f := &fakeAuthentik{users: map[int]*user{
		1: {PK: 1, Username: "alice", IsActive: true, Type: "internal"},
		2: {PK: 2, Username: "akadmin", IsActive: true, IsSuperuser: true, Type: "internal"},
		3: {PK: 3, Username: "openxdr-response", IsActive: true, Type: "service_account"},
		4: {PK: 4, Username: "boss", IsActive: true, Type: "internal"},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	a := &Accounts{API: &Client{BaseURL: srv.URL, Token: "t"}, Protected: map[string]bool{"boss": true}}
	ctx := context.Background()
	for _, name := range []string{"akadmin", "openxdr-response", "boss", "nobody", "bad name"} {
		if _, err := a.Disable(ctx, name); err == nil {
			t.Fatalf("%s 不该被停用", name)
		}
	}
	if len(f.patches) != 0 {
		t.Fatalf("被拒绝的账号不能发修改请求：%v", f.patches)
	}
	if _, err := a.Disable(ctx, "alice"); err != nil || f.users[1].IsActive {
		t.Fatalf("普通账号应停用：%v", err)
	}
	if msg, err := a.Disable(ctx, "alice"); err != nil || !strings.Contains(msg, "原本就是停用") {
		t.Fatalf("重复停用算达成：%v %s", err, msg)
	}
	if _, err := a.Enable(ctx, "alice"); err != nil || !f.users[1].IsActive {
		t.Fatalf("应恢复：%v", err)
	}
}

// 拉取：倒序翻页，翻到早于游标的就停
func TestFetchStopsAtCursor(t *testing.T) {
	base := time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	pages := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages++
		page := r.URL.Query().Get("page")
		var res []map[string]any
		start := map[string]int{"1": 0, "2": 100}[page]
		for i := start; i < start+100; i++ {
			res = append(res, map[string]any{"pk": itoa(i), "action": "login_failed", "created": base.Add(-time.Duration(i) * time.Minute)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"pagination": map[string]int{"next": 2}, "results": res})
	}))
	defer srv.Close()
	p := &Poller{API: &Client{BaseURL: srv.URL, Token: "t"}}
	got, err := p.fetch(context.Background(), "login_failed", base.Add(-150*time.Minute))
	if err != nil || len(got) != 151 || pages != 2 {
		t.Fatalf("应取到游标为止的 151 条、翻 2 页：%d 条 %d 页 %v", len(got), pages, err)
	}
}
