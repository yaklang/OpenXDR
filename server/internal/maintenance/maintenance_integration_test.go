//go:build integration

package maintenance

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/testdb"
)

// heartbeat 在线主机每轮都会上报：回不来的那台除外
func (f *fakeFleet) heartbeat(ctx context.Context) {
	for _, a := range f.db.Asset.Query().AllX(ctx) {
		if !f.silent[a.Hostname] || !f.rebooted[a.Hostname] {
			f.db.Asset.UpdateOne(a).SetLastSeen(f.now).ExecX(ctx)
		}
	}
}

type fakeFleet struct {
	rebooted map[string]bool
	t        *testing.T
	db       *ent.Client
	now      time.Time
	boot     map[string]string
	pending  map[string]bool // 需要重启
	calls    []string
	silent   map[string]bool // 重启后回不来
}

func (f *fakeFleet) exec(ctx context.Context, a *ent.Asset, cmd string, _ time.Duration) (string, error) {
	switch cmd {
	case upgradeScript, bootIDCommand:
		if cmd == upgradeScript {
			f.calls = append(f.calls, "upgrade "+a.Hostname)
		}
		out := "BOOT_ID " + f.boot[a.Hostname] + "\n"
		if f.pending[a.Hostname] {
			out += "REBOOT_REQUIRED\n"
		}
		return out, nil
	case rebootCommand:
		f.calls = append(f.calls, "reboot "+a.Hostname)
		f.rebooted[a.Hostname] = true
		if !f.silent[a.Hostname] {
			// 模拟重启：启动 ID 换了、不再需要重启，agent 一分钟后重新上线
			f.boot[a.Hostname] = uuid.NewString()
			f.pending[a.Hostname] = false
			f.db.Asset.UpdateOne(a).SetLastSeen(f.now.Add(time.Minute)).ExecX(ctx)
		}
		return "", nil
	}
	f.t.Fatalf("意外的命令：%s", cmd)
	return "", nil
}

func setup(t *testing.T) (context.Context, *ent.Client, *Runner, *fakeFleet, *[]string) {
	ctx, client := testdb.New(t)
	raw, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	sh := time.FixedZone("CST", 8*3600)
	now := time.Date(2026, 11, 10, 2, 30, 0, 0, sh)
	f := &fakeFleet{t: t, db: client, now: now, boot: map[string]string{}, pending: map[string]bool{}, silent: map[string]bool{}, rebooted: map[string]bool{}}
	server := json.RawMessage(`[{"proto":"tcp","addr":"0.0.0.0","port":8081,"process":"openxdr-server"}]`)
	for _, h := range []string{"app1", "app2", "openxdr-node1", "openxdr-node2", "pve1"} {
		c := client.Asset.Create().SetHostname(h).SetOs("linux").SetAgentID(uuid.New()).SetLastSeen(now)
		if strings.HasPrefix(h, "openxdr-") {
			c.SetListening(server)
		}
		c.SaveX(ctx)
		f.boot[h] = uuid.NewString()
		f.pending[h] = true
	}
	f.pending["app2"] = false
	var notes []string
	r := &Runner{DB: client, SQL: raw, Exec: f.exec, Now: func() time.Time { return f.now },
		Config: Config{Start: 2 * time.Hour, End: 5 * time.Hour, Location: sh, Exclude: map[string]bool{"pve1": true}},
		Notify: func(_ context.Context, title, text, _ string) error {
			notes = append(notes, title+"："+text)
			return nil
		}}
	return ctx, client, r, f, &notes
}

// 一晚：普通主机依次处理，重启的确认回来才轮下一台；平台节点最后、只一台；PVE 不碰
func TestOneNightOfMaintenance(t *testing.T) {
	ctx, _, r, f, notes := setup(t)
	for i := 0; i < 10; i++ {
		f.heartbeat(ctx)
		if err := r.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(2 * time.Minute)
	}
	want := "upgrade app1,reboot app1,upgrade app2,upgrade openxdr-node1,reboot openxdr-node1"
	if got := strings.Join(f.calls, ","); got != want {
		t.Fatalf("顺序不对：\n%s\n%s", got, want)
	}
	if len(*notes) != 0 {
		t.Fatalf("顺利的一晚不该通知：%v", *notes)
	}
	st, _ := r.Status(ctx)
	if !st.CoreDone || st.Current != nil || st.Halted != "" || len(st.Done) != 3 {
		t.Fatalf("状态：%+v", st)
	}
	// 窗口外不动
	f.now = time.Date(2026, 11, 10, 6, 0, 0, 0, f.now.Location())
	f.calls = nil
	_ = r.Tick(ctx)
	if len(f.calls) != 0 {
		t.Fatalf("窗口外不该动：%v", f.calls)
	}
}

// 重启后回不来：超时当晚停手、通知，之后不再继续
func TestHaltsWhenAHostDoesNotComeBack(t *testing.T) {
	ctx, _, r, f, notes := setup(t)
	f.silent["app1"] = true
	for i := 0; i < 12; i++ {
		f.heartbeat(ctx)
		if err := r.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(2 * time.Minute)
	}
	if got := strings.Join(f.calls, ","); got != "upgrade app1,reboot app1" {
		t.Fatalf("停手后不该继续：%s", got)
	}
	st, _ := r.Status(ctx)
	if st.Halted == "" || len(*notes) != 1 || !strings.Contains((*notes)[0], "app1") {
		t.Fatalf("应停手并通知：%+v %v", st, *notes)
	}
}

type fakePatroni struct {
	mu        sync.Mutex
	roles     map[string]string // 名字 → 角色
	healthy   bool              // 从节点复制是否健康
	switchTo  string
	servers   map[string]*httptest.Server
	authFails int
}

func (p *fakePatroni) server(t *testing.T, name string) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		switch r.URL.Path {
		case "/patroni":
			_ = json.NewEncoder(w).Encode(map[string]any{"role": p.roles[name], "patroni": map[string]string{"name": name}})
		case "/replica":
			if p.roles[name] == "replica" && p.healthy {
				w.WriteHeader(200)
			} else {
				w.WriteHeader(503)
			}
		case "/switchover":
			if u, pw, ok := r.BasicAuth(); !ok || u != "patroni-admin" || pw != "secret" {
				p.authFails++
				w.WriteHeader(401)
				return
			}
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			p.roles[body["leader"]], p.roles[body["candidate"]] = "replica", "primary"
			p.switchTo = body["candidate"]
			w.WriteHeader(200)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func platformOnly(t *testing.T, healthy bool) (context.Context, *Runner, *fakeFleet, *fakePatroni, *[]string) {
	ctx, client, r, f, notes := setup(t)
	for _, h := range []string{"app1", "app2", "pve1"} {
		client.Asset.Update().Where(asset.HostnameEQ(h)).SetRetiredAt(f.now).ExecX(ctx)
	}
	p := &fakePatroni{roles: map[string]string{"openxdr-node1": "primary", "openxdr-node2": "replica"}, healthy: healthy, servers: map[string]*httptest.Server{}}
	for _, n := range []string{"openxdr-node1", "openxdr-node2"} {
		p.servers[n] = p.server(t, n)
	}
	r.Poll = 10 * time.Millisecond
	// node1 的地址里先列一个指向 node2 的「虚拟地址」：成员名对不上主机名的应答不能采信
	r.Config.Patroni = &Patroni{User: "patroni-admin", Password: "secret", Addrs: func(a *ent.Asset) []string {
		if a.Hostname == "openxdr-node1" {
			return []string{p.servers["openxdr-node2"].URL, p.servers["openxdr-node1"].URL}
		}
		return []string{p.servers[a.Hostname].URL}
	}}
	return ctx, r, f, p, notes
}

// 平台节点是数据库主节点：先计划内切换到健康的从节点，变成从节点后才装更新、重启
func TestPlatformNodeHandsOffPrimaryFirst(t *testing.T) {
	ctx, r, f, p, notes := platformOnly(t, true)
	for i := 0; i < 4; i++ {
		f.heartbeat(ctx)
		if err := r.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(2 * time.Minute)
	}
	if p.switchTo != "openxdr-node2" || p.roles["openxdr-node1"] != "replica" || p.authFails != 0 {
		t.Fatalf("应先把主节点切到 node2：%+v", p.roles)
	}
	if got := strings.Join(f.calls, ","); got != "upgrade openxdr-node1,reboot openxdr-node1" {
		t.Fatalf("切换后才维护：%s", got)
	}
	if len(*notes) != 0 {
		t.Fatalf("不该通知：%v", *notes)
	}
}

// 另一台复制不健康：不切换、不装更新、不重启，当晚停手并通知
func TestPlatformNodeStaysWhenNoHealthyReplica(t *testing.T) {
	ctx, r, f, p, notes := platformOnly(t, false)
	for i := 0; i < 4; i++ {
		f.heartbeat(ctx)
		if err := r.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(2 * time.Minute)
	}
	if p.switchTo != "" || len(f.calls) != 0 {
		t.Fatalf("不该切换也不该动主机：%v %v", p.switchTo, f.calls)
	}
	if len(*notes) != 1 || !strings.Contains((*notes)[0], "不是健康的从节点") {
		t.Fatalf("应停手并通知：%v", *notes)
	}
}
