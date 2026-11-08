//go:build integration

package containment

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
	"openxdr/server/internal/triage"
	"openxdr/server/pb"
)

type fixture struct {
	ctx    context.Context
	client *ent.Client
	db     *sql.DB
	hub    *response.Hub
	group  uuid.UUID
	now    time.Time
	inbox  map[string]chan *pb.Command
	agents map[string]uuid.UUID
}

func setup(t *testing.T) *fixture {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := ingest.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`TRUNCATE lateral_evidence`); err != nil {
		t.Fatal(err)
	}
	return &fixture{
		ctx: ctx, client: client, db: db, hub: response.NewHub(client, true),
		group: client.Group.Create().SetName("lab").SaveX(ctx).ID,
		now:   time.Now().UTC().Truncate(time.Second), inbox: map[string]chan *pb.Command{},
		agents: map[string]uuid.UUID{},
	}
}

// host 建一台在线的纳管主机，指令收进 inbox
func (f *fixture) host(t *testing.T, name, ip string, tier *entasset.ResponseTier, listening string) *ent.Asset {
	agent := uuid.New()
	create := f.client.Asset.Create().SetHostname(name).SetOs("linux").SetGroupID(f.group).
		SetIPAddrs([]string{ip}).SetAgentID(agent).SetNillableResponseTier(tier)
	if listening != "" {
		create.SetListening(json.RawMessage(listening))
	}
	a := create.SaveX(f.ctx)
	f.inbox[name] = f.hub.Attach(agent)
	f.agents[name] = agent
	return a
}

// spray 在 src 上落一条喷洒告警，证据是 victims 各一条，来源地址 ip
func (f *fixture) spray(t *testing.T, src *ent.Asset, ip string, victims ...*ent.Asset) *ent.Alert {
	for i, v := range victims {
		if _, err := f.db.Exec(`INSERT INTO lateral_evidence(event_id,src_asset,victim_asset,ts,src_ip) VALUES($1,$2,$3,$4,$5)`,
			uuid.New(), src.ID, v.ID, f.now.Add(time.Duration(i-10)*time.Minute), ip); err != nil {
			t.Fatal(err)
		}
	}
	return f.client.Alert.Create().SetRuleID(sigma.RuleLateralSpray).SetSeverity(5).SetAssetID(src.ID).
		SetTs(f.now.Add(-8 * time.Minute)).SetLastTs(f.now.Add(-time.Minute)).SetDetail("测试喷洒").SaveX(f.ctx)
}

func (f *fixture) engine(scope string) *Engine {
	return &Engine{DB: f.client, SQL: f.db, Hub: f.hub, AllowEndpoints: []string{"10.1.1.199:8081"}, Scope: scope,
		TTL: 24 * time.Hour, MaxPerHour: 10, Now: func() time.Time { return f.now }}
}

// received 取走某台主机收到的全部指令，并模拟 agent 回报执行成功与对账
func (f *fixture) received(name string) []*pb.Command {
	var out []*pb.Command
	for {
		select {
		case c := <-f.inbox[name]:
			if err := f.hub.Complete(f.ctx, f.agents[name], &pb.CommandResult{
				CommandId: c.Id,
				Status:    pb.CommandResult_SUCCEEDED,
			}); err != nil {
				panic(err)
			}
			out = append(out, c)
		default:
			if err := Reconcile(f.ctx, f.client, f.now); err != nil {
				panic(err)
			}
			return out
		}
	}
}

func tierPtr(t entasset.ResponseTier) *entasset.ResponseTier { return &t }

// 实验等级的来源：隔离来源主机，受害方封锁来源地址；重复跑不重复下发，新证据续期，到期自动解除
func TestLabSourceIsolatedVictimsBlockSource(t *testing.T) {
	f := setup(t)
	src := f.host(t, "range", "10.1.1.170", tierPtr(entasset.ResponseTierLab), "")
	v1 := f.host(t, "node1", "10.1.1.198", nil, "")
	v2 := f.host(t, "web", "10.1.1.183", nil, "")
	al := f.spray(t, src, "10.1.1.170", v1, v2)
	e := f.engine(ScopeLab)

	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("range"); len(got) != 1 || got[0].Kind != pb.CommandKind_ISOLATE_HOST || len(got[0].AllowEndpoints) == 0 {
		t.Fatalf("来源应被隔离并放行 server：%v", got)
	}
	for _, name := range []string{"node1", "web"} {
		if got := f.received(name); len(got) != 1 || got[0].Kind != pb.CommandKind_BLOCK_NETWORK || got[0].Target != "10.1.1.170" {
			t.Fatalf("%s 应封锁来源地址：%v", name, got)
		}
	}
	active := f.client.Containment.Query().Where(entcontainment.StateEQ(entcontainment.StateActive)).AllX(f.ctx)
	if len(active) != 3 {
		t.Fatalf("应有 3 条生效租约，实际 %d", len(active))
	}
	for _, c := range active {
		if c.AlertID != al.ID || c.SourceAssetID == nil || *c.SourceAssetID != src.ID || c.CommandID == nil || !c.ExpiresAt.Equal(al.LastTs.Add(24*time.Hour)) {
			t.Fatalf("租约内容不对：%+v", c)
		}
	}

	// 再跑一轮：不重复下发
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(f.received("range")) + len(f.received("node1")) + len(f.received("web")); n != 0 {
		t.Fatalf("重复决定不应再下发，实际 %d 条", n)
	}

	// 证据持续：最近时间后移，租约跟着续期
	f.client.Alert.UpdateOneID(al.ID).SetLastTs(f.now).ExecX(f.ctx)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.client.Containment.Query().AllX(f.ctx) {
		if !c.ExpiresAt.Equal(f.now.Add(24 * time.Hour)) {
			t.Fatalf("新证据应续期到 %v，实际 %v", f.now.Add(24*time.Hour), c.ExpiresAt)
		}
	}

	// 到期：下发解除，状态转 expired；同一告警不再重新处置
	f.now = f.now.Add(25 * time.Hour)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("range"); len(got) != 1 || got[0].Kind != pb.CommandKind_UNISOLATE_HOST {
		t.Fatalf("到期应解除隔离：%v", got)
	}
	if got := f.received("node1"); len(got) != 1 || got[0].Kind != pb.CommandKind_UNBLOCK_NETWORK || got[0].Target != "10.1.1.170" {
		t.Fatalf("到期应解除封锁：%v", got)
	}
	if got := f.received("web"); len(got) != 1 || got[0].Kind != pb.CommandKind_UNBLOCK_NETWORK || got[0].Target != "10.1.1.170" {
		t.Fatalf("到期应解除封锁：%v", got)
	}
	if n := f.client.Containment.Query().Where(entcontainment.StateEQ(entcontainment.StateExpired), entcontainment.LiftCommandIDNotNil()).CountX(f.ctx); n != 3 {
		t.Fatalf("三条租约都应到期解除，实际 %d", n)
	}
}

// 范围只含实验等级时，生产来源的攻击只记 skipped，什么都不下发
func TestScopeLabSkipsProductionSource(t *testing.T) {
	f := setup(t)
	src := f.host(t, "app", "10.1.1.50", nil, "")
	v := f.host(t, "db", "10.1.1.51", nil, "")
	f.spray(t, src, "10.1.1.50", v)
	if err := f.engine(ScopeLab).Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(f.received("app")) + len(f.received("db")); n != 0 {
		t.Fatalf("范围外不应下发，实际 %d 条", n)
	}
	rows := f.client.Containment.Query().AllX(f.ctx)
	if len(rows) != 1 || rows[0].State != entcontainment.StateSkipped || rows[0].Kind != "block_network" {
		t.Fatalf("应只记一条跳过的封锁：%+v", rows)
	}

	// 范围放开：生产来源不隔离，受害方照样封锁
	f2 := setup(t)
	src = f2.host(t, "app", "10.1.1.50", nil, "")
	v = f2.host(t, "db", "10.1.1.51", nil, "")
	f2.spray(t, src, "10.1.1.50", v)
	if err := f2.engine(ScopeAll).Tick(f2.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f2.received("app"); len(got) != 0 {
		t.Fatalf("生产等级的来源不隔离：%v", got)
	}
	if got := f2.received("db"); len(got) != 1 || got[0].Target != "10.1.1.50" {
		t.Fatalf("受害方应封锁来源：%v", got)
	}
}

// 控制台开关：关闭时不做新处置，打开后下一轮按配置的范围生效
func TestConsoleSwitch(t *testing.T) {
	f := setup(t)
	src := f.host(t, "range", "10.1.1.170", nil, "")
	app := f.host(t, "app", "10.1.1.50", nil, "")
	f.spray(t, src, "10.1.1.170", app)
	e := f.engine(ScopeLab)
	e.Config = &Store{DB: f.client}
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.client.Containment.Query().CountX(f.ctx); n != 0 {
		t.Fatalf("默认关闭不应处置：%d", n)
	}
	if err := e.Config.Save(f.ctx, Config{Enabled: true, Scope: ScopeAll}); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("app"); len(got) != 1 || got[0].Target != "10.1.1.170" {
		t.Fatalf("开启并放开到 all 后应封锁来源：%v", got)
	}
}

// 核心来源（跑着 openxdr-server）：不隔离；受害方也是核心时不封，免得两台平台节点互相切断
func TestCoreSourceNeverPartitionsControlPlane(t *testing.T) {
	f := setup(t)
	server := `[{"process":"openxdr-server","port":8081}]`
	src := f.host(t, "node1", "10.1.1.198", tierPtr(entasset.ResponseTierLab), server)
	peer := f.host(t, "node2", "10.1.1.197", nil, server)
	app := f.host(t, "app", "10.1.1.50", nil, "")
	f.spray(t, src, "10.1.1.198", peer, app)
	if err := f.engine(ScopeAll).Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("node1"); len(got) != 0 {
		t.Fatalf("核心来源不隔离（资产指定的实验等级也压不过）：%v", got)
	}
	if got := f.received("node2"); len(got) != 0 {
		t.Fatalf("核心受害方不封核心来源：%v", got)
	}
	if got := f.received("app"); len(got) != 1 || got[0].Target != "10.1.1.198" {
		t.Fatalf("普通受害方照样封锁：%v", got)
	}
}

// 熔断：一小时内执行数到上限后只记 held；封 server 自己的地址直接跳过
func TestFuseAndProtectedTargets(t *testing.T) {
	f := setup(t)
	src := f.host(t, "range", "10.1.1.170", nil, "")
	var victims []*ent.Asset
	for i, name := range []string{"a", "b", "c"} {
		victims = append(victims, f.host(t, name, "10.1.2."+string(rune('1'+i)), nil, ""))
	}
	f.spray(t, src, "10.1.1.170", victims...)
	e := f.engine(ScopeAll)
	e.MaxPerHour = 2
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.client.Containment.Query().Where(entcontainment.StateEQ(entcontainment.StatePending)).CountX(f.ctx); n != 2 {
		t.Fatalf("上限 2：回执前应有 2 条待确认，实际 %d", n)
	}
	held := f.client.Containment.Query().Where(entcontainment.StateEQ(entcontainment.StateHeld)).AllX(f.ctx)
	if len(held) != 1 {
		t.Fatalf("第三条应被熔断挡下：%+v", held)
	}
	f.received("a")
	f.received("b")
	if n := f.client.Containment.Query().Where(entcontainment.StateEQ(entcontainment.StateActive)).CountX(f.ctx); n != 2 {
		t.Fatalf("上限 2：回执后应有 2 条生效，实际 %d", n)
	}

	g := setup(t)
	src = g.host(t, "vip", "10.1.1.199", nil, "")
	v := g.host(t, "app", "10.1.1.50", nil, "")
	g.spray(t, src, "10.1.1.199", v)
	if err := g.engine(ScopeAll).Tick(g.ctx); err != nil {
		t.Fatal(err)
	}
	rows := g.client.Containment.Query().AllX(g.ctx)
	if len(g.received("app")) != 0 || len(rows) != 1 || rows[0].State != entcontainment.StateSkipped {
		t.Fatalf("封 server 自己的地址必须跳过：%+v", rows)
	}
}

// 组内隔离上限：纳管 2 台时最多同时隔离 1 台
func TestGroupIsolationCap(t *testing.T) {
	f := setup(t)
	lab := tierPtr(entasset.ResponseTierLab)
	a := f.host(t, "range-a", "10.1.1.170", lab, "")
	b := f.host(t, "range-b", "10.1.1.171", lab, "")
	f.spray(t, a, "10.1.1.170")
	f.spray(t, b, "10.1.1.171")
	if err := f.engine(ScopeLab).Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.client.Containment.Query().Where(entcontainment.KindEQ("isolate_host"), entcontainment.StateEQ(entcontainment.StatePending)).CountX(f.ctx); n != 1 {
		t.Fatalf("组内回执前应有 1 台待确认隔离，实际 %d", n)
	}
	if n := f.client.Containment.Query().Where(entcontainment.StateEQ(entcontainment.StateHeld)).CountX(f.ctx); n != 1 {
		t.Fatalf("第二台应被挡下，实际 %d", n)
	}
	f.received("range-a")
	if n := f.client.Containment.Query().Where(entcontainment.KindEQ("isolate_host"), entcontainment.StateEQ(entcontainment.StateActive)).CountX(f.ctx); n != 1 {
		t.Fatalf("组内只能隔离 1 台，实际 %d", n)
	}
}

// event 在主机上落一条事件并挂告警
func (f *fixture) alertOn(t *testing.T, host *ent.Asset, rule string, class int, user string, raw string) *ent.Alert {
	guid := uuid.New()
	create := f.client.Event.Create().SetTs(f.now.Add(-2 * time.Minute)).SetClassUID(class).SetSource("agent").
		SetAssetID(host.ID).SetProcessGUID(guid).SetRaw(json.RawMessage(raw))
	if user != "" {
		create.SetUsername(user)
	}
	ev := create.SaveX(f.ctx)
	return f.client.Alert.Create().SetRuleID(rule).SetSeverity(5).SetAssetID(host.ID).SetEventID(ev.ID).
		SetTs(ev.Ts).SaveX(f.ctx)
}

func (f *fixture) states() map[string]entcontainment.State {
	out := map[string]entcontainment.State{}
	for _, c := range f.client.Containment.Query().AllX(f.ctx) {
		out[c.Kind+" "+c.Target] = c.State
	}
	return out
}

// 爆破得手：封锁来源、锁定账号；来源是实验等级的纳管主机就隔离它。锁账号是一次性的，到期不解锁
func TestBruteforceSuccessBlocksLocksAndIsolatesLabSource(t *testing.T) {
	f := setup(t)
	f.host(t, "range", "10.1.1.170", tierPtr(entasset.ResponseTierLab), "")
	victim := f.host(t, "web", "10.1.1.183", nil, "")
	f.alertOn(t, victim, sigma.RuleBruteforceSuccess, 3002, "deploy", `{"src_endpoint":{"ip":"10.1.1.170"},"user":{"name":"deploy"}}`)
	e := f.engine(ScopeLab)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("range"); len(got) != 1 || got[0].Kind != pb.CommandKind_ISOLATE_HOST {
		t.Fatalf("实验等级来源应隔离：%v", got)
	}
	got := f.received("web")
	if len(got) != 2 || got[0].Kind != pb.CommandKind_BLOCK_NETWORK || got[0].Target != "10.1.1.170" ||
		got[1].Kind != pb.CommandKind_DISABLE_ACCOUNT || got[1].Target != "deploy" {
		t.Fatalf("受害方应封锁来源并锁定账号：%v", got)
	}
	if s := f.states(); s["disable_account deploy"] != entcontainment.StateExecuted || s["block_network 10.1.1.170"] != entcontainment.StateActive {
		t.Fatalf("锁账号一次性、封锁走租约：%v", s)
	}
	f.now = f.now.Add(25 * time.Hour)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.received("web") {
		if c.Kind == pb.CommandKind_ENABLE_ACCOUNT {
			t.Fatal("到期不能自动解锁被爆破的账号")
		}
	}
}

// 爆破得手：外部来源时只看受害方；内置账号由目标校验挡下，核心主机不锁账号；范围 lab 下生产主机不处置
func TestBruteforceGuards(t *testing.T) {
	f := setup(t)
	web := f.host(t, "web", "10.1.1.183", nil, "")
	core := f.host(t, "db", "10.1.1.184", tierPtr(entasset.ResponseTierCore), "")
	f.alertOn(t, web, sigma.RuleBruteforceSuccess, 3002, "root", `{"src_endpoint":{"ip":"203.0.113.5"}}`)
	f.alertOn(t, core, sigma.RuleBruteforceSuccess, 3002, "deploy", `{"src_endpoint":{"ip":"203.0.113.6"}}`)
	if err := f.engine(ScopeLab).Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(f.received("web")) + len(f.received("db")); n != 0 {
		t.Fatalf("范围 lab 下生产与核心主机不处置，实际下发 %d 条", n)
	}

	g := setup(t)
	web = g.host(t, "web", "10.1.1.183", nil, "")
	core = g.host(t, "db", "10.1.1.184", tierPtr(entasset.ResponseTierCore), "")
	g.alertOn(t, web, sigma.RuleBruteforceSuccess, 3002, "root", `{"src_endpoint":{"ip":"203.0.113.5"}}`)
	g.alertOn(t, core, sigma.RuleBruteforceSuccess, 3002, "deploy", `{"src_endpoint":{"ip":"203.0.113.6"}}`)
	if err := g.engine(ScopeAll).Tick(g.ctx); err != nil {
		t.Fatal(err)
	}
	if got := g.received("web"); len(got) != 1 || got[0].Target != "203.0.113.5" {
		t.Fatalf("root 不能锁，只封锁来源：%v", got)
	}
	if got := g.received("db"); len(got) != 1 || got[0].Target != "203.0.113.6" {
		t.Fatalf("核心主机只封锁来源：%v", got)
	}
	s := g.states()
	if s["disable_account root"] != entcontainment.StateSkipped || s["disable_account deploy"] != entcontainment.StateSkipped {
		t.Fatalf("内置账号与核心主机的锁定应记 skipped：%v", s)
	}
}

// 情报命中 IP：主动外连时封锁并结束进程；入站命中只封锁，不碰本机服务进程
func TestIntelIPOutboundKillsInboundOnlyBlocks(t *testing.T) {
	f := setup(t)
	out := f.host(t, "app", "10.1.1.50", nil, "")
	in := f.host(t, "nginx", "10.1.1.51", nil, "")
	f.alertOn(t, out, "intel:ip:198.51.100.7", 4001, "",
		`{"process":{"pid":4242,"name":"miner"},"connection_info":{"direction":"outbound"},"dst_endpoint":{"ip":"198.51.100.7","port":443}}`)
	f.alertOn(t, in, "intel:ip:198.51.100.8", 4001, "",
		`{"process":{"pid":80,"name":"nginx"},"connection_info":{"direction":"inbound"},"src_endpoint":{"ip":"198.51.100.8"},"dst_endpoint":{"ip":"10.1.1.51","port":443}}`)
	// 低级别情报不处置
	low := f.alertOn(t, in, "intel:ip:198.51.100.9", 4001, "", `{"connection_info":{"direction":"inbound"}}`)
	f.client.Alert.UpdateOneID(low.ID).SetSeverity(3).ExecX(f.ctx)
	if err := f.engine(ScopeAll).Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	got := f.received("app")
	if len(got) != 2 || got[0].Kind != pb.CommandKind_BLOCK_NETWORK || got[1].Kind != pb.CommandKind_KILL_PROCESS || got[1].Pid != 4242 || got[1].ProcessGuid == "" {
		t.Fatalf("外连情报地址应封锁并结束进程：%v", got)
	}
	if got := f.received("nginx"); len(got) != 1 || got[0].Kind != pb.CommandKind_BLOCK_NETWORK || got[0].Target != "198.51.100.8" {
		t.Fatalf("入站命中只封锁：%v", got)
	}
}

// 情报命中文件哈希：进程本身命中就结束进程并隔离文件；核心资产不隔离文件；哈希碰在父进程上的不处置
func TestIntelHashKillsAndQuarantines(t *testing.T) {
	f := setup(t)
	app := f.host(t, "app", "10.1.1.50", nil, "")
	core := f.host(t, "db", "10.1.1.51", tierPtr(entasset.ResponseTierCore), "")
	other := f.host(t, "dev", "10.1.1.52", nil, "")
	const evil = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"
	proc := `{"process":{"pid":777,"name":"x","file":{"path":"/tmp/x","sha256":"` + evil + `"}}}`
	f.alertOn(t, app, "intel:hash:"+evil, 1007, "", proc)
	f.alertOn(t, core, "intel:hash:"+evil, 1007, "", proc)
	f.alertOn(t, other, "intel:hash:"+evil, 1007, "", `{"process":{"pid":9,"name":"bash","file":{"path":"/bin/bash"},"parent_process":{"file":{"sha256":"`+evil+`"}}}}`)
	if err := f.engine(ScopeAll).Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("app"); len(got) != 2 || got[0].Kind != pb.CommandKind_KILL_PROCESS || got[1].Kind != pb.CommandKind_QUARANTINE_FILE || got[1].Target != "/tmp/x" {
		t.Fatalf("应结束进程并隔离文件：%v", got)
	}
	if got := f.received("db"); len(got) != 1 || got[0].Kind != pb.CommandKind_KILL_PROCESS {
		t.Fatalf("核心资产只结束进程：%v", got)
	}
	if got := f.received("dev"); len(got) != 0 {
		t.Fatalf("哈希不是这个进程自己的，不处置：%v", got)
	}
}

// 平台指令与已知自动化引起的告警不处置
func TestOwnOperationsAreNotContained(t *testing.T) {
	f := setup(t)
	web := f.host(t, "web", "10.1.1.183", nil, "")
	al := f.alertOn(t, web, sigma.RuleBruteforceSuccess, 3002, "deploy", `{"src_endpoint":{"ip":"203.0.113.5"}}`)
	f.client.Alert.UpdateOneID(al.ID).SetAutomationID(uuid.New()).ExecX(f.ctx)
	if err := f.engine(ScopeAll).Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("web"); len(got) != 0 || f.client.Containment.Query().CountX(f.ctx) != 0 {
		t.Fatalf("已知自动化的告警不该处置：%v", got)
	}
}

// 人工解除：下发恢复动作；解除之前的证据（包括同一批的另一条告警）不再触发同一处置，之后的新证据照样触发
func TestManualLiftSticksUntilNewEvidence(t *testing.T) {
	f := setup(t)
	src := f.host(t, "range", "10.1.1.170", tierPtr(entasset.ResponseTierLab), "")
	v := f.host(t, "web", "10.1.1.183", nil, "")
	first := f.spray(t, src, "10.1.1.170", v)
	e := f.engine(ScopeLab)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.received("range")
	f.received("web")
	block := f.client.Containment.Query().Where(entcontainment.KindEQ("block_network")).OnlyX(f.ctx)
	if _, err := Lift(f.ctx, f.client, f.hub, block, "kei", "确认是演练"); err != nil {
		t.Fatal(err)
	}
	if got := f.received("web"); len(got) != 1 || got[0].Kind != pb.CommandKind_UNBLOCK_NETWORK {
		t.Fatalf("解除应下发 unblock：%v", got)
	}
	if _, err := Lift(f.ctx, f.client, f.hub, f.client.Containment.GetX(f.ctx, block.ID), "kei", ""); err != ErrNotLiftable {
		t.Fatalf("已解除的不能再解除：%v", err)
	}

	// 同一批证据的另一条告警晚到：不再封
	second := f.client.Alert.Create().SetRuleID(sigma.RuleLateralSpray).SetSeverity(5).SetAssetID(src.ID).
		SetTs(first.Ts).SetLastTs(*first.LastTs).SaveX(f.ctx)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("web"); len(got) != 0 {
		t.Fatalf("解除之前的证据不该重新封锁：%v", got)
	}

	// 解除之后的新证据：照样封
	f.now = f.now.Add(10 * time.Minute)
	f.client.Alert.UpdateOneID(second.ID).SetLastTs(f.now).ExecX(f.ctx)
	if _, err := f.db.Exec(`INSERT INTO lateral_evidence(event_id,src_asset,victim_asset,ts,src_ip) VALUES($1,$2,$3,$4,$5)`,
		uuid.New(), src.ID, v.ID, f.now, "10.1.1.170"); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("web"); len(got) != 1 || got[0].Kind != pb.CommandKind_BLOCK_NETWORK {
		t.Fatalf("新证据应重新封锁：%v", got)
	}

	// 结束进程撤不回
	kill := f.client.Containment.Create().SetAssetID(v.ID).SetKind("kill_process").SetTarget(uuid.NewString()).SetKey("k").
		SetSignal("intel:ip:1.2.3.4").SetAlertID(first.ID).SetRole("host").SetState("executed").SetReason("x").SaveX(f.ctx)
	if _, err := Lift(f.ctx, f.client, f.hub, kill, "kei", ""); err != ErrNotLiftable {
		t.Fatalf("结束进程不能撤回：%v", err)
	}
}

// outbound 在来源主机上落一条容器发起的外连
func (f *fixture) outbound(t *testing.T, src *ent.Asset, dst, uid, name, runtime string) {
	raw := `{"connection_info":{"direction":"outbound"},"dst_endpoint":{"ip":"` + dst + `","port":22},` +
		`"container":{"uid":"` + uid + `","name":"` + name + `","runtime":"` + runtime + `"}}`
	f.client.Event.Create().SetTs(f.now.Add(-5 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetAssetID(src.ID).SetRaw(json.RawMessage(raw)).SaveX(f.ctx)
}

// 认出发起喷洒的容器：只隔离容器，不动宿主机；生产等级的来源也隔离容器；核心不动；QEMU 与连向别处的不算
func TestSprayIsolatesSourceContainer(t *testing.T) {
	f := setup(t)
	lab := f.host(t, "uos-server", "10.1.1.170", tierPtr(entasset.ResponseTierLab), "")
	prod := f.host(t, "docker-host", "10.1.1.34", nil, "")
	core := f.host(t, "pve", "10.1.1.2", tierPtr(entasset.ResponseTierCore), "")
	v1 := f.host(t, "node1", "10.1.1.198", nil, "")
	v2 := f.host(t, "web", "10.1.1.183", nil, "")
	f.outbound(t, lab, "10.1.1.198", "4f173e0d45b0", "range_c11_comp1_t2", "docker")
	f.outbound(t, lab, "10.1.1.183", "4f173e0d45b0", "range_c11_comp1_t2", "docker")
	f.outbound(t, lab, "8.8.8.8", "aaaaaaaaaaaa", "dns-tool", "docker")
	f.outbound(t, prod, "10.1.1.198", "bbbbbbbbbbbb", "ctf0-web", "docker")
	f.outbound(t, prod, "10.1.1.183", "201", "", "qemu")
	f.outbound(t, core, "10.1.1.198", "cccccccccccc", "x", "docker")
	f.spray(t, lab, "10.1.1.170", v1, v2)
	f.spray(t, prod, "10.1.1.34", v1, v2)
	f.spray(t, core, "10.1.1.2", v1, v2)
	if err := f.engine(ScopeAll).Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("uos-server"); len(got) != 1 || got[0].Kind != pb.CommandKind_ISOLATE_CONTAINER || got[0].Target != "4f173e0d45b0" {
		t.Fatalf("实验等级认出容器只隔离容器：%v", got)
	}
	if got := f.received("docker-host"); len(got) != 1 || got[0].Kind != pb.CommandKind_ISOLATE_CONTAINER || got[0].Target != "bbbbbbbbbbbb" {
		t.Fatalf("生产等级也隔离来源容器，QEMU 不算：%v", got)
	}
	if got := f.received("pve"); len(got) != 0 {
		t.Fatalf("核心来源不动：%v", got)
	}
	c := f.client.Containment.Query().Where(entcontainment.TargetEQ("4f173e0d45b0")).OnlyX(f.ctx)
	if c.State != entcontainment.StateActive || c.ExpiresAt == nil || !strings.Contains(c.Reason, "range_c11_comp1_t2") {
		t.Fatalf("容器隔离走租约并写明容器名：%+v", c)
	}
	// 到期解除容器隔离
	f.now = f.now.Add(25 * time.Hour)
	if err := f.engine(ScopeAll).Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("uos-server"); len(got) != 1 || got[0].Kind != pb.CommandKind_UNISOLATE_CONTAINER || got[0].Target != "4f173e0d45b0" {
		t.Fatalf("到期解除容器隔离：%v", got)
	}
}

// 数据库拉起 shell（2026-11-03 原样）：核心的数据库主机上结束 shell、封锁 COPY 的客户端地址；客户端是实验等级的纳管主机就隔离它。
// 本机 socket 连入（[local]）没有客户端地址，只结束 shell；范围 lab 下核心主机自己的事不处置
func TestDatabaseShellKillsBlocksAndContainsClient(t *testing.T) {
	f := setup(t)
	server := `[{"process":"openxdr-server","port":8081}]`
	node1 := f.host(t, "openxdr-node1", "10.1.1.198", nil, server)
	f.host(t, "uos-server", "10.1.1.170", tierPtr(entasset.ResponseTierLab), "")
	raw := `{"process":{"pid":2268957,"name":"sh","file":{"path":"/bin/sh"},"cmd_line":"sh -c id",` +
		`"parent_process":{"pid":2268947,"name":"postgres","cmd_line":"postgres: postgres openxdr 10.1.1.170(41866) COPY"}}}`
	f.alertOn(t, node1, RuleDatabaseShell, 1007, "70", raw)
	if err := f.engine(ScopeLab).Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	got := f.received("openxdr-node1")
	if len(got) != 2 || got[0].Kind != pb.CommandKind_KILL_PROCESS || got[0].Pid != 2268957 ||
		got[1].Kind != pb.CommandKind_BLOCK_NETWORK || got[1].Target != "10.1.1.170" {
		t.Fatalf("数据库主机应结束 shell 并封锁客户端：%v", got)
	}
	if got := f.received("uos-server"); len(got) != 1 || got[0].Kind != pb.CommandKind_ISOLATE_HOST {
		t.Fatalf("实验等级的客户端主机应隔离：%v", got)
	}

	g := setup(t)
	node1 = g.host(t, "openxdr-node1", "10.1.1.198", nil, server)
	g.alertOn(t, node1, RuleDatabaseShell, 1007, "70", `{"process":{"pid":7,"name":"sh","parent_process":{"name":"postgres","cmd_line":"postgres: postgres openxdr [local] COPY"}}}`)
	if err := g.engine(ScopeLab).Tick(g.ctx); err != nil {
		t.Fatal(err)
	}
	if got := g.received("openxdr-node1"); len(got) != 0 {
		t.Fatalf("范围 lab 下核心主机自己的事不处置：%v", got)
	}
	if err := g.engine(ScopeAll).Tick(g.ctx); err != nil {
		t.Fatal(err)
	}
	if got := g.received("openxdr-node1"); len(got) != 0 {
		t.Fatalf("同一条告警已经决定过（skipped），放开范围后不追溯：%v", got)
	}
}

// 原地 exec：sh -c 'sleep 90' 的 sh 变成 sleep，PID 与父进程不变、GUID 换了；结束进程要用现在的 GUID。
// 父进程不同的同 PID 进程（PID 复用）不算
func TestKillFollowsInPlaceExec(t *testing.T) {
	f := setup(t)
	host := f.host(t, "openxdr-test-linux", "10.1.1.137", tierPtr(entasset.ResponseTierLab), "")
	raw := func(name string, ppid int) string {
		return `{"activity_id":1,"process":{"pid":13311,"name":"` + name + `","parent_process":{"pid":` + strconv.Itoa(ppid) +
			`,"name":"postgres","cmd_line":"postgres: postgres postgres [local] COPY"}}}`
	}
	al := f.alertOn(t, host, RuleDatabaseShell, 1007, "70", raw("sh", 13300))
	sh := f.client.Event.GetX(f.ctx, *al.EventID)
	sleep := f.client.Event.Create().SetTs(sh.Ts.Add(time.Millisecond)).SetClassUID(1007).SetSource("agent").SetAssetID(host.ID).
		SetProcessGUID(uuid.New()).SetRaw(json.RawMessage(raw("sleep", 13300))).SaveX(f.ctx)
	f.client.Event.Create().SetTs(sh.Ts.Add(2 * time.Millisecond)).SetClassUID(1007).SetSource("agent").SetAssetID(host.ID).
		SetProcessGUID(uuid.New()).SetRaw(json.RawMessage(raw("other", 1))).SaveX(f.ctx)
	if err := f.engine(ScopeLab).Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	got := f.received("openxdr-test-linux")
	if len(got) != 1 || got[0].Kind != pb.CommandKind_KILL_PROCESS || got[0].ProcessGuid != sleep.ProcessGUID.String() {
		t.Fatalf("应按 exec 后的 GUID 结束进程 %s：%v", sleep.ProcessGUID, got)
	}
}

// 到期复核：模型说解除才解除；说续期就续一个租约；认不出就续一小时尽快再问；满 7 天不再问，直接解除
func TestExpiryReview(t *testing.T) {
	var answer string
	calls := 0
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": answer}}}})
	}))
	t.Cleanup(llm.Close)

	f := setup(t)
	src := f.host(t, "range", "10.1.1.170", tierPtr(entasset.ResponseTierLab), "")
	v := f.host(t, "web", "10.1.1.183", nil, "")
	f.spray(t, src, "10.1.1.170", v)
	e := f.engine(ScopeLab)
	e.LLM = triage.NewLLM(llm.URL, "fake", "", 5*time.Second)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.received("range")
	f.received("web")
	block := func() *ent.Containment {
		return f.client.Containment.Query().Where(entcontainment.KindEQ("block_network")).OnlyX(f.ctx)
	}

	answer = `{"decision":"extend","reason":"来源仍在喷洒"}`
	f.now = f.now.Add(25 * time.Hour)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if c := block(); c.State != entcontainment.StateActive || c.Reviews != 1 || !c.ExpiresAt.Equal(f.now.Add(24*time.Hour)) || !strings.Contains(c.Reason, "来源仍在喷洒") {
		t.Fatalf("续期一个租约并记下依据：%+v", c)
	}
	if got := f.received("web"); len(got) != 0 {
		t.Fatalf("续期不下发解除：%v", got)
	}

	answer = "我觉得可以先观察一下"
	f.now = f.now.Add(25 * time.Hour)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if c := block(); c.State != entcontainment.StateActive || !c.ExpiresAt.Equal(f.now.Add(time.Hour)) {
		t.Fatalf("认不出的输出续一小时：%+v", c)
	}

	answer = `{"decision":"lift","reason":"租约期间没有新告警，来源已清理"}`
	f.now = f.now.Add(2 * time.Hour)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("web"); len(got) != 1 || got[0].Kind != pb.CommandKind_UNBLOCK_NETWORK {
		t.Fatalf("模型说解除才下发解除：%v", got)
	}
	if c := block(); c.State != entcontainment.StateExpired || !strings.Contains(c.Reason, "AI 复核解除") {
		t.Fatalf("解除并记下依据：%+v", c)
	}

	// 隔离那条一直续期，满 7 天不再问模型
	answer = `{"decision":"extend","reason":"仍可疑"}`
	f.now = f.now.Add(8 * 24 * time.Hour)
	before := calls
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("range"); len(got) != 1 || got[0].Kind != pb.CommandKind_UNISOLATE_HOST || calls != before {
		t.Fatalf("满最长期限直接解除、不再问模型：%v（调用 %d→%d）", got, before, calls)
	}
}

// 回执闭环与安全边界：初始投递 sent 不算已生效；延迟成功/失败/不支持/未知回执对账；
// 解除指令 sent/pending/unknown/unsupported 不写 EndedAt 且不重复建指令；PID 已退出与身份不符安全拒绝归类且不补杀；
// 历史 executed+failed 不一致记录自动修复。
func TestReceiptReconciliationAndSafetyBounds(t *testing.T) {
	f := setup(t)
	host := f.host(t, "endpoint", "10.1.1.50", tierPtr(entasset.ResponseTierLab), "")
	e := f.engine(ScopeAll)

	// 1. 初始投递 sent：处于 pending，不标 active/executed；回执失败（目标已消失/身份不符）后转 failed 且不重发
	al := f.alertOn(t, host, "intel:ip:198.51.100.7", 4001, "",
		`{"process":{"pid":4242,"name":"miner"},"connection_info":{"direction":"outbound"},"dst_endpoint":{"ip":"198.51.100.7","port":443}}`)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	block := f.client.Containment.Query().Where(entcontainment.KindEQ("block_network")).OnlyX(f.ctx)
	kill := f.client.Containment.Query().Where(entcontainment.KindEQ("kill_process")).OnlyX(f.ctx)
	if block.State != entcontainment.StatePending || kill.State != entcontainment.StatePending {
		t.Fatalf("初始投递尚未回执应为 pending: block=%s kill=%s", block.State, kill.State)
	}
	<-f.inbox["endpoint"]
	<-f.inbox["endpoint"]
	if err := f.hub.Complete(f.ctx, f.agents["endpoint"], &pb.CommandResult{
		CommandId: block.CommandID.String(), Status: pb.CommandResult_SUCCEEDED, Detail: "ok",
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.hub.Complete(f.ctx, f.agents["endpoint"], &pb.CommandResult{
		CommandId: kill.CommandID.String(), Status: pb.CommandResult_FAILED,
		Detail: "进程身份不匹配或已过期，拒绝结束进程",
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	block = f.client.Containment.GetX(f.ctx, block.ID)
	kill = f.client.Containment.GetX(f.ctx, kill.ID)
	if block.State != entcontainment.StateActive {
		t.Fatalf("block_network 成功回执后应为 active: %+v", block)
	}
	if kill.State != entcontainment.StateFailed || !strings.Contains(kill.Reason, "安全闸门拒绝") {
		t.Fatalf("kill_process 身份不符应归类为安全闸门拒绝并转 failed: %+v", kill)
	}
	if len(f.inbox["endpoint"]) != 0 {
		t.Fatalf("失败的 kill_process 不应自动补杀")
	}
	_ = al

	// 2. 历史 executed 但底层命令 failed 的记录自动对账修正
	f.client.Containment.UpdateOneID(kill.ID).SetState(entcontainment.StateExecuted).ExecX(f.ctx)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.client.Containment.GetX(f.ctx, kill.ID); got.State != entcontainment.StateFailed {
		t.Fatalf("历史虚假 executed 应被修正为 failed: %+v", got)
	}

	// 3. 租约到期解除：sent / unknown 阶段保持 active 且 EndedAt 为空，且不重复下发；收到 succeeded 才转 expired
	f.now = f.now.Add(25 * time.Hour)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	liftCmdProto := <-f.inbox["endpoint"]
	block = f.client.Containment.GetX(f.ctx, block.ID)
	if block.State != entcontainment.StateActive || block.EndedAt != nil || block.LiftCommandID == nil {
		t.Fatalf("解除指令仅投递时应保持 active 且 EndedAt 为空: %+v", block)
	}
	f.now = f.now.Add(time.Hour)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.inbox["endpoint"]) != 0 {
		t.Fatalf("在途解除指令不应重复创建")
	}
	if err := f.hub.Complete(f.ctx, f.agents["endpoint"], &pb.CommandResult{
		CommandId: liftCmdProto.Id, Status: pb.CommandResult_SUCCEEDED, Detail: "unblocked",
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	block = f.client.Containment.GetX(f.ctx, block.ID)
	if block.State != entcontainment.StateExpired || block.EndedAt == nil {
		t.Fatalf("解除指令成功回执后应转 expired 并写 EndedAt: %+v", block)
	}
}

func TestContainmentCommandIdempotencyAndConcurrency(t *testing.T) {
	f := setup(t)
	host := f.host(t, "endpoint", "10.0.1.31", tierPtr(entasset.ResponseTierLab), "")

	al := f.client.Alert.Create().SetTs(f.now).SetRuleID("test.idempotent").SetSeverity(5).SetAssetID(host.ID).SaveX(f.ctx)
	e := f.engine(ScopeAll)
	act := action{asset: host, kind: "block_network", target: "198.51.100.77", role: "host", why: "幂等与并发核验"}
	if err := e.decide(f.ctx, al, nil, act, f.now); err != nil {
		t.Fatal(err)
	}
	initProto := <-f.inbox["endpoint"]
	c := f.client.Containment.Query().Where(entcontainment.AlertIDEQ(al.ID)).OnlyX(f.ctx)
	initCmdID := *c.CommandID

	// 同一 CommandID + 完全一致动作身份重复调用：返回已有 prior，不再投递
	prior, err := f.hub.Issue(f.ctx, response.Request{
		CommandID: initCmdID, AssetID: host.ID, Kind: "block_network", Target: "198.51.100.77", IssuedBy: "auto", AllowEndpoints: e.AllowEndpoints,
	})
	if err != nil || prior.ID != initCmdID || len(f.inbox["endpoint"]) != 0 {
		t.Fatalf("同身份幂等复用异常: prior=%v err=%v inbox=%d", prior, err, len(f.inbox["endpoint"]))
	}

	// 同一 CommandID 但目标不同：拒绝复用，防止跨目标回执串号
	if _, err := f.hub.Issue(f.ctx, response.Request{
		CommandID: initCmdID, AssetID: host.ID, Kind: "block_network", Target: "198.51.100.88", IssuedBy: "auto", AllowEndpoints: e.AllowEndpoints,
	}); err == nil {
		t.Fatalf("同 CommandID 不同目标应当拒绝复用")
	}

	// 初次处置回执成功 -> active，再并发调用 Lift：只建一条解除指令、投递一次
	agentID := *host.AgentID
	if err := f.hub.Complete(f.ctx, agentID, &pb.CommandResult{
		CommandId: initProto.Id, Status: pb.CommandResult_SUCCEEDED, Detail: "blocked",
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	c = f.client.Containment.GetX(f.ctx, c.ID)

	var wg sync.WaitGroup
	for _, actor := range []string{"alice", "bob"} {
		wg.Add(1)
		go func(who string) {
			defer wg.Done()
			_, _ = Lift(f.ctx, f.client, f.hub, c, who, "并发人工解除")
		}(actor)
	}
	wg.Wait()
	if n := f.client.Command.Query().CountX(f.ctx); n != 2 {
		t.Fatalf("并发人工解除应只产生 1 条解除指令（含初次封禁共 2 条），实得 %d", n)
	}
	if len(f.inbox["endpoint"]) != 1 {
		t.Fatalf("并发人工解除应只投递 1 次解除指令，实得 %d", len(f.inbox["endpoint"]))
	}
}

func TestClassifyFailurePidfdDoesNotFalsePositiveOnEpermOrEnosys(t *testing.T) {
	for _, detail := range []string{
		"进程不存在或无法打开 pidfd: Operation not permitted (os error 1)",
		"进程不存在或无法打开 pidfd: Function not implemented (os error 38)",
	} {
		d := detail
		if cause := classifyFailure("kill_process", "failed", &d); strings.Contains(cause, "目标已消失") {
			t.Fatalf("pidfd EPERM/ENOSYS 不应被误判为目标已退出: %s -> %s", detail, cause)
		}
	}

	gone := "进程不存在或无法打开 pidfd: No such process (os error 3)"
	if cause := classifyFailure("kill_process", "failed", &gone); !strings.Contains(cause, "目标已消失") {
		t.Fatalf("pidfd ESRCH (No such process) 应被判定为目标已退出: %s", cause)
	}
}

// 复核事实只看本租约期：上一期的命中不再带着；租约前就在例行出现的规则（cron 之类）不算攻击迹象
func TestReviewFactsCoverThisPeriodWithoutBackground(t *testing.T) {
	f := setup(t)
	src := f.host(t, "range", "10.1.1.170", tierPtr(entasset.ResponseTierLab), "")
	v := f.host(t, "web", "10.1.1.183", nil, "")
	alertAt := func(rule string, ts, last time.Time) {
		f.client.Alert.Create().SetRuleID(rule).SetSeverity(3).SetAssetID(v.ID).SetTs(ts).SetLastTs(last).SaveX(f.ctx)
	}
	start := f.now
	alertAt("hourly-cron", start.Add(-3*24*time.Hour), start.Add(48*time.Hour))
	f.spray(t, src, "10.1.1.170", v)
	e := f.engine(ScopeLab)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	block := f.client.Containment.Query().Where(entcontainment.KindEQ("block_network")).OnlyX(f.ctx)
	alertAt("first-period", start.Add(time.Hour), start.Add(time.Hour))
	f.now = start.Add(49 * time.Hour)
	alertAt("this-period", f.now.Add(-time.Hour), f.now.Add(-time.Hour))

	facts, err := e.reviewFacts(f.ctx, block)
	if err != nil {
		t.Fatal(err)
	}
	if !facts.Now.Equal(f.now) || !facts.PeriodStart.Equal(f.now.Add(-24*time.Hour)) {
		t.Fatalf("事实要带当前时间与本期起点：%v %v", facts.Now, facts.PeriodStart)
	}
	if len(facts.HostAlerts) != 1 || facts.HostAlerts[0].Rule != "this-period" {
		t.Fatalf("只应剩本期的新告警：%+v", facts.HostAlerts)
	}
}
