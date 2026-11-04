//go:build integration

package containment

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
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

// received 取走某台主机收到的全部指令
func (f *fixture) received(name string) []*pb.Command {
	var out []*pb.Command
	for {
		select {
		case c := <-f.inbox[name]:
			out = append(out, c)
		default:
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
		if c.AlertID != al.ID || c.SourceAssetID != src.ID || c.CommandID == nil || !c.ExpiresAt.Equal(al.LastTs.Add(24*time.Hour)) {
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
	if n := f.client.Containment.Query().Where(entcontainment.StateEQ(entcontainment.StateActive)).CountX(f.ctx); n != 2 {
		t.Fatalf("上限 2：应有 2 条生效，实际 %d", n)
	}
	held := f.client.Containment.Query().Where(entcontainment.StateEQ(entcontainment.StateHeld)).AllX(f.ctx)
	if len(held) != 1 {
		t.Fatalf("第三条应被熔断挡下：%+v", held)
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
	if n := f.client.Containment.Query().Where(entcontainment.KindEQ("isolate_host"), entcontainment.StateEQ(entcontainment.StateActive)).CountX(f.ctx); n != 1 {
		t.Fatalf("组内只能隔离 1 台，实际 %d", n)
	}
	if n := f.client.Containment.Query().Where(entcontainment.StateEQ(entcontainment.StateHeld)).CountX(f.ctx); n != 1 {
		t.Fatalf("第二台应被挡下，实际 %d", n)
	}
}
