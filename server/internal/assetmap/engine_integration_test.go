//go:build integration

package assetmap

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/assetlink"
	"openxdr/server/internal/testdb"
	"openxdr/server/internal/triage"
)

// 网络事件聚合成依赖边、设备清单物化到资产，游标落库后重跑不重复计数；
// 图谱与攻击面基于物化结果给出正确的对端与暴露面。
func TestEngineMaterializesLinksAndInventory(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	group, err := client.Group.Create().SetName("prod").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	web, _ := client.Asset.Create().SetHostname("web-01").SetIPAddrs([]string{"10.0.0.1"}).SetGroupID(group.ID).Save(ctx)
	dbHost, _ := client.Asset.Create().SetHostname("db-01").SetIPAddrs([]string{"10.0.0.2"}).SetGroupID(group.ID).Save(ctx)

	now := time.Now()
	guid := uuid.New()
	mustEvent := func(c *ent.EventCreate) {
		if _, err := c.Save(ctx); err != nil {
			t.Fatal(err)
		}
	}
	mustEvent(client.Event.Create().SetTs(now.Add(-5 * time.Minute)).SetClassUID(1007).SetSource("agent").SetAssetID(web.ID).
		SetProcessGUID(guid).SetRaw(json.RawMessage(`{"process":{"name":"nginx"}}`)))
	for i := range 3 {
		mustEvent(client.Event.Create().SetTs(now.Add(-time.Duration(4-i) * time.Minute)).SetClassUID(classNetwork).SetSource("agent").
			SetAssetID(web.ID).SetProcessGUID(guid).SetConnTuple("tcp:10.0.0.1:40000>10.0.0.2:5432").
			SetRaw(json.RawMessage(`{"src_endpoint":{"ip":"10.0.0.1","port":40000},"dst_endpoint":{"ip":"10.0.0.2","port":5432}}`)))
	}
	// 同一网桥上的容器互连，不该成为依赖
	mustEvent(client.Event.Create().SetTs(now.Add(-time.Minute)).SetClassUID(classNetwork).SetSource("agent").SetAssetID(web.ID).
		SetRaw(json.RawMessage(`{"src_endpoint":{"ip":"172.18.0.3","port":1},"dst_endpoint":{"ip":"172.18.0.4","port":6379}}`)))
	inv := `{"activity_id":2,"device":{"listening":[{"proto":"tcp","addr":"0.0.0.0","port":5432,"process":{"pid":9,"name":"postgres"}}]}}`
	mustEvent(client.Event.Create().SetTs(now.Add(-30 * time.Second)).SetClassUID(ClassInventory).SetSource("agent").SetAssetID(dbHost.ID).SetRaw(json.RawMessage(inv)))
	// 更早的快照乱序到达，不能覆盖新的
	mustEvent(client.Event.Create().SetTs(now.Add(-40 * time.Second)).SetClassUID(ClassInventory).SetSource("agent").SetAssetID(dbHost.ID).
		SetRaw(json.RawMessage(`{"device":{"listening":[]}}`)))

	e := &Engine{DB: client, SQL: db, Interval: time.Second}
	e.cursor, e.cursorID = e.loadCursor(ctx)
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	links, err := client.AssetLink.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].Count != 3 || links[0].Process != "nginx" || links[0].DstPort != 5432 || *links[0].SrcAssetID != web.ID {
		t.Fatalf("依赖边: %+v", links)
	}
	got, _ := client.Asset.Get(ctx, dbHost.ID)
	if got.InventoryAt == nil || len(listenersOf(got)) != 1 {
		t.Fatalf("清单物化: %s", got.Listening)
	}

	// 游标已落库：新引擎实例接着扫，不重复计数
	mustEvent(client.Event.Create().SetTs(now).SetClassUID(classNetwork).SetSource("agent").SetAssetID(web.ID).SetProcessGUID(guid).
		SetRaw(json.RawMessage(`{"src_endpoint":{"ip":"10.0.0.1","port":40001},"dst_endpoint":{"ip":"10.0.0.2","port":5432}}`)))
	e2 := &Engine{DB: client, SQL: db, Interval: time.Second}
	e2.cursor, e2.cursorID = e2.loadCursor(ctx)
	if n, err := e2.batch(ctx); err != nil || n != 1 {
		t.Fatalf("续扫应只读到新事件: n=%d err=%v", n, err)
	}
	if l, _ := client.AssetLink.Query().Where(assetlink.DstPortEQ(5432)).Only(ctx); l.Count != 4 {
		t.Fatalf("续扫计数: %d", l.Count)
	}

	g, err := LoadGroup(ctx, client, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	graph := g.Graph(now)
	if len(graph.Nodes) != 2 || len(graph.Edges) != 1 || graph.Edges[0].Processes[0] != "nginx" {
		t.Fatalf("图谱: %+v", graph)
	}
	s := g.Surface()
	if len(s.Exposures) != 1 || s.Exposures[0].Peers[0] != "web-01" || len(s.Summary.NoInventory) != 1 {
		t.Fatalf("攻击面: %+v", s)
	}
}

// agent 在服务端看到的入站：发起方未纳管才记（发起方由地址解析、进程不记），纳管的发起方已有自己的出站
func TestEngineInboundLinks(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	group, _ := client.Group.Create().SetName("prod").Save(ctx)
	client.Asset.Create().SetHostname("web-01").SetIPAddrs([]string{"10.0.0.1"}).SetGroupID(group.ID).SaveX(ctx)
	dbHost := client.Asset.Create().SetHostname("db-01").SetIPAddrs([]string{"10.0.0.2"}).SetGroupID(group.ID).SaveX(ctx)
	inbound := func(src string) {
		client.Event.Create().SetTs(time.Now().Add(-time.Minute)).SetClassUID(classNetwork).SetSource("agent").SetAssetID(dbHost.ID).
			SetConnTuple("tcp:" + src + ":50000>10.0.0.2:5432").
			SetRaw(json.RawMessage(`{"connection_info":{"direction":"inbound"},"src_endpoint":{"ip":"` + src + `","port":50000},"dst_endpoint":{"ip":"10.0.0.2","port":5432},"process":{"name":"postgres"}}`)).
			SaveX(ctx)
	}
	inbound("10.0.0.9")
	inbound("10.0.0.1")
	// 宿主机上容器之间的入站（目的不是宿主机自己的地址）不算这台资产的依赖
	client.Event.Create().SetTs(time.Now().Add(-time.Minute)).SetClassUID(classNetwork).SetSource("agent").SetAssetID(dbHost.ID).
		SetRaw(json.RawMessage(`{"connection_info":{"direction":"inbound"},"src_endpoint":{"ip":"172.18.0.3","port":1},"dst_endpoint":{"ip":"172.18.0.2","port":5432}}`)).
		SaveX(ctx)
	e := &Engine{DB: client, SQL: db, Interval: time.Second}
	e.cursor, e.cursorID = e.loadCursor(ctx)
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	links := client.AssetLink.Query().AllX(ctx)
	if len(links) != 1 || links[0].SrcIP != "10.0.0.9" || links[0].SrcAssetID != nil || links[0].Process != "" || links[0].DstIP != "10.0.0.2" {
		t.Fatalf("入站依赖边: %+v", links)
	}
}

// 清单到了的新资产当轮标注；人工锁定的字段不被覆盖；编造的对端被丢弃；
// 模型输出坏了不写入、隔一个周期再试。
func TestAnnotateRespectsLocksAndFacts(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	reply := `{"role":"PostgreSQL 数据库","summary":"业务主库","criticality":5,"reason":"被应用依赖","relations":[{"peer":"web-01","note":"读写业务库"},{"peer":"ghost","note":"编造"}]}`
	calls := 0
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": reply}}}})
	}))
	t.Cleanup(llm.Close)

	now := time.Now()
	web, _ := client.Asset.Create().SetHostname("web-01").SetIPAddrs([]string{"10.0.0.1"}).Save(ctx)
	dbHost, _ := client.Asset.Create().SetHostname("db-01").SetIPAddrs([]string{"10.0.0.2"}).SetInventoryAt(now).
		SetListening(json.RawMessage(`[{"proto":"tcp","addr":"0.0.0.0","port":5432,"process":"postgres"}]`)).
		SetRole("人工定的角色").SetLockedFields([]string{"role"}).Save(ctx)
	client.AssetLink.Create().SetSrcIP("10.0.0.1").SetSrcAssetID(web.ID).SetDstIP("10.0.0.2").SetDstPort(5432).SetProto("tcp").
		SetCount(3).SetFirstSeen(now).SetLastSeen(now).SaveX(ctx)

	e := &Engine{DB: client, SQL: db, LLM: triage.NewLLM(llm.URL, "fake", "", 5*time.Second), Interval: time.Second}
	e.annotateDue(ctx)
	got := client.Asset.GetX(ctx, dbHost.ID)
	if *got.Role != "人工定的角色" || *got.Criticality != 5 || got.AnnotatedAt == nil {
		t.Fatalf("锁定字段不能被覆盖，其余照写: role=%v crit=%v", *got.Role, got.Criticality)
	}
	if got.RelationNotes["web-01"] != "读写业务库" || len(got.RelationNotes) != 1 {
		t.Fatalf("只保留事实里出现过的对端: %v", got.RelationNotes)
	}
	if w := client.Asset.GetX(ctx, web.ID); w.AnnotatedAt != nil {
		t.Fatal("清单还没到的新资产先不标注")
	}

	// 坏输出：不写入，且在一个检查周期内不再重试
	reply = "抱歉，我无法判断"
	client.Asset.UpdateOneID(web.ID).SetInventoryAt(now).ExecX(ctx)
	before := calls
	e.annotateDue(ctx)
	e.annotateDue(ctx)
	if calls != before+1 || client.Asset.GetX(ctx, web.ID).Role != nil {
		t.Fatalf("坏输出不写入且退避: calls %d→%d", before, calls)
	}
}

// 未 connect 的 UDP 套接字源地址是未指定地址：旧 agent 照报 0.0.0.0、新 agent 查不到出口时省略，
// 都记到上报资产自己的地址上；旧库里已有的 0.0.0.0 / :: 边归属不可信，启动时清掉，图谱上不出现未指定地址节点。
func TestEngineUnspecifiedSource(t *testing.T) {
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	group := client.Group.Create().SetName("prod").SaveX(ctx)
	host := client.Asset.Create().SetHostname("pve1").SetGroupID(group.ID).
		SetIPAddrs([]string{"100.121.204.45", "10.1.1.2", "fd7a:115c:a1e0::a37:cc2e"}).SaveX(ctx)
	bare := client.Asset.Create().SetHostname("no-ip").SetGroupID(group.ID).SaveX(ctx)
	now := time.Now()
	// 没登记地址的资产说不清从哪个地址发出，不进图谱
	client.Event.Create().SetTs(now.Add(-3 * time.Minute)).SetClassUID(classNetwork).SetSource("agent").SetAssetID(bare.ID).
		SetRaw(json.RawMessage(`{"connection_info":{"direction":"outbound"},"src_endpoint":{"ip":"0.0.0.0","port":1},"dst_endpoint":{"ip":"198.51.100.8","port":3478}}`)).
		SaveX(ctx)

	// 旧库脏数据清掉，正常的边不动
	mkLink := func(src string, dst string, count int64) {
		client.AssetLink.Create().SetSrcIP(src).SetSrcAssetID(host.ID).SetDstIP(dst).SetDstPort(41641).
			SetProto("udp").SetProcess("tailscaled").SetCount(count).SetFirstSeen(now.Add(-time.Hour)).SetLastSeen(now).SaveX(ctx)
	}
	mkLink("0.0.0.0", "110.42.47.158", 5)
	mkLink("::", "2001:db8::9", 1)
	mkLink("10.1.1.2", "110.42.47.158", 2)
	mkLink("10.1.1.2", "100.100.100.200", 1) // agent 启动探阿里云实例元数据

	// 新事件：旧 agent 报 0.0.0.0，新 agent 省略源地址
	for i, src := range []string{`"ip":"0.0.0.0",`, ``} {
		client.Event.Create().SetTs(now.Add(-time.Duration(2-i) * time.Minute)).SetClassUID(classNetwork).SetSource("agent").
			SetAssetID(host.ID).SetConnTuple("udp::41641>198.51.100.7:3478").
			SetRaw(json.RawMessage(`{"connection_info":{"direction":"outbound","protocol_name":"udp"},"src_endpoint":{` + src +
				`"port":41641},"dst_endpoint":{"ip":"198.51.100.7","port":3478},"process":{"name":"tailscaled"}}`)).
			SaveX(ctx)
	}

	e := &Engine{DB: client, SQL: db, Interval: time.Second}
	e.cursor, e.cursorID = e.loadCursor(ctx)
	for range 2 { // 幂等：第二次没有脏数据
		if err := e.dropNonDependencies(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}

	got := map[string]int64{}
	for _, l := range client.AssetLink.Query().AllX(ctx) {
		got[l.SrcIP+">"+l.DstIP] = l.Count
	}
	want := map[string]int64{
		"10.1.1.2>110.42.47.158": 2,
		"10.1.1.2>198.51.100.7":  2, // 两条新事件记到资产的私网地址上
	}
	if len(got) != len(want) {
		t.Fatalf("依赖边 %v，期望 %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s 计数 %d，期望 %d", k, got[k], n)
		}
	}

	g, err := LoadGroup(ctx, client, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g.Graph(now).Nodes {
		if n.Label == "0.0.0.0" || n.Label == "::" {
			t.Errorf("图谱出现未指定地址节点: %+v", n)
		}
	}
}

// 详情页的连接次数：同一对端多个端口、多个进程的边合计次数，最近时间取最晚；
// 次数只进统计不进事实，涨了也不改指纹
func TestFactsPeerStats(t *testing.T) {
	ctx, client := testdb.New(t)
	group := client.Group.Create().SetName("prod").SaveX(ctx)
	web := client.Asset.Create().SetHostname("web-01").SetIPAddrs([]string{"10.0.0.1"}).SetGroupID(group.ID).SaveX(ctx)
	client.Asset.Create().SetHostname("db-01").SetIPAddrs([]string{"10.0.0.2"}).SetGroupID(group.ID).SaveX(ctx)
	now := time.Now().Truncate(time.Second)
	link := func(src, dst string, port int, count int64, at time.Time) {
		q := client.AssetLink.Create().SetSrcIP(src).SetDstIP(dst).SetDstPort(port).SetProto("tcp").
			SetCount(count).SetFirstSeen(at).SetLastSeen(at)
		if src == "10.0.0.1" {
			q.SetSrcAssetID(web.ID)
		}
		q.ExecX(ctx)
	}
	link("10.0.0.1", "10.0.0.2", 5432, 30, now.Add(-time.Hour))
	link("10.0.0.1", "10.0.0.2", 6379, 12, now)
	link("10.0.0.9", "10.0.0.1", 443, 7, now)

	g, err := LoadGroup(ctx, client, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	f, err := FactsOf(ctx, client, g.World, web)
	if err != nil {
		t.Fatal(err)
	}
	if s := f.OutboundStats["db-01"]; s.Count != 42 || !s.LastSeen.Equal(now) {
		t.Fatalf("出向统计不对: %+v", f.OutboundStats)
	}
	if s := f.InboundStats["10.0.0.9"]; s.Count != 7 {
		t.Fatalf("入向统计不对: %+v", f.InboundStats)
	}
	before := f.fingerprint()
	client.AssetLink.Update().Where(assetlink.DstPortEQ(5432)).AddCount(1000).ExecX(ctx)
	if f, _ = FactsOf(ctx, client, g.World, web); f.fingerprint() != before {
		t.Fatal("连接次数变化不该改变事实指纹")
	}
}

// 详情页不能沿用模型的40条事实限额，否则按连接次数排序会漏掉名称靠后的高频对端。
func TestFactsDetailsRetainPeersBeyondModelLimit(t *testing.T) {
	ctx, client := testdb.New(t)
	host := client.Asset.Create().SetHostname("host").SetIPAddrs([]string{"10.0.0.1"}).SaveX(ctx)
	now := time.Now()
	for i := 100; i <= 100+maxPeers; i++ {
		ip := fmt.Sprintf("10.2.%d.1", i)
		count := int64(i)
		if i == 100+maxPeers {
			count = 100000
		}
		client.AssetLink.Create().SetSrcAssetID(host.ID).SetSrcIP("10.0.0.1").SetDstIP(ip).
			SetDstPort(443).SetProto("tcp").SetCount(count).SetFirstSeen(now).SetLastSeen(now).ExecX(ctx)
		client.AssetLink.Create().SetSrcIP(ip).SetDstIP("10.0.0.1").
			SetDstPort(443).SetProto("tcp").SetCount(count).SetFirstSeen(now).SetLastSeen(now).ExecX(ctx)
	}
	world, err := LoadWorld(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	f, err := FactsOf(ctx, client, world, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Outbound) != maxPeers || len(f.Inbound) != maxPeers ||
		len(f.OutboundDetails) != maxPeers+1 || len(f.InboundDetails) != maxPeers+1 {
		t.Fatalf("模型/详情条数错误: %d/%d %d/%d", len(f.Outbound), len(f.OutboundDetails), len(f.Inbound), len(f.InboundDetails))
	}
	peer := fmt.Sprintf("10.2.%d.1", 100+maxPeers)
	if !slices.Contains(f.OutboundDetails, peer+":443 ← ?") || !slices.Contains(f.InboundDetails, peer+" → 443") ||
		f.OutboundStats[peer].Count != 100000 || f.InboundStats[peer].Count != 100000 {
		t.Fatal("详情丢失最高频对端")
	}
	before := f.fingerprint()
	client.AssetLink.Update().AddCount(1).ExecX(ctx)
	after, err := FactsOf(ctx, client, world, host)
	if err != nil || after.fingerprint() != before {
		t.Fatalf("计数改变事实指纹: %v", err)
	}
}

// 跨组连接：按组看对端只是不露主机名的别组资产；全部组视图里连成主机到主机的边，节点带各自的组
func TestLoadAllJoinsGroups(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	ga := client.Group.Create().SetName("业务").SaveX(ctx)
	gb := client.Group.Create().SetName("基础设施").SaveX(ctx)
	app := client.Asset.Create().SetHostname("app-01").SetGroupID(ga.ID).SetIPAddrs([]string{"10.0.0.1"}).SetLastSeen(now).SaveX(ctx)
	db := client.Asset.Create().SetHostname("db-01").SetGroupID(gb.ID).SetIPAddrs([]string{"10.0.0.2"}).SetLastSeen(now).SaveX(ctx)
	client.AssetLink.Create().SetSrcIP("10.0.0.1").SetSrcAssetID(app.ID).SetDstIP("10.0.0.2").SetDstPort(5432).SetProto("tcp").
		SetProcess("java").SetCount(5).SetFirstSeen(now).SetLastSeen(now).SaveX(ctx)

	byGroup, err := LoadGroup(ctx, client, ga.ID)
	if err != nil {
		t.Fatal(err)
	}
	g := byGroup.Graph(now)
	peer := slices.IndexFunc(g.Nodes, func(n Node) bool { return n.ID == "ip:10.0.0.2" })
	if len(g.Nodes) != 2 || peer < 0 || g.Nodes[peer].Kind != "managed" || g.Nodes[peer].Label != "10.0.0.2" {
		t.Fatalf("按组看别组资产只露地址: %+v", g.Nodes)
	}

	all, err := LoadAll(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	g = all.Graph(now)
	if len(g.Nodes) != 2 || len(g.Edges) != 1 || g.Edges[0].From != app.ID.String() || g.Edges[0].To != db.ID.String() {
		t.Fatalf("全部组视图应连成主机到主机: %+v %+v", g.Nodes, g.Edges)
	}
	for _, n := range g.Nodes {
		want := map[string]uuid.UUID{app.ID.String(): ga.ID, db.ID.String(): gb.ID}[n.ID]
		if n.Kind != "asset" || n.GroupID == nil || *n.GroupID != want {
			t.Fatalf("节点应是带自身组的资产: %+v", n)
		}
	}
}
