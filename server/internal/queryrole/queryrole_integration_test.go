//go:build integration

package queryrole

import (
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/identity"
	"openxdr/server/internal/testdb"
)

// 自动开通的身份只看得到本组资产、读不到基表；重复开通不换密码；删组后账号不复存在。
func TestEnsureIsolatesGroupAndDrops(t *testing.T) {
	ctx, client := testdb.New(t)
	dsn := os.Getenv("INTEGRATION_DATABASE_URL")
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	a := client.Group.Create().SetName("a").SaveX(ctx)
	b := client.Group.Create().SetName("b").SaveX(ctx)
	a1 := client.Asset.Create().SetHostname("a1").SetGroupID(a.ID).SetIPAddrs([]string{"10.9.0.1"}).SaveX(ctx)
	b1 := client.Asset.Create().SetHostname("b1").SetGroupID(b.ID).SetIPAddrs([]string{"10.9.0.2"}).SaveX(ctx)
	// 新视图的两组数据：每张表各给 a、b 一份，只读身份只能看到 a 的
	now := time.Now()
	for _, x := range []struct {
		group uuid.UUID
		asset *ent.Asset
		ip    string
	}{{a.ID, a1, "203.0.113.1"}, {b.ID, b1, "198.51.100.1"}} {
		client.Finding.Create().SetGroupID(x.group).SetAssetID(x.asset.ID).SetKey("k").SetTitle("t").SaveX(ctx)
		client.Memory.Create().SetGroupID(x.group).SetContent("m").SetSource("human").SetAuthor("u").SaveX(ctx)
		client.Suppression.Create().SetRuleID("r").SetAssetID(x.asset.ID).SaveX(ctx)
		client.AssetLink.Create().SetSrcIP("10.0.0.1").SetSrcAssetID(x.asset.ID).SetDstIP(x.ip).SetDstPort(443).SetProto("tcp").
			SetCount(1).SetFirstSeen(now).SetLastSeen(now).SaveX(ctx)
		client.IPInfo.Create().SetIP(x.ip).SetIpdbAsn(64500).SetIpdbOrg("Example Net").SetIpdbCountry("AU").SaveX(ctx)
		client.Report.Create().SetSessionID(uuid.New()).SetGroupID(x.group).SetTitle("r").SetMarkdown("m").SaveX(ctx)
	}
	client.Suppression.Create().SetRuleID("global").SaveX(ctx) // 全局抑制谁的视图里都不该有
	// 身份图：两组各一份本地账号清单与一条登录，由后台过程登记账号、建出身份与链接并关联登录
	if err := identity.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	for _, x := range []*ent.Asset{a1, b1} {
		inventory := client.Event.Create().SetTs(now.Add(-time.Minute)).SetClassUID(5001).SetSource("agent").SetAssetID(x.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
		login := client.Event.Create().SetTs(now).SetClassUID(3002).SetSource("agent").SetAssetID(x.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
		for _, stmt := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO identity_local_snapshots(event_id,asset_id,group_id,state,source,ts) VALUES($1,$2,$3,'observed','etc-passwd',$4)`, []any{inventory.ID, x.ID, *x.GroupID, inventory.Ts}},
			{`INSERT INTO identity_local_accounts(event_id,name,uid,gid,shell) VALUES($1,'alice',1000,1000,'/bin/sh')`, []any{inventory.ID}},
			{`INSERT INTO identity_observations(event_id,asset_id,group_id,account_name,success,state) VALUES($1,$2,$3,'alice',true,'missing_uid')`, []any{login.ID, x.ID, *x.GroupID}},
		} {
			if _, err := db.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := identity.SyncGraph(ctx, db); err != nil {
		t.Fatal(err)
	}
	// 告警连同事件：各组一条；再造一条挂在 a1 上、却指向 b1 事件的告警，事件不属于同一主机就不能带出来
	events := map[uuid.UUID]*ent.Event{}
	for _, x := range []*ent.Asset{a1, b1} {
		events[x.ID] = client.Event.Create().SetTs(now).SetClassUID(1007).SetSource("agent").SetAssetID(x.ID).
			SetRaw(json.RawMessage(`{"process":{"name":"` + x.Hostname + `"}}`)).SaveX(ctx)
		client.Alert.Create().SetTs(now).SetRuleID("r").SetSeverity(3).SetAssetID(x.ID).SetEventID(events[x.ID].ID).SaveX(ctx)
	}
	client.Alert.Create().SetTs(now).SetRuleID("cross").SetSeverity(3).SetAssetID(a1.ID).SetEventID(events[b1.ID].ID).SaveX(ctx)
	// ip_infos 还要带上本组告警里的地址：a 的情报命中与入站对端看得到，b 告警里的看不到
	for _, x := range []struct {
		asset      *ent.Asset
		intel, src string
	}{{a1, "203.0.113.5", "203.0.113.6"}, {b1, "198.51.100.5", "198.51.100.6"}} {
		peer := client.Event.Create().SetTs(now).SetClassUID(4001).SetSource("agent").SetAssetID(x.asset.ID).
			SetRaw(json.RawMessage(`{"src_endpoint":{"ip":"` + x.src + `"},"dst_endpoint":{"ip":"10.0.0.1"}}`)).SaveX(ctx)
		client.Alert.Create().SetTs(now).SetRuleID("intel:ip:" + x.intel).SetSeverity(3).SetAssetID(x.asset.ID).SaveX(ctx)
		client.Alert.Create().SetTs(now).SetRuleID("ssh-brute").SetSeverity(3).SetAssetID(x.asset.ID).SetEventID(peer.ID).SaveX(ctx)
		client.IPInfo.Create().SetIP(x.intel).SaveX(ctx)
		client.IPInfo.Create().SetIP(x.src).SaveX(ctx)
	}

	static := uuid.New()
	p := &Provisioner{DB: db, Client: client, BaseDSN: dsn, Static: map[uuid.UUID]string{static: "postgres://manual"}}
	if p.URL(ctx, a.ID) != "" {
		t.Fatal("未开通时应返回空")
	}
	if err := p.Ensure(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	first := p.URL(ctx, a.ID)
	if err := p.Ensure(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if again := p.URL(ctx, a.ID); first == "" || again != first {
		t.Fatalf("重复开通不应换密码：%q → %q", first, again)
	}
	if p.URL(ctx, static) != "postgres://manual" {
		t.Error("手工配置的身份应优先")
	}

	ro, err := sql.Open("pgx", first)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close() })
	var host string
	var n int
	if err := ro.QueryRowContext(ctx, `SELECT count(*), min(hostname) FROM assets`).Scan(&n, &host); err != nil {
		t.Fatal(err)
	}
	if n != 1 || host != "a1" {
		t.Errorf("只应看到本组资产 a1，实际 %d 条 %q", n, host)
	}
	for view, want := range map[string]string{
		"findings": "1", "memories": "1", "suppressions": "1", "asset_links": "1", "reports": "1",
		"ip_infos": "203.0.113.1,203.0.113.5,203.0.113.6",
	} {
		var got string
		q := `SELECT count(*)::text FROM ` + view
		if view == "ip_infos" {
			// 离线库字段也在视图里
			q = `SELECT string_agg(ip, ',' ORDER BY ip) FROM ip_infos WHERE ipdb_at IS NULL AND ipdb_country IN ('', 'AU')`
		}
		if err := ro.QueryRowContext(ctx, q).Scan(&got); err != nil || got != want {
			t.Errorf("%s 只应看到本组的数据：得到 %q，%v", view, got, err)
		}
	}
	var linked int
	if err := ro.QueryRowContext(ctx, `SELECT count(*) FROM identity_accounts a JOIN identities i ON i.id = a.identity_id
  JOIN identity_links l ON l.account_id = a.id JOIN identity_linux_logins g ON g.account_id = a.id WHERE a.asset_id = $1`, a1.ID).Scan(&linked); err != nil || linked != 1 {
		t.Errorf("身份视图应能串起本组账号、身份、链接与登录：%d %v", linked, err)
	}
	for _, view := range []string{"identity_accounts", "identities", "identity_links", "identity_linux_logins"} {
		if err := ro.QueryRowContext(ctx, `SELECT count(*) FROM `+view).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s 只应看到本组的数据：%d %v", view, n, err)
		}
	}
	var proc string
	if err := ro.QueryRowContext(ctx, `SELECT count(*), min(raw->'process'->>'name') FROM alert_events WHERE rule_id IN ('r', 'cross')`).Scan(&n, &proc); err != nil || n != 1 || proc != "a1" {
		t.Errorf("alert_events 只应带出本组主机自己的事件：%d 条 %q，%v", n, proc, err)
	}
	// 别组纳管的地址看得到、标为非本组，但拿不到别组主机名：AI 才不会把它报成未纳管
	var managed string
	if err := ro.QueryRowContext(ctx, `SELECT string_agg(ip || '=' || in_group, ',' ORDER BY ip) FROM managed_addresses`).Scan(&managed); err != nil ||
		managed != "10.9.0.1=true,10.9.0.2=false" {
		t.Fatalf("managed_addresses 应列出两组地址并只标本组: %q %v", managed, err)
	}
	if err := ro.QueryRowContext(ctx, `SELECT count(*) FROM pg_attribute WHERE attrelid = 'managed_addresses'::regclass AND attnum > 0`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("managed_addresses 只该有 ip 与 in_group 两列: %d %v", n, err)
	}
	if err := ro.QueryRowContext(ctx, `SELECT count(*) FROM public.assets`).Scan(&n); err == nil {
		t.Error("不应能读业务基表")
	}
	var readOnly string
	if err := ro.QueryRowContext(ctx, `SHOW default_transaction_read_only`).Scan(&readOnly); err != nil || readOnly != "on" {
		t.Errorf("应默认只读，实际 %q %v", readOnly, err)
	}
	ro.Close()

	if err := p.Drop(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.Drop(ctx, a.ID); err != nil {
		t.Fatalf("重复回收应无害：%v", err)
	}
	gone, _ := sql.Open("pgx", first)
	defer gone.Close()
	if err := gone.PingContext(ctx); err == nil {
		t.Error("回收后不应还能登录")
	}
}

// 删遗留 dry_run 列：旧版组视图挡着时报错不删，视图重建后删干净；重复执行无害，组视图照常可查。
func TestDropDryRunAfterViewRebuild(t *testing.T) {
	ctx, client := testdb.New(t)
	dsn := os.Getenv("INTEGRATION_DATABASE_URL")
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	g := client.Group.Create().SetName("g").SaveX(ctx)
	a := client.Asset.Create().SetHostname("g1").SetGroupID(g.ID).SaveX(ctx)
	if err := identity.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	p := &Provisioner{DB: db, Client: client, BaseDSN: dsn}
	t.Cleanup(func() { p.Drop(ctx, g.ID) })
	if err := p.Ensure(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	// 模拟升级前：四张表带 dry_run 列，组视图还是旧版定义
	schema, _ := names(g.ID)
	for _, stmt := range []string{
		`ALTER TABLE commands ADD COLUMN IF NOT EXISTS dry_run boolean NOT NULL DEFAULT true`,
		`ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS dry_run boolean NOT NULL DEFAULT true`,
		`ALTER TABLE approvals ADD COLUMN IF NOT EXISTS dry_run boolean NOT NULL DEFAULT true`,
		`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS dry_run boolean NOT NULL DEFAULT true`,
		`DROP VIEW ` + schema + `.commands`,
		`CREATE VIEW ` + schema + `.commands AS SELECT id, status, dry_run FROM public.commands`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := DropDryRun(ctx, db); err == nil {
		t.Fatal("旧版视图还引用 commands.dry_run 时应报错")
	}

	if err := p.Ensure(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := DropDryRun(ctx, db); err != nil {
			t.Fatalf("视图重建后应能删列且可重复执行：%v", err)
		}
	}
	var left int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
  WHERE table_schema = current_schema() AND column_name = 'dry_run'`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("dry_run 列应全部删除，剩 %d %v", left, err)
	}

	client.Command.Create().SetKind("exec").SetAssetID(a.ID).SetIssuedBy("admin").SaveX(ctx)
	ro, err := sql.Open("pgx", p.URL(ctx, g.ID))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close() })
	var n int
	if err := ro.QueryRowContext(ctx, `SELECT count(*) FROM commands`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("删列后组视图应照常可查：%d %v", n, err)
	}
}

// events 是分区表时组视图定义不变：带 ts 范围的查询穿过 security_barrier 视图仍能裁剪分区
// （时间比较运算符是 leakproof 的，条件可以下推），alert_events 按事件主键回查照常可用。
func TestGroupViewsPrunePartitions(t *testing.T) {
	ctx, client := testdb.New(t)
	dsn := os.Getenv("INTEGRATION_DATABASE_URL")
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := identity.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	g := client.Group.Create().SetName("g").SaveX(ctx)
	a := client.Asset.Create().SetHostname("g1").SetGroupID(g.ID).SaveX(ctx)
	today := eventpart.Today()
	for i := range 3 {
		e := client.Event.Create().SetTs(today.AddDate(0, 0, i).Add(time.Hour)).SetClassUID(1007).SetSource("agent").SetAssetID(a.ID).
			SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
		client.Alert.Create().SetTs(e.Ts).SetRuleID("r").SetSeverity(3).SetAssetID(a.ID).SetEventID(e.ID).SaveX(ctx)
	}
	p := &Provisioner{DB: db, Client: client, BaseDSN: dsn}
	t.Cleanup(func() { p.Drop(ctx, g.ID) })
	if err := p.Ensure(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	ro, err := sql.Open("pgx", p.URL(ctx, g.ID))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close() })
	from, to := today.AddDate(0, 0, 1), today.AddDate(0, 0, 2)
	var plan string
	if err := ro.QueryRowContext(ctx, `EXPLAIN (FORMAT JSON) SELECT count(*) FROM events WHERE ts >= $1 AND ts < $2`, from, to).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, eventpart.DailyName(from)) || strings.Contains(plan, eventpart.DailyName(today)) || strings.Contains(plan, eventpart.DefaultName) {
		t.Fatalf("组视图上带 ts 范围的查询应只扫 %s：%s", eventpart.DailyName(from), plan)
	}
	var n int
	if err := ro.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE ts >= $1 AND ts < $2`, from, to).Scan(&n); err != nil || n != 1 {
		t.Fatalf("按天计数应为 1：%d %v", n, err)
	}
	if err := ro.QueryRowContext(ctx, `SELECT count(*) FROM alert_events`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("alert_events 应带出 3 条告警事件：%d %v", n, err)
	}
}
