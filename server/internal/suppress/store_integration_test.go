//go:build integration

package suppress

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/suppression"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
)

// Reload 从库重建索引 → Suppressed 命中累加 → flush 把计数回写库。
// 验证抑制规则从"建库"到"界面看到压掉多少"的整条链路。
func TestStoreReloadAndFlush(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()

	// 过期规则：不压制
	_, err := client.Suppression.Create().
		SetRuleID("r-stale").SetExpiresAt(now.Add(-time.Hour)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 全局规则（不限资产）
	global, err := client.Suppression.Create().
		SetRuleID("r-global").SetExpiresAt(now.Add(time.Hour)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 限单资产规则
	assetID := uuid.New()
	scoped, err := client.Suppression.Create().
		SetRuleID("r-scoped").SetAssetID(assetID).SetExpiresAt(now.Add(time.Hour)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	store := New(client, time.Hour)
	store.Reload(ctx)

	// 过期规则不压制
	if store.Suppressed("r-stale", nil, nil, now) {
		t.Error("过期抑制规则不应压制")
	}
	// 全局规则压制任意资产
	if !store.Suppressed("r-global", nil, nil, now) {
		t.Error("全局规则应压制空资产")
	}
	// 限定资产的规则：匹配资产压制，其他资产与空资产不压制
	if !store.Suppressed("r-scoped", &assetID, nil, now) {
		t.Error("限定资产规则应压制该资产")
	}
	other := uuid.New()
	if store.Suppressed("r-scoped", &other, nil, now) {
		t.Error("限定资产规则不应压制其他资产")
	}
	if store.Suppressed("r-scoped", nil, nil, now) {
		t.Error("限定资产规则不应压制空资产")
	}
	// 未登记的规则不压制
	if store.Suppressed("r-unknown", nil, nil, now) {
		t.Error("未登记规则不应压制")
	}

	// 命中计数已累计，flush 落库
	store.Flush(ctx)

	g, err := client.Suppression.Get(ctx, global.ID)
	if err != nil {
		t.Fatal(err)
	}
	if g.MatchedCount != 1 {
		t.Errorf("全局规则 matched_count = %d, want 1", g.MatchedCount)
	}
	if g.LastMatchedAt == nil {
		t.Error("命中后应记录 last_matched_at")
	}

	sc, err := client.Suppression.Get(ctx, scoped.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sc.MatchedCount != 1 {
		t.Errorf("限定资产规则 matched_count = %d, want 1", sc.MatchedCount)
	}
}

// TestBuiltinSyncLineageAndDisablePersistence 验证内置良性链同步、多跳血缘数据库回溯（含顶层守护进程早于热表保留期靠内嵌父进程兜底）、
// 高危拦截、命中计数累计，以及管理员停用状态在重启同步后保留。
func TestBuiltinSyncLineageAndDisablePersistence(t *testing.T) {
	ctx, client := testdb.New(t)
	engine, _ := sigma.LoadDirReport("../../../rules")

	n, err := SyncBuiltins(ctx, client, engine, "../../../rules/benign-chains")
	if err != nil || n < 6 {
		t.Fatalf("SyncBuiltins 失败: n=%d err=%v", n, err)
	}

	store := New(client, time.Hour)
	store.SetRules(engine)
	store.Reload(ctx)
	if !store.NeedsLineage() {
		t.Fatal("加载内置良性链后 NeedsLineage 应为 true")
	}

	host := client.Asset.Create().SetHostname("github-runner-linchen").SetOs("linux").SaveX(ctx)
	now := time.Now().UTC().Truncate(time.Second)

	// 构造真实多跳血缘：Runner.Listener 早于保留期未落 1007 行，靠 Runner.Worker 事件内嵌的 parent_process 补齐；
	// Runner.Worker (1007) → bash -e .../_work/_temp/step.sh (1007) → cargo test (当前事件)
	listenerGUID := uuid.New()
	workerGUID := uuid.New()
	stepGUID := uuid.New()
	cargoGUID := uuid.New()

	client.Event.Create().
		SetTs(now.Add(-2 * time.Minute)).
		SetClassUID(1007).
		SetSource("agent").
		SetAssetID(host.ID).
		SetProcessGUID(workerGUID).
		SetParentProcessGUID(listenerGUID).
		SetRaw(json.RawMessage(`{"process":{"name":"Runner.Worker","file":{"path":"/opt/actions-runner/bin/Runner.Worker"},"cmd_line":"/opt/actions-runner/bin/Runner.Worker spawnclient 10 11","parent_process":{"name":"Runner.Listener","file":{"path":"/opt/actions-runner/bin/Runner.Listener"},"cmd_line":"/opt/actions-runner/bin/Runner.Listener run"}}}`)).
		SaveX(ctx)

	client.Event.Create().
		SetTs(now.Add(-time.Minute)).
		SetClassUID(1007).
		SetSource("agent").
		SetAssetID(host.ID).
		SetProcessGUID(stepGUID).
		SetParentProcessGUID(workerGUID).
		SetRaw(json.RawMessage(`{"process":{"name":"bash","file":{"path":"/usr/bin/bash"},"cmd_line":"/usr/bin/bash -e /opt/actions-runner/_work/_temp/88ab12cd.sh","parent_process":{"name":"Runner.Worker","file":{"path":"/opt/actions-runner/bin/Runner.Worker"},"cmd_line":"/opt/actions-runner/bin/Runner.Worker spawnclient 10 11"}}}`)).
		SaveX(ctx)

	var cargoRaw map[string]any
	_ = json.Unmarshal([]byte(`{"process":{"name":"cargo","file":{"path":"/root/.cargo/bin/cargo"},"cmd_line":"/root/.cargo/bin/cargo test --locked","parent_process":{"name":"bash","file":{"path":"/usr/bin/bash"},"cmd_line":"/usr/bin/bash -e /opt/actions-runner/_work/_temp/88ab12cd.sh"}}}`), &cargoRaw)
	_ = cargoGUID

	lineage := ResolveLineageEnt(ctx, client, &host.ID, &stepGUID, now, cargoRaw)
	if len(lineage) != 3 {
		t.Fatalf("应还原 3 跳血缘（bash + Runner.Worker + 内嵌 Runner.Listener），实际 %d: %+v", len(lineage), lineage)
	}
	if !store.SuppressedWithLineage(sigma.RuleNewProcess, &host.ID, cargoRaw, lineage, now) {
		t.Fatal("真实 Runner 多跳血缘下的 cargo 首次进程应被内置链压制")
	}
	// 同一进程若命中威胁情报或高危规则，绝不能被内置链放行
	if store.SuppressedWithLineage("intel:ip:198.51.100.9", &host.ID, cargoRaw, lineage, now) {
		t.Fatal("威胁情报命中绝不能被内置良性链压制")
	}
	if store.SuppressedWithLineage("b03fc985-9d70-4dd1-a4a1-0bcaf4019a74", &host.ID, cargoRaw, lineage, now) {
		t.Fatal("T1611 高危逃逸规则绝不能被内置良性链压制")
	}
	// 缺少祖先链时（仿冒单层 bash -e .../_work/_temp/*.sh）不能被压制
	if store.SuppressedWithLineage(sigma.RuleNewProcess, &host.ID, cargoRaw, DefaultLineage(cargoRaw), now) {
		t.Fatal("缺少 Runner.Worker/Runner.Listener 祖先的仿冒进程不应被压制")
	}

	store.Flush(ctx)
	runnerChain := client.Suppression.Query().Where(suppression.BuiltinKeyEQ("github-actions-runner-build")).OnlyX(ctx)
	if runnerChain.MatchedCount != 1 {
		t.Fatalf("内置良性链应累计 matched_count=1，实际 %d", runnerChain.MatchedCount)
	}

	// 管理员停用该内置链后重载：不再压制；再次 SyncBuiltins（模拟发版重启）必须保留 disabled 状态与 matched_count
	// 与控制台启停接口一致：人工停用会记下 reviewed_by
	client.Suppression.UpdateOneID(runnerChain.ID).SetStatus("disabled").SetReviewedBy("admin").SetReviewedAt(time.Now()).ExecX(ctx)
	if _, err := SyncBuiltins(ctx, client, engine, "../../../rules/benign-chains"); err != nil {
		t.Fatalf("二次 SyncBuiltins 失败: %v", err)
	}
	afterSync := client.Suppression.GetX(ctx, runnerChain.ID)
	if afterSync.Status != "disabled" || afterSync.MatchedCount != 1 {
		t.Fatalf("二次同步应保留 disabled 状态与命中计数: %+v", afterSync)
	}
	store.Reload(ctx)
	if store.SuppressedWithLineage(sigma.RuleNewProcess, &host.ID, cargoRaw, lineage, now.Add(time.Second)) {
		t.Fatal("已停用的内置良性链不应再生效")
	}
}

// TestLineageLookbackPrunesOldPartitionsAndFallsBack 验证血缘回溯带 ts >= ts-LineageLookback 下限：
// 祖先启动事件早于窗口时，PostgreSQL 分区裁剪不扫旧日分区，ResolveLineage 与 ResolveLineageEnt 均走内嵌 parent_process 兜底。
func TestLineageLookbackPrunesOldPartitionsAndFallsBack(t *testing.T) {
	ctx, client := testdb.New(t)
	sqlDB, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()

	// 固定在一个别的测试不会碰的远期月份：测试库是各包共用的，eventarchive 的测试会留下当月的整月归档分区，
	// 按当前时间预建日分区会与之重叠
	now := time.Date(2031, 3, 20, 12, 0, 0, 0, time.UTC)
	if _, err := eventpart.EnsureDays(ctx, sqlDB, "events", now.Add(-6*24*time.Hour), 7); err != nil {
		t.Fatalf("预建日分区失败: %v", err)
	}

	engine, _ := sigma.LoadDirReport("../../../rules")
	if _, err := SyncBuiltins(ctx, client, engine, "../../../rules/benign-chains"); err != nil {
		t.Fatalf("SyncBuiltins 失败: %v", err)
	}
	store := New(client, time.Hour)
	store.SetRules(engine)
	store.Reload(ctx)

	host := client.Asset.Create().SetHostname("runner-part-test").SetOs("linux").SaveX(ctx)
	oldTs := now.Add(-LineageLookback - 48*time.Hour) // 早于 3 天窗口（落在 5 天前日分区）
	oldPart := eventpart.DailyName(oldTs)

	listenerGUID := uuid.New()
	workerGUID := uuid.New()
	stepGUID := uuid.New()

	// 在 5 天前分区写入 Runner.Listener 的 1007 启动事件（带 /lib/systemd/systemd 父进程标记）：
	// 若查询未加 ts 下限，会读出该行并拼出第 4 跳 /lib/systemd/systemd。
	client.Event.Create().
		SetTs(oldTs).
		SetClassUID(1007).
		SetSource("agent").
		SetAssetID(host.ID).
		SetProcessGUID(listenerGUID).
		SetRaw(json.RawMessage(`{"process":{"name":"Runner.Listener","file":{"path":"/opt/actions-runner/bin/Runner.Listener"},"cmd_line":"/opt/actions-runner/bin/Runner.Listener run","parent_process":{"name":"systemd","file":{"path":"/lib/systemd/systemd"},"cmd_line":"/lib/systemd/systemd --system"}}}`)).
		SaveX(ctx)

	client.Event.Create().
		SetTs(now.Add(-2 * time.Minute)).
		SetClassUID(1007).
		SetSource("agent").
		SetAssetID(host.ID).
		SetProcessGUID(workerGUID).
		SetParentProcessGUID(listenerGUID).
		SetRaw(json.RawMessage(`{"process":{"name":"Runner.Worker","file":{"path":"/opt/actions-runner/bin/Runner.Worker"},"cmd_line":"/opt/actions-runner/bin/Runner.Worker spawnclient 10 11","parent_process":{"name":"Runner.Listener","file":{"path":"/opt/actions-runner/bin/Runner.Listener"},"cmd_line":"/opt/actions-runner/bin/Runner.Listener run"}}}`)).
		SaveX(ctx)

	client.Event.Create().
		SetTs(now.Add(-time.Minute)).
		SetClassUID(1007).
		SetSource("agent").
		SetAssetID(host.ID).
		SetProcessGUID(stepGUID).
		SetParentProcessGUID(workerGUID).
		SetRaw(json.RawMessage(`{"process":{"name":"bash","file":{"path":"/usr/bin/bash"},"cmd_line":"/usr/bin/bash -e /opt/actions-runner/_work/_temp/part.sh","parent_process":{"name":"Runner.Worker","file":{"path":"/opt/actions-runner/bin/Runner.Worker"},"cmd_line":"/opt/actions-runner/bin/Runner.Worker spawnclient 10 11"}}}`)).
		SaveX(ctx)

	// 1. 验证真实执行计划对早于窗口的日分区做了分区裁剪（不执行旧分区扫描）
	var planJSON []byte
	if err := sqlDB.QueryRowContext(ctx, `EXPLAIN (ANALYZE, FORMAT JSON)
SELECT parent_process_guid, raw FROM events
WHERE asset_id = $1 AND process_guid = $2 AND class_uid = 1007 AND ts >= $4 AND ts <= $3
ORDER BY ts ASC LIMIT 1`, host.ID, listenerGUID, now, now.Add(-LineageLookback)).Scan(&planJSON); err != nil {
		t.Fatalf("EXPLAIN 失败: %v", err)
	}
	var plans []map[string]any
	if err := json.Unmarshal(planJSON, &plans); err != nil || len(plans) == 0 {
		t.Fatalf("解析 EXPLAIN JSON 失败: %v", err)
	}
	var checkPruned func(map[string]any)
	checkPruned = func(node map[string]any) {
		if rel, _ := node["Relation Name"].(string); rel == oldPart {
			if never, _ := node["Never Executed"].(bool); !never {
				t.Fatalf("早于窗口的旧日分区 %s 未被裁剪，仍被实际扫描: %s", oldPart, string(planJSON))
			}
		}
		if kids, ok := node["Plans"].([]any); ok {
			for _, k := range kids {
				if m, ok := k.(map[string]any); ok {
					checkPruned(m)
				}
			}
		}
	}
	if root, ok := plans[0]["Plan"].(map[string]any); ok {
		checkPruned(root)
	}

	// 2. 验证 SQL 与 Ent 两条血缘路径均不读 5 天前分区行，而靠最顶层已知事件（Runner.Worker）的 parent_process 兜底第 3 跳
	var cargoRaw map[string]any
	_ = json.Unmarshal([]byte(`{"process":{"name":"cargo","file":{"path":"/root/.cargo/bin/cargo"},"cmd_line":"/root/.cargo/bin/cargo build","parent_process":{"name":"bash","file":{"path":"/usr/bin/bash"},"cmd_line":"/usr/bin/bash -e /opt/actions-runner/_work/_temp/part.sh"}}}`), &cargoRaw)

	for name, got := range map[string][]map[string]any{
		"sql": ResolveLineage(ctx, sqlDB, &host.ID, &stepGUID, now, cargoRaw),
		"ent": ResolveLineageEnt(ctx, client, &host.ID, &stepGUID, now, cargoRaw),
	} {
		if len(got) != 3 {
			t.Fatalf("[%s] 超出窗口的祖先不应从旧分区读出第 4 跳，期望 3 跳实际 %d: %+v", name, len(got), got)
		}
		fileMap, _ := got[2]["file"].(map[string]any)
		if path, _ := fileMap["path"].(string); path != "/opt/actions-runner/bin/Runner.Listener" {
			t.Fatalf("[%s] 第 3 跳应由 Runner.Worker 内嵌 parent_process 兜底还原 Runner.Listener，实际 %+v", name, got[2])
		}
		if !store.SuppressedWithLineage(sigma.RuleNewProcess, &host.ID, cargoRaw, got, now) {
			t.Fatalf("[%s] 兜底还原后仍应命中 github-actions-runner-build 内置良性链", name)
		}
	}

	// 3. 验证直接父进程本身早于窗口时，不读旧分区，直接退回当前事件内嵌的 DefaultLineage
	oldParentGUID := uuid.New()
	client.Event.Create().
		SetTs(oldTs).
		SetClassUID(1007).
		SetSource("agent").
		SetAssetID(host.ID).
		SetProcessGUID(oldParentGUID).
		SetRaw(json.RawMessage(`{"process":{"name":"node","file":{"path":"/usr/local/bin/node"},"cmd_line":"node server.js","parent_process":{"name":"ancient","file":{"path":"/sbin/ancient-init"},"cmd_line":"/sbin/ancient-init"}}}`)).
		SaveX(ctx)

	var unameRaw map[string]any
	_ = json.Unmarshal([]byte(`{"process":{"name":"uname","file":{"path":"/bin/uname"},"cmd_line":"uname -m","parent_process":{"name":"node","file":{"path":"/usr/local/bin/node"},"cmd_line":"node /app/node_modules/vite/bin/vite.js build"}}}`), &unameRaw)

	for name, got := range map[string][]map[string]any{
		"sql": ResolveLineage(ctx, sqlDB, &host.ID, &oldParentGUID, now, unameRaw),
		"ent": ResolveLineageEnt(ctx, client, &host.ID, &oldParentGUID, now, unameRaw),
	} {
		if len(got) != 1 {
			t.Fatalf("[%s] 直接父进程早于窗口时应退回单跳内嵌 parent_process，实际 %d: %+v", name, len(got), got)
		}
	}
}

// 滚动发布或回滚时，旧版本节点会把它没见过的新链当成「已从仓库移除」自动停用；
// 新版本再同步时要把这类自动停用的链重新启用，人工停用的保持不动
func TestSyncBuiltinsReenablesAutoDisabledChains(t *testing.T) {
	ctx, client := testdb.New(t)
	engine, _ := sigma.LoadDirReport("../../../rules")
	full := "../../../rules/benign-chains"
	if _, err := SyncBuiltins(ctx, client, engine, full); err != nil {
		t.Fatal(err)
	}
	// 人工停用另一条链
	manual := client.Suppression.Query().Where(suppression.BuiltinKeyEQ("kafka-tool-uname")).OnlyX(ctx)
	client.Suppression.UpdateOneID(manual.ID).SetStatus("disabled").SetReviewedBy("admin").SetReviewedAt(time.Now()).ExecX(ctx)

	// 旧版本的链目录里没有这条新链
	old := t.TempDir()
	entries, err := os.ReadDir(full)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yml") || e.Name() == "apt-dpkg-maintainer-scripts.yml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(full, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(old, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SyncBuiltins(ctx, client, engine, old); err != nil {
		t.Fatal(err)
	}
	chain := client.Suppression.Query().Where(suppression.BuiltinKeyEQ("apt-dpkg-maintainer-scripts")).OnlyX(ctx)
	if chain.Status != "disabled" || chain.ReviewedBy != nil {
		t.Fatalf("旧版本应把没见过的链自动停用且不留人工记录：%+v", chain)
	}

	if _, err := SyncBuiltins(ctx, client, engine, full); err != nil {
		t.Fatal(err)
	}
	if got := client.Suppression.GetX(ctx, chain.ID); got.Status != "active" {
		t.Fatalf("新版本同步应重新启用被自动停用的链：%+v", got)
	}
	if got := client.Suppression.GetX(ctx, manual.ID); got.Status != "disabled" {
		t.Fatalf("人工停用的链不应被同步启用：%+v", got)
	}
}
