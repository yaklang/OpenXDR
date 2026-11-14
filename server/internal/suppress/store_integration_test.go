//go:build integration

package suppress

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/suppression"
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
	store.flush(ctx)

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
	client.Suppression.UpdateOneID(runnerChain.ID).SetStatus("disabled").ExecX(ctx)
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
