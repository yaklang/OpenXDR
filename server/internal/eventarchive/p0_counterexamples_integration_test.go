//go:build integration

// P0 反例集成测试：把 COLD_ARCHIVE_EVOLUTION.SCRATCH.md 问题登记册 #2 的两条数据丢失路径
// （5.2 节 T01/T02）固定成确定性用例。P0 阶段断言的是当时实现（有缺陷）的行为；
// P3 实施后本文件的两条反例已按新契约翻转（断言修复后的行为），fixture 与注入方式不变，
// 供后续回归对照。
//
// 两条反例共用同一个事实基础：旧实现的删除门禁是「冷块条数 == 计划移出条数」的计数校验，
// 且发生在重写事务之外（先 Plan/coldCount，后 RewriteDay 加锁重建分区）。P3 起删除依据
// 完全由重写事务内的集合校验承担（swapVerify），保留口径自带「不在 locator → 保留」。
package eventarchive

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// T01（串行抵消反例，已翻转，HEAD=本次改动）：当日未 pin 的 A、B → shadow + verify →
// 给 A 建 alert 引用（待删集 −1）→ 再插入同日未 pin 的 C（+1）。计数门禁仍然相等
// （冷 2 == 待移出 2），P0 实测旧实现把没有冷副本的 C 一并删除——静默丢失。
//
// P3 翻转：Swap 的保留口径带「不在本 run 的 locator → 保留」，swapVerify 在锁内重读后核对
// keep == H − D：C 没有冷副本，不进删除集，留在热表；B 有冷副本照常移出，A 被钉住留热。
// 计数抵消不再能造成无副本删除——「C 留热」正是底稿 §1.2 与 §P3 验收
// （「串行计数抵消反例中，新行 C 留热」）对新契约的要求。
//
// 注：任务底稿曾写「T01 断言 Swap 拒绝执行」，但 T01 与 T02 在重写事务开始那一刻的
// 数据库终态相同（C 都是 shadow 之后到达、无冷副本的口径内行），拒绝前者而放行后者
// 在同一份删除依据下不可兼得；以底稿 §1.2/§P3 验收与 T02 条目的「C 留热、其余移出」为准。
func TestP0T01SerialCancellationKeepsUncoveredRowHot(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)

	runID := p0VerifiedRun(t, ctx, db, day, day)

	// 对拍通过之后再动 events：钉住 A（待删集 −1），插入同日同口径的 C（+1）
	p0Pin(t, ctx, client, day.Add(10*time.Minute), a)
	c := p0Event(t, ctx, client, day.Add(30*time.Minute), 4001, "agent", `{"mark":"C","conn":{"dst":"10.0.0.7:443"}}`)

	p, err := Plan(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if p.Archived != 2 || p.KeepPinned != 1 {
		t.Fatalf("计划应是 待移出=2（B、C）、钉住=1（A），实际 %+v", p)
	}
	cold := p0ColdDayCount(t, ctx, db, runID, day)
	if cold != 2 || cold != p.Archived {
		t.Fatalf("反例前提：计数门禁必须仍然相等（冷块 %d 条 == 计划移出 %d 条），否则说明 fixture 漂了", cold, p.Archived)
	}

	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("P3：B 有冷副本移出、A 钉住留热、C 无冷副本留热，Swap 应照常执行，实际 %v", err)
	}

	// A 被钉住，留在热表
	if !p0HotExists(t, ctx, db, a) {
		t.Fatal("被钉住的 A 应留在热表")
	}
	// B 被移出热表，冷层有副本：这是预期中的正常行为
	if p0HotExists(t, ctx, db, b) {
		t.Fatal("B 应已移出热表")
	}
	if _, found, err := Locate(ctx, db, b); err != nil || !found {
		t.Fatalf("B 的冷副本必须可定位：found=%v err=%v", found, err)
	}
	// P3 翻转：C 留在热表——计数抵消不再能把没有冷副本的行带进删除集
	if !p0HotExists(t, ctx, db, c) {
		t.Fatal("P3：C 没有冷副本，必须留在热表（这正是被翻转的缺陷）")
	}
	_, found, err := Locate(ctx, db, c)
	if err != nil {
		t.Fatalf("定位 C 不该报错（报错就无法断言确定不存在）: %v", err)
	}
	if found {
		t.Fatal("C 从未进冷块，冷层不应命中")
	}
	if got := p0PartitionRows(t, ctx, db, day); got != 2 {
		t.Fatalf("切换后日分区应剩 A、C 两行，实际 %d 行", got)
	}
	// 逐日记录：kept=2（A 钉住 + C 无冷副本）、dropped=1（B），与分区实际状态一致
	days := p3DayRecords(t, ctx, db, runID)
	rec, ok := days[day.Format(time.DateOnly)]
	if !ok {
		t.Fatalf("detail.days 应记录 %s：%v", day.Format(time.DateOnly), days)
	}
	if rec.Kept != 2 || rec.Dropped != 1 || !rec.RunDayVerified {
		t.Fatalf("detail.days.%s 应是 kept=2 dropped=1 run_day_verified=true，实际 %+v",
			day.Format(time.DateOnly), rec)
	}
}

// T02（检查后、加锁前的 TOCTOU 反例，已翻转，HEAD=本次改动；确定性同步、无 sleep）：
// goroutine 里跑 Swap，swapTestHook 在「预检已完成、重写事务未开始」的确切位置
// （stage == "prechecks_done"）回调；测试主协程收到信号后，经一条**独立连接**向同日写入
// 未 pin 的口径内事件 C，再放行 Swap。P0 实测旧实现照常重建分区并把没有冷副本的 C
// 一并删除，只能事后报「结果与计划不符」。
//
// P3 翻转：C 在加锁前提交，锁内重读时属于 H；它不在本 run 的 locator → 不进删除集 D →
// 保留。Swap 成功执行：A/B 正常移出（有冷副本），C 留热，TOCTOU 窗口不再有删除依据，
// detail.days 记录事务内实测 kept=1 / dropped=2。
func TestP0T02InsertBetweenPrecheckAndLockKeepsRowHot(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)

	runID := p0VerifiedRun(t, ctx, db, day, day)

	// 独立连接：与 Swap 走的连接池完全分开，模拟另一路并发写入方（接入进程）
	inserter, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inserter.Close() })

	// 双通道屏障：钩子在 Swap 协程里触发（预检已过）→ 通知主协程 → 主协程写入 C 并放行。
	// Swap 协程阻塞在钩子里时，RewriteDayGuarded 的事务还没开，日分区上没有任何锁，
	// 独立连接的 INSERT 不需要等待，时序完全确定。事务内的阶段（after_copy 等）照常放行。
	prechecksDone := make(chan struct{})
	release := make(chan struct{})
	swapTestHook = func(stage string, tx *sql.Tx) error {
		switch stage {
		case "prechecks_done":
			close(prechecksDone)
			<-release
		case "after_copy", "after_indexes", "before_replace", "after_record":
			// 本用例只停在事务外的窗口，事务内阶段直接放行
		default:
			t.Errorf("未知的钩子阶段 %q", stage)
		}
		return nil
	}
	t.Cleanup(func() { swapTestHook = nil })

	type swapOutcome struct {
		plan SwapPlan
		err  error
	}
	done := make(chan swapOutcome, 1)
	go func() {
		plan, err := Swap(ctx, db, runID, day)
		done <- swapOutcome{plan: plan, err: err}
	}()

	select {
	case <-prechecksDone:
	case <-time.After(time.Minute):
		t.Fatal("钩子没有在预检完成后触发：Swap 在前置检查阶段就失败了，反例前提不成立")
	}

	c := uuid.New()
	if _, err := inserter.ExecContext(ctx, `INSERT INTO events (id, ts, class_uid, source, raw)
 VALUES ($1, $2, 4001, 'agent', $3::jsonb)`,
		c, day.Add(45*time.Minute), `{"mark":"C-race","conn":{"dst":"10.0.0.8:443"}}`); err != nil {
		t.Fatalf("在竞态窗口内写入 C: %v", err)
	}
	close(release)

	var outcome swapOutcome
	select {
	case outcome = <-done:
	case <-time.After(time.Minute):
		t.Fatal("Swap 在放行后没有返回")
	}

	if outcome.err != nil {
		t.Fatalf("P3：窗口内写入的 C 留热，A/B 照常移出，Swap 应成功，实际 %v", outcome.err)
	}
	if outcome.plan.Kept != 1 || outcome.plan.Dropped != 2 {
		t.Fatalf("事务内实测应是 kept=1（C）/ dropped=2（A/B），实际 %+v", outcome.plan)
	}
	for _, id := range []uuid.UUID{a, b} {
		if p0HotExists(t, ctx, db, id) {
			t.Fatalf("事件 %s 应已随分区重建移出热表", id)
		}
		if _, found, err := Locate(ctx, db, id); err != nil || !found {
			t.Fatalf("事件 %s 的冷副本必须可定位：found=%v err=%v", id, found, err)
		}
	}
	// P3 翻转：C 留在热表——窗口内到达的行只进 H，不进删除集
	if !p0HotExists(t, ctx, db, c) {
		t.Fatal("P3：C 是窗口内新写入且无冷副本，必须留在热表（这正是被翻转的缺陷）")
	}
	_, found, err := Locate(ctx, db, c)
	if err != nil {
		t.Fatalf("定位 C 不该报错: %v", err)
	}
	if found {
		t.Fatal("C 是窗口内新写入的，冷层不应有它的副本")
	}
	if got := p0PartitionRows(t, ctx, db, day); got != 1 {
		t.Fatalf("切换后日分区应只剩 C 一行，实际 %d 行", got)
	}
	days := p3DayRecords(t, ctx, db, runID)
	rec, ok := days[day.Format(time.DateOnly)]
	if !ok || rec.Kept != 1 || rec.Dropped != 2 || !rec.RunDayVerified {
		t.Fatalf("detail.days.%s 应记录 kept=1 dropped=2 run_day_verified=true，实际 %+v",
			day.Format(time.DateOnly), days[day.Format(time.DateOnly)])
	}
}
