//go:build integration

// P6 集成测试：生命周期、迁移与恢复（COLD_ARCHIVE_EVOLUTION.SCRATCH.md §P6、§5.2 的
// T21/T22，V12/V13 的实现侧）。
//
//   - T21 完整版：同一天依次 swap → retire → restore → janitor（走 janitor.Run 真实入口，
//     与 main.go 同一构造）。断言 restore 物化 C 集合且按当前分区路由落月归档分区、
//     pin 行随退役并进归档分区且内容不变、再跑一次保留期清理时非 pin 恢复行被到期删除
//     （restore 不重置保留期——恢复行带着原始 ts 回来，对保留期立即再次到期）、
//     被 pin 的行保留；swap 之后该日再 shadow 不会重复归档已移出的行（shadow 按 events
//     扫描，切走的行天然扫不到）。
//   - T22 多日：同一 run 连续 swap 两天，detail.days 逐日记录互不覆盖、kept/dropped 各自
//     正确；退役后再 swap 明确拒绝；restore 路由按当前分区（月归档 / 无覆盖分区落 default）。
//   - T22 重叠 run：两个 run 覆盖同一天形成重叠冷副本，Locate 任一副本命中；swap 只按
//     本 run 的 locator 删除，另一 run 的副本不受影响；报告口径不把重叠副本当两次节省（文档）。
//   - T22 部分恢复 + 资产外键：冷事件 asset_id 指向已删除资产时 restore / Materialize
//     按外键显式失败（错误含资产外键原因与块 id），已完成块保留；恢复原因（重建同 id 资产）
//     后幂等重跑补齐——不静默改写 asset_id，不跳坏块。
//   - RunState 三态：verified run → payload 改坏 → 「曾经验证过（粘性）」「现在自校验不过」
//     「已操作（detail.days）」三者分别可读，不被一个状态值吞并。
//
// 专用测试库 openxdr_p0，与其它集成测试一样串行（-p 1）。复用 p0/p1/p3/p4 的夹具 helper。
package eventarchive

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/janitor"
)

// p6WaitEventsGone 轮询直到给定事件全部不在 events 里。后台清理（janitor.Run 的定时循环）
// 不与测试同步，判据是可观察的库状态；超时把当前残留数写进失败信息，不用 sleep 猜。
func p6WaitEventsGone(t *testing.T, ctx context.Context, db *sql.DB, ids []uuid.UUID) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var left int64
		if err := db.QueryRowContext(ctx,
			`SELECT count(*) FROM events WHERE id = ANY($1::uuid[])`, ids).Scan(&left); err != nil {
			t.Fatalf("轮询事件残留: %v", err)
		}
		if left == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("等 janitor 清理 %d 条到期恢复行超时（仍剩 %d 条）", len(ids), left)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// p6LocatorRows 数一个事件在 locator 里的行数（= 覆盖它的冷块数，跨 run 副本各一行）。
func p6LocatorRows(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM event_archive_locator WHERE event_id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("数事件 %s 的 locator 行: %v", id, err)
	}
	return n
}

// T21 完整链条：swap(day) → Retire(day) → Restore(run, day) → janitor.Run（真实入口）→ 再 shadow。
// 与 p0_baseline 的 TestP0RestoreRoutingAfterRetireBaseline（现状固定）的区别：这里把链条
// 走到「再清理」与「再归档」，验证 P6 的生命周期不变量而不是只记录路由现状。
func TestP6T21SwapRetireRestoreThenJanitorCleanup(t *testing.T) {
	ctx, client, db := p0Open(t)
	// 40 天前的日子：退役窗口内，且对 39 天保留期「restore 后立即再次到期」可判定。
	day := p0Day(t, ctx, db, 40)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)

	pin := p0Event(t, ctx, client, day.Add(1*time.Minute), 4001, "agent", `{"mark":"pin","conn":{"dst":"10.0.0.9:22"}}`)
	p0Pin(t, ctx, client, day.Add(1*time.Minute), pin)
	a := p0Event(t, ctx, client, day.Add(2*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(3*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
	before := hotSnapshot(t, ctx, db, []uuid.UUID{pin, a, b})

	// ① swap：A/B（口径内、未 pin、有本 run 冷副本）移出，pin 留下
	runID := p0VerifiedRun(t, ctx, db, day, day)
	got, err := Swap(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if got.Kept != 1 || got.Dropped != 2 {
		t.Fatalf("swap 实测应为 kept=1（pin）/ dropped=2（A/B），实际 kept=%d dropped=%d", got.Kept, got.Dropped)
	}

	// ② retire：该日分区整体退役，pin 行并进当月归档分区
	month := time.Date(day.Year(), day.Month(), 1, 0, 0, 0, 0, time.UTC)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+eventpart.ArchiveName(month))
	})
	retired, droppedRetire, err := eventpart.Retire(ctx, db, day.AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if retired < 1 || droppedRetire != 0 {
		t.Fatalf("retire 应退役该日且不丢 pin 行（retired=%d dropped=%d）", retired, droppedRetire)
	}
	if p0RelExists(t, ctx, db, eventpart.DailyName(day)) {
		t.Fatal("退役后日分区不应再存在")
	}
	if got := routingOf(t, ctx, db, pin); got != eventpart.ArchiveName(month) {
		t.Fatalf("pin 行应随退役并进 %s，实际 %s", eventpart.ArchiveName(month), got)
	}

	// ③ restore（retire 之后）：物化 C = {A,B}，按当前分区路由落月归档分区，不重建日分区
	n, err := Restore(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if n != 2 {
		t.Fatalf("retire 后 Restore 应物化 A/B 共 2 条，实际 %d 条", n)
	}
	for _, id := range []uuid.UUID{a, b} {
		if got := routingOf(t, ctx, db, id); got != eventpart.ArchiveName(month) {
			t.Fatalf("恢复行 %s 应按当前分区路由落进 %s，实际 %s", id, eventpart.ArchiveName(month), got)
		}
	}
	if p0RelExists(t, ctx, db, eventpart.DailyName(day)) {
		t.Fatal("restore 不重新创建与月归档重叠的日分区（不撤销退役）")
	}
	assertHotRow(t, ctx, db, pin, before)
	assertHotRow(t, ctx, db, a, before)
	assertHotRow(t, ctx, db, b, before)

	// ④ janitor 的保留期清理入口（真实入口 janitor.Run，与 main.go 同一构造）：
	// 保留期 39 天 < 该日 40 天，恢复行带着原始 ts 回来——restore 不重置保留期，它们立即
	// 再次到期；没有 pin（无告警引用）就被删掉。pin 行同样到期，但被告警引用保护而保留。
	janitorCtx, stop := context.WithCancel(ctx)
	t.Cleanup(stop)
	j := &janitor.Janitor{DB: client, SQL: db, Retention: 39 * 24 * time.Hour, Interval: 200 * time.Millisecond}
	runDone := make(chan struct{})
	go func() { defer close(runDone); j.Run(janitorCtx) }()
	p6WaitEventsGone(t, ctx, db, []uuid.UUID{a, b})
	stop()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Log("janitor.Run 未在 5 秒内退出，继续断言（不阻塞）")
	}
	if p0HotExists(t, ctx, db, a) || p0HotExists(t, ctx, db, b) {
		t.Fatal("非 pin 的恢复行应被保留期清理再次删除（restore 不重置保留期）")
	}
	if !p0HotExists(t, ctx, db, pin) {
		t.Fatal("被 pin（告警引用）的行即使到期也应保留")
	}
	assertHotRow(t, ctx, db, pin, before)
	if got := routingOf(t, ctx, db, pin); got != eventpart.ArchiveName(month) {
		t.Fatalf("pin 行清理后应仍在 %s，实际 %s", eventpart.ArchiveName(month), got)
	}

	// ⑤ swap 后该日再次 shadow：A/B 已不在 events，shadow 按 events 扫描天然扫不到，
	// 不产生重叠副本（locator 行数不增长）；该日仅剩的 pin 行被如实计入 pinned 跳过。
	run2, err := Shadow(ctx, db, Options{From: day, To: day, Classes: p0Classes, Sources: p0Sources, Confirm: true})
	if err != nil {
		t.Fatalf("再次 shadow: %v", err)
	}
	info2, err := LoadRun(ctx, db, run2)
	if err != nil {
		t.Fatal(err)
	}
	if info2.Archived != 0 || info2.Chunks != 0 {
		t.Fatalf("已切走的日子再次 shadow 不应归档任何事件，实际 archived=%d chunks=%d", info2.Archived, info2.Chunks)
	}
	if info2.Scanned != 1 || info2.PinnedSkip != 1 {
		t.Fatalf("该日仅剩 pin 行在口径内，应 scanned=1 pinned_skipped=1，实际 scanned=%d pinned=%d",
			info2.Scanned, info2.PinnedSkip)
	}
	for _, id := range []uuid.UUID{a, b} {
		if got := p6LocatorRows(t, ctx, db, id); got != 1 {
			t.Fatalf("事件 %s 的冷副本应只有 run1 一份（无重叠归档），实际 %d 份", id, got)
		}
	}
}

// T22 多日：同一 run 连续 swap 两天——detail.days 逐日记录互不覆盖、每天各自的
// kept/dropped 正确（物化数与删除数分开记账）；retire 后同日再 swap 明确拒绝；
// restore 的路由按当前分区：日分区仍在则回日分区（P0 已固定），覆盖该日的月归档分区
// 存在则落月归档，都没有（该日从未建过分区、退役也没覆盖到）则落默认分区。
func TestP6T22MultiDayRecordsAndRouting(t *testing.T) {
	ctx, client, db := p0Open(t)
	day1 := p0Day(t, ctx, db, 9)
	day2 := p0Day(t, ctx, db, 8)
	// day3：故意不建日分区（行落在默认分区），验证 restore 的 default 路由分支
	day3 := p0Today().AddDate(0, 0, -7)
	if p0RelExists(t, ctx, db, eventpart.DailyName(day3)) {
		t.Fatalf("测试前提：%s 不应有日分区（上一个用例的清理没执行？）", eventpart.DailyName(day3))
	}
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	for _, d := range []time.Time{day1, day2} {
		p4SeedConsumed(t, ctx, db, d)
	}

	seed := func(day time.Time, mark string) (a, b, pin uuid.UUID) {
		a = p0Event(t, ctx, client, day.Add(1*time.Minute), 4001, "agent", `{"mark":"`+mark+`A"}`)
		b = p0Event(t, ctx, client, day.Add(2*time.Minute), 4001, "agent", `{"mark":"`+mark+`B"}`)
		pin = p0Event(t, ctx, client, day.Add(3*time.Minute), 4001, "agent", `{"mark":"`+mark+`pin"}`)
		p0Pin(t, ctx, client, day.Add(3*time.Minute), pin)
		return a, b, pin
	}
	a1, b1, pin1 := seed(day1, "d1")
	a2, b2, pin2 := seed(day2, "d2")
	// day3 的 pin 在 shadow 时就被排除（pinned_skipped），该日冷块里只有 A/B——
	// 这正是「C ≠ 整日行集」的又一处体现
	a3, b3, _ := seed(day3, "d3")

	// 一个 run 覆盖三天：day3 没有日分区，swap 会拒绝它，但 shadow/verify/restore 都不挑分区
	runID := p4VerifiedRun(t, ctx, db, day1, day3, p0Classes, p0Sources)

	// 连续 swap 两天：逐日记录互不覆盖，kept/dropped 每天各自实测
	for i, d := range []time.Time{day1, day2} {
		p, err := Swap(ctx, db, runID, d)
		if err != nil {
			t.Fatalf("Swap %s: %v", d.Format(time.DateOnly), err)
		}
		// 每天 3 行（A/B/pin）：A/B 移出、pin 留下；夹具没有类别外的行（KeepOther=0）
		if p.Kept != 1 || p.Dropped != 2 {
			t.Fatalf("day %d 的 swap 实测应为 kept=1 dropped=2，实际 kept=%d dropped=%d", i+1, p.Kept, p.Dropped)
		}
	}
	days := p3DayRecords(t, ctx, db, runID)
	if len(days) != 2 {
		t.Fatalf("detail.days 应有两天各自的记录，实际 %d 条：%v", len(days), days)
	}
	for _, d := range []time.Time{day1, day2} {
		rec, ok := days[d.Format(time.DateOnly)]
		if !ok {
			t.Fatalf("detail.days 缺 %s 的记录：%v", d.Format(time.DateOnly), days)
		}
		if rec.Kept != 1 || rec.Dropped != 2 || !rec.RunDayVerified {
			t.Fatalf("detail.days.%s 应是 kept=1 dropped=2 run_day_verified=true，实际 %+v",
				d.Format(time.DateOnly), rec)
		}
	}
	// swap 前置拒绝：day3 没有独立日分区（行在默认分区），明确拒绝而不是去默认分区搬行
	if _, err := Swap(ctx, db, runID, day3); err == nil || !strings.Contains(err.Error(), "没有独立日分区") {
		t.Fatalf("day3 无日分区时 Swap 应明确拒绝，实际 err=%v", err)
	}

	// retire 到 day2 结束：day1/day2 分区退役（pin 行并进各自月份的归档分区），day3 不受影响。
	// day1/day2 可能跨月（测试跑在月初时），两个归档分区都要清理。
	month1 := time.Date(day1.Year(), day1.Month(), 1, 0, 0, 0, 0, time.UTC)
	month2 := time.Date(day2.Year(), day2.Month(), 1, 0, 0, 0, 0, time.UTC)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+eventpart.ArchiveName(month1))
		_, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+eventpart.ArchiveName(month2))
	})
	if _, _, err := eventpart.Retire(ctx, db, day2.AddDate(0, 0, 1)); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if p0RelExists(t, ctx, db, eventpart.DailyName(day1)) || p0RelExists(t, ctx, db, eventpart.DailyName(day2)) {
		t.Fatal("退役后 day1/day2 的日分区不应再存在")
	}
	// 退役后同日再 swap：无日分区可重写，明确拒绝（不撤销退役、不重建重叠日分区）
	if _, err := Swap(ctx, db, runID, day2); err == nil || !strings.Contains(err.Error(), "没有独立日分区") {
		t.Fatalf("退役后再 Swap 应明确拒绝，实际 err=%v", err)
	}
	if got := routingOf(t, ctx, db, pin1); got != eventpart.ArchiveName(month1) {
		t.Fatalf("day1 的 pin 行应随退役并进 %s，实际 %s", eventpart.ArchiveName(month1), got)
	}
	if got := routingOf(t, ctx, db, pin2); got != eventpart.ArchiveName(month2) {
		t.Fatalf("day2 的 pin 行应随退役并进 %s，实际 %s", eventpart.ArchiveName(month2), got)
	}

	// restore day2（退役后）：落覆盖该日的月归档分区
	n2, err := Restore(ctx, db, runID, day2)
	if err != nil {
		t.Fatalf("Restore day2: %v", err)
	}
	if n2 != 2 {
		t.Fatalf("Restore day2 应物化 A/B 共 2 条，实际 %d 条", n2)
	}
	for _, id := range []uuid.UUID{a2, b2} {
		if got := routingOf(t, ctx, db, id); got != eventpart.ArchiveName(month2) {
			t.Fatalf("day2 恢复行 %s 应落月归档分区 %s，实际 %s", id, eventpart.ArchiveName(month2), got)
		}
	}
	// restore day3（该日从无日分区、退役覆盖止于 day2）：无覆盖分区，落默认分区。
	// day3 的 pin 在 shadow 时就被排除，冷块里只有 A/B 两条。它们此前一直在默认分区里
	// （swap 不碰无日分区的日子）；让它们离开热表的是保留期逐行清理——janitor.sweep 只在
	// 日分区之外的归档/默认分区逐行删（该真实入口 T21 已经验证），这里直接删到清理后的
	// 状态，单测 restore 的 default 路由分支。
	if _, err := db.ExecContext(ctx, `DELETE FROM events WHERE id = ANY($1::uuid[])`, []uuid.UUID{a3, b3}); err != nil {
		t.Fatalf("模拟保留期清理删除 day3 的到期行: %v", err)
	}
	n3, err := Restore(ctx, db, runID, day3)
	if err != nil {
		t.Fatalf("Restore day3: %v", err)
	}
	if n3 != 2 {
		t.Fatalf("Restore day3 应物化 A/B 共 2 条，实际 %d 条", n3)
	}
	for _, id := range []uuid.UUID{a3, b3} {
		if got := routingOf(t, ctx, db, id); got != eventpart.DefaultName {
			t.Fatalf("day3 恢复行 %s 无覆盖分区应落 %s，实际 %s", id, eventpart.DefaultName, got)
		}
	}
	// 物化数不冒充 swap 删除数：swap 移出的只有 day1/day2 的 A/B（4 条）；restore 插入了
	// day2 的 2 条 + day3 的 2 条；day1 的 A/B 从未被 restore、也不在热表（C ≠ D，见 §1.3）。
	for _, id := range []uuid.UUID{a1, b1} {
		if p0HotExists(t, ctx, db, id) {
			t.Fatalf("day1 的事件 %s 只 swap 未 restore，不应回热表", id)
		}
	}
}

// T22 重叠 run：两个 run 覆盖同一天，同一事件有两份冷副本（locator 各一行）。
// Locate 任一副本命中；swap(run1) 的删除依据只看 run1 的 locator，run2 的块与索引不动；
// 空间口径上重叠副本计入成本、不重复计算节省（report 按各自 run 报数，见 docs）。
func TestP6T22OverlappingRunsShareDay(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)

	a := p0Event(t, ctx, client, day.Add(1*time.Minute), 4001, "agent", `{"mark":"A"}`)
	b := p0Event(t, ctx, client, day.Add(2*time.Minute), 4001, "agent", `{"mark":"B"}`)
	c := p0Event(t, ctx, client, day.Add(3*time.Minute), 4001, "agent", `{"mark":"C"}`)
	abc := []uuid.UUID{a, b, c}

	run1 := p0VerifiedRun(t, ctx, db, day, day)
	run2 := p0VerifiedRun(t, ctx, db, day, day) // 同一天第二轮：重叠副本
	for _, id := range abc {
		if got := p6LocatorRows(t, ctx, db, id); got != 2 {
			t.Fatalf("重叠 run 下事件 %s 应有 2 份冷副本（各 run 一份），实际 %d", id, got)
		}
	}
	if e, found, err := Locate(ctx, db, a); err != nil || !found || e.ID != a {
		t.Fatalf("重叠副本下 Locate 应任一命中: found=%v err=%v", found, err)
	}

	// swap 只以 run1 的 locator 为删除依据；run2 的副本不受影响，冷层仍可定位
	if _, err := Swap(ctx, db, run1, day); err != nil {
		t.Fatalf("Swap(run1): %v", err)
	}
	for _, id := range abc {
		if p0HotExists(t, ctx, db, id) {
			t.Fatalf("事件 %s 有 run1 冷副本，应已移出热表", id)
		}
		if got := p6LocatorRows(t, ctx, db, id); got != 2 {
			t.Fatalf("swap 后事件 %s 的两份冷副本都应在（run2 的副本不受影响），实际 %d", id, got)
		}
		if _, found, err := Locate(ctx, db, id); err != nil || !found {
			t.Fatalf("swap(run1) 后 Locate %s 仍应命中（任一副本）: found=%v err=%v", id, found, err)
		}
	}
	// 两个 run 各自的账：同一天各 3 条、各 1 块——重叠副本在空间口径上叠加为成本，
	// 节省量不得按 run 相加（docs/event-archive.md 的报告口径）。
	for _, run := range []uuid.UUID{run1, run2} {
		if got := p0ColdDayCount(t, ctx, db, run, day); got != 3 {
			t.Fatalf("run %s 在该日的冷块应有 3 条，实际 %d", run, got)
		}
	}
}

// T22 部分恢复 + 资产外键：冷块里的 asset_id 指向已删除资产。现状按底稿「保留显式失败，
// 不静默改写」：批量 restore 的失败块整体回滚（错误带块 id 与外键原因），已完成块保留；
// 单条 Materialize 同样显式失败且不插行。修复原因（重建同 id 资产）后幂等重跑补齐。
func TestP6T22RestoreAssetFKExplicitFailureAndRerun(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)

	// 300 条 ts 严格递增（每秒一条）→ 3 块（ChunkEvents=100）；第 150 条挂资产
	const total, perChunk = 300, 100
	asset := client.Asset.Create().SetHostname("p6-fk").SaveX(ctx)
	var fkEvent uuid.UUID
	for i := 1; i <= total; i++ {
		create := client.Event.Create().SetTs(day.Add(time.Duration(i) * time.Second)).
			SetClassUID(4001).SetSource("agent").
			SetRaw([]byte(`{"mark":"f","i":` + strconv.Itoa(i) + `}`))
		if i == 150 {
			create.SetAssetID(asset.ID)
		}
		e := create.SaveX(ctx)
		if i == 150 {
			fkEvent = e.ID
		}
	}

	runID := p1VerifiedRun(t, ctx, db, day, day, perChunk, MaxPlainLen)
	chunkIDs, err := dayChunkIDs(ctx, db, runID, day)
	if err != nil || len(chunkIDs) != 3 {
		t.Fatalf("测试前提：应恰好 3 块，实际 %v（%v）", chunkIDs, err)
	}
	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("Swap: %v", err)
	}

	// 删除资产：热表已无行引用它（全被 swap 移出），删除干净成功——冷块里的 asset_id 从此悬空
	if err := client.Asset.DeleteOneID(asset.ID).Exec(ctx); err != nil {
		t.Fatalf("删除资产: %v", err)
	}

	// 批量 restore：第 2 块（含第 150 条）FK 失败整体回滚；第 1 块已提交保留
	n, err := Restore(ctx, db, runID, day)
	if err == nil {
		t.Fatalf("资产已删除时 Restore 必须显式失败，实际成功插入 %d 条", n)
	}
	if !strings.Contains(err.Error(), "events_assets_events") {
		t.Fatalf("失败原因应含资产外键（events_assets_events），实际：%v", err)
	}
	if !strings.Contains(err.Error(), chunkIDs[1].String()) {
		t.Fatalf("失败错误应带第 2 块 id %s，实际：%v", chunkIDs[1], err)
	}
	if n != perChunk {
		t.Fatalf("部分完成：第 1 块的 %d 行应已提交并如实返回，实际 %d", perChunk, n)
	}
	if got := p0PartitionRows(t, ctx, db, day); got != perChunk {
		t.Fatalf("失败后该日分区应只有第 1 块的 %d 行（第 2 块无部分提交），实际 %d 行", perChunk, got)
	}
	if p0HotExists(t, ctx, db, fkEvent) {
		t.Fatal("FK 失败的事件不应被插入任何行")
	}

	// 单条 Materialize 同一事件：同样显式失败、带资产原因、不插行
	inserted, err := Materialize(ctx, db, fkEvent)
	if err == nil || inserted {
		t.Fatalf("单条物化 FK 失败事件应显式失败 (false, err)，实际 (%v, %v)", inserted, err)
	}
	if !strings.Contains(err.Error(), "events_assets_events") {
		t.Fatalf("单条物化失败原因应含资产外键，实际：%v", err)
	}
	if p0HotExists(t, ctx, db, fkEvent) {
		t.Fatal("单条物化失败不应留下任何行")
	}

	// 修复原因后重跑（部分恢复的补齐路径）：重建同 id 资产，FK 重新成立，幂等重跑补齐剩余 200 条
	revived := client.Asset.Create().SetID(asset.ID).SetHostname("p6-fk-revived").SaveX(ctx)
	if revived.ID != asset.ID {
		t.Fatalf("重建资产应保持同 id %s，实际 %s", asset.ID, revived.ID)
	}
	n2, err := Restore(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("修复后重跑 Restore: %v", err)
	}
	if n2 != total-perChunk {
		t.Fatalf("重跑应补插 %d 条（已恢复的第 1 块被幂等跳过），实际 %d", total-perChunk, n2)
	}
	if got := p0PartitionRows(t, ctx, db, day); got != total {
		t.Fatalf("重跑后该日分区应有 %d 行，实际 %d 行", total, got)
	}
	// 恢复的是冷块里的原始行：asset_id 保留原值（显式失败语义下从未被改写成 NULL）
	var assetBack uuid.NullUUID
	if err := db.QueryRowContext(ctx, `SELECT asset_id FROM events WHERE id = $1`, fkEvent).
		Scan(&assetBack); err != nil {
		t.Fatalf("读回 FK 事件: %v", err)
	}
	if !assetBack.Valid || assetBack.UUID != asset.ID {
		t.Fatalf("恢复行的 asset_id 应保留原值 %s，实际 %v", asset.ID, assetBack.UUID)
	}
	// 第三次：主键幂等，0 行
	if n3, err := Restore(ctx, db, runID, day); err != nil || n3 != 0 {
		t.Fatalf("第三次 Restore 应插入 0 行，实际 (%d, %v)", n3, err)
	}
}

// RunState 三态区分：verified（曾对拍通过）+ 自校验失败（payload 改坏）+ 已操作（detail.days）
// 是三个独立事实，任一组合都可能出现；它们不能被塞进一个状态值（§P6「三类校验分开」）。
func TestP6RunStateSeparatesVerifiedSelfcheckAndDays(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)

	// 3 条事件、ChunkEvents=2 → 2 块：改坏第 2 块后 SelfCheck 应停在 ChunksChecked=1
	for i := 1; i <= 3; i++ {
		client.Event.Create().SetTs(day.Add(time.Duration(i) * time.Minute)).
			SetClassUID(4001).SetSource("agent").
			SetRaw([]byte(`{"mark":"s","i":` + strconv.Itoa(i) + `}`)).SaveX(ctx)
	}
	runID := p1VerifiedRun(t, ctx, db, day, day, 2, MaxPlainLen)
	chunkIDs, err := dayChunkIDs(ctx, db, runID, day)
	if err != nil || len(chunkIDs) != 2 {
		t.Fatalf("测试前提：应恰好 2 块，实际 %v（%v）", chunkIDs, err)
	}
	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("Swap: %v", err)
	}

	// 操作后状态：曾对拍通过 + 当前自校验通过 + 已切换该日
	st, err := RunState(ctx, db, runID)
	if err != nil {
		t.Fatalf("RunState: %v", err)
	}
	if !st.BuildVerified || st.VerifiedAt == "" {
		t.Fatalf("verified run 应报告曾对拍通过（verified_at 非空），实际 %+v", st)
	}
	if st.SelfCheck.Err != nil || st.SelfCheck.ChunksChecked != 2 || st.SelfCheck.EventsChecked != 3 {
		t.Fatalf("自校验应全部通过（2 块 3 条），实际 %+v", st.SelfCheck)
	}
	if len(st.Days) != 1 || st.Days[0].Kept != 0 || st.Days[0].Dropped != 3 {
		t.Fatalf("应有一条逐日记录 kept=0 dropped=3，实际 %+v", st.Days)
	}

	// 改坏第 2 块 payload：run.status 仍 verified（粘性资格不自动回退），但「现在自校验不过」；
	// 操作记录不受影响。三个事实分别可读，正是 status 子命令要区分的口径。
	var payload []byte
	if err := db.QueryRowContext(ctx, `SELECT payload FROM event_archive_chunks WHERE id = $1`,
		chunkIDs[1]).Scan(&payload); err != nil {
		t.Fatalf("读第 2 块 payload: %v", err)
	}
	payload[len(payload)-1] ^= 0xff
	if _, err := db.ExecContext(ctx, `UPDATE event_archive_chunks SET payload = $2 WHERE id = $1`,
		chunkIDs[1], payload); err != nil {
		t.Fatalf("改坏第 2 块 payload: %v", err)
	}

	st2, err := RunState(ctx, db, runID)
	if err != nil {
		t.Fatalf("RunState（改坏后）: %v", err)
	}
	if !st2.BuildVerified {
		t.Fatalf("曾对拍通过是粘性事实，改坏 payload 不应回退 status（当前 %s）", st2.Run.Status)
	}
	if st2.Run.Status != StatusVerified {
		t.Fatalf("run.status 应保持 %s（自校验失败由 SelfCheck 表达，不改 status）", StatusVerified)
	}
	if st2.SelfCheck.Err == nil {
		t.Fatal("payload 改坏后自校验应失败")
	}
	if !strings.Contains(st2.SelfCheck.Err.Error(), chunkIDs[1].String()) {
		t.Fatalf("自校验失败应带块 id %s，实际：%v", chunkIDs[1], st2.SelfCheck.Err)
	}
	if st2.SelfCheck.ChunksChecked != 1 {
		t.Fatalf("自校验应在第 1 块通过后停在第 2 块（ChunksChecked=1），实际 %d", st2.SelfCheck.ChunksChecked)
	}
	if len(st2.Days) != 1 {
		t.Fatalf("操作记录不因冷块损坏消失，实际 %+v", st2.Days)
	}
	if out := st2.String(); !strings.Contains(out, "verified") || !strings.Contains(out, "自校验") {
		t.Fatalf("String 输出应把三态分别呈现，实际：\n%s", out)
	}

	// 对照：从未对拍过的 run——三态分别是 未对拍 / 自校验通过 / 无操作
	run2, err := Shadow(ctx, db, Options{From: p0Today(), To: p0Today(), Classes: p0Classes, Sources: p0Sources, Confirm: true})
	if err != nil {
		t.Fatalf("对照 shadow: %v", err)
	}
	st3, err := RunState(ctx, db, run2)
	if err != nil {
		t.Fatal(err)
	}
	if st3.BuildVerified || st3.VerifiedAt != "" || st3.SelfCheck.Err != nil || len(st3.Days) != 0 {
		t.Fatalf("未对拍的空 run 应是 未验证/自校验通过/无操作，实际 %+v", st3)
	}
}
