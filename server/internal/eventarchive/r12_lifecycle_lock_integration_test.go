//go:build integration

// R1/R2 集成测试：同日生命周期锁（COLD_ARCHIVE_EVOLUTION.SCRATCH.md §P3 的「R1 最小修复」
// 「R2 最小修复」两节，5.2 节 T03b/T04b，V06/V07 的并发侧）。
//
//   - T03b（R1）两种先后顺序各一例：终检之后、DETACH 之前（RewriteBeforeReplace）到达的
//     引用写入者，与持有排他生命周期锁的 swap 在锁上串行——
//     顺序一（swap 先持锁）：引用事务阻塞到 swap 提交后执行，锁内重读发现热行缺失，
//     经冷层物化回热表再写引用（事件页面恢复可访问，无悬空引用）；
//     顺序二（引用先持锁）：swap 在生命周期锁上等待，引用提交后 swap 的锁内重读把
//     该行判为 pin 留热（pin 生效，无数据丢失）。
//   - T04b（R2）：两块各一行，restore 停在第一块提交后（块间隙），同日 swap 无法穿进
//     间隙；restore 完成边界 C 全体在热表。反向（swap 先持锁）restore 排队等待。
//   - swap/retire、restore/retire 互斥：retire 按生产路径（janitor）的协议取同日排他锁
//     后再跑 eventpart.Retire。
//   - 会话级锁随连接消失：持锁连接被杀后锁立即释放，后续操作能拿到。
//
// 引用写入者走「生产写入者协议」：与 ingest.upsertAlert 同一套调用——
// eventpart.LifecycleLockShared 取共享锁 → eventarchive.EnsureHotEvents 锁内重读/冷物化
// 补链 → INSERT alerts。并发全部用 channel 屏障确定性同步，不使用 sleep 证明竞态
// （少量 sleep 只用于「仍未返回」的可证伪观察，超时即失败）。
//
// 专用测试库 openxdr_p0，与其它集成测试一样串行（-p 1）。复用 p0/p1/p3/p4 的夹具。
package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/internal/eventpart"
)

// r12RefWriter 经生产写入者协议建一条 alerts 引用（R1 锁点 + 锁内重读/物化补链）。
// park 非 nil 时在写入引用后、提交前停住（顺序二用：引用先持锁不提交，让 swap 排队）；
// 结果（提交错误）写回 done。整个事务失败时 done 收到错误，不留下任何提交。
func r12RefWriter(ctx context.Context, db *sql.DB, ts time.Time, id uuid.UUID, rule string, park <-chan struct{}, done chan<- error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		done <- err
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := eventpart.LifecycleLockShared(ctx, tx, ts); err != nil {
		done <- err
		return
	}
	if err := EnsureHotEvents(ctx, tx, id); err != nil {
		done <- err
		return
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO alerts (id, ts, rule_id, severity, event_id)
 VALUES (gen_random_uuid(), $1, $2, 5, $3)`, ts, rule, id); err != nil {
		done <- err
		return
	}
	if park != nil {
		<-park
	}
	done <- tx.Commit()
}

// r12PinDirect 由测试直接插一条 alert 引用（夹具用，不经锁协议——模拟已提交的外部状态）。
func r12PinDirect(t *testing.T, ctx context.Context, db *sql.DB, ts time.Time, id uuid.UUID, rule string) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `INSERT INTO alerts (id, ts, rule_id, severity, event_id)
 VALUES (gen_random_uuid(), $1, $2, 5, $3)`, ts, rule, id); err != nil {
		t.Fatalf("直接注入 pin（事件 %s）: %v", id, err)
	}
}

// r12AlertCount 数引用某事件的 alert 行数。
func r12AlertCount(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM alerts WHERE event_id = $1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// r12RestoreRecord 读 run.detail.days.<day>.restore（R2 的恢复记录）。
func r12RestoreRecord(t *testing.T, ctx context.Context, db *sql.DB, runID uuid.UUID, day time.Time) restoreDayRecord {
	t.Helper()
	run, err := LoadRun(ctx, db, runID)
	if err != nil {
		t.Fatal(err)
	}
	var detail struct {
		Days map[string]json.RawMessage `json:"days"`
	}
	if err := json.Unmarshal(run.Detail, &detail); err != nil {
		t.Fatalf("解析 run detail: %v", err)
	}
	raw, ok := detail.Days[day.Format(time.DateOnly)]
	if !ok {
		t.Fatalf("detail.days 缺 %s（swap 记录应已建）: %s", day.Format(time.DateOnly), run.Detail)
	}
	var rec struct {
		Restore restoreDayRecord `json:"restore"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("解析 detail.days.%s.restore: %v", day.Format(time.DateOnly), err)
	}
	return rec.Restore
}

// r12NotDoneWithin 断言通道在窗口内仍无结果（把「仍在等待」变成明确的可证伪观察）。
func r12NotDoneWithin[T any](t *testing.T, d time.Duration, name string, ch <-chan T) {
	t.Helper()
	select {
	case v := <-ch:
		t.Fatalf("%s 不应在这段窗口内返回（说明锁没有挡住它）: %v", name, v)
	case <-time.After(d):
	}
}

// r12ReleaseOnExit 兜底放行 park 通道：断言提前失败（FailNow）时也不让停住的
// swap/restore 协程带着表锁泄漏把后续夹具的清理挂死。正常路径 close 后本函数是空操作。
func r12ReleaseOnExit(ch chan struct{}) {
	select {
	case <-ch: // 已关闭
	default:
		close(ch)
	}
}

// T03b 顺序一（swap 先持锁，R1）：swap 停在终检前后（before_replace）、持有同日排他生命
// 周期锁时，独立连接的引用写入者必须阻塞；swap 提交后写入者才继续，锁内重读发现热行
// 已被移出 → 从冷层物化回热表 → 引用指向热行。断言：无悬空引用、alert 存在、事件行
// 存在（被物化）、无数据丢失（逐字段）、冷副本仍可定位。
func TestR12T03bWriterBlocksThenMaterializes(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
	before := hotSnapshot(t, ctx, db, []uuid.UUID{a, b})
	runID := p0VerifiedRun(t, ctx, db, day, day)
	conn := p3IndependentConn(t)

	parked, release := p3Park(t, "before_replace")
	defer r12ReleaseOnExit(release)
	doneSwap := p3RunSwap(ctx, db, runID, day)
	select {
	case <-parked:
	case <-time.After(time.Minute):
		t.Fatal("Swap 没有停在 before_replace")
	}

	// 独立连接经生产写入者协议建引用：此刻 swap 持有排他生命周期锁，写入者必须阻塞。
	writerDone := make(chan error, 1)
	go r12RefWriter(ctx, conn, day.Add(15*time.Minute), a, "r12-t03b-a", nil, writerDone)
	// 可证伪观察：写入者既没报错也没提交（alert 不可见、事务未完成）——
	// 若 swap 没取生命周期锁（回归），写入者会在窗口内直接完成。
	r12NotDoneWithin(t, 400*time.Millisecond, "引用写入者", writerDone)
	if got := r12AlertCount(t, ctx, db, a); got != 0 {
		t.Fatalf("阻塞中的写入者不应提交任何引用，实际 %d 条", got)
	}

	close(release)
	out := p3WaitSwap(t, doneSwap)
	if out.err != nil {
		t.Fatalf("Swap 应照常完成: %v", out.err)
	}
	if out.plan.Dropped != 2 {
		t.Fatalf("A/B 均未被 pin（引用还没提交），应移出 2 行，实际 dropped=%d", out.plan.Dropped)
	}

	// swap 提交后写入者才拿到共享锁：A 的热行已消失 → 冷定位 + 同事务物化 + 写引用。
	select {
	case err := <-writerDone:
		if err != nil {
			t.Fatalf("swap 提交后引用写入者应完成物化补链并提交: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("swap 提交后引用写入者没有返回")
	}
	if got := r12AlertCount(t, ctx, db, a); got != 1 {
		t.Fatalf("应恰好一条引用 A 的 alert，实际 %d 条", got)
	}
	// 引用指向热行（证据页可访问）：A 已被物化回热表且逐字段不变；B 留在冷层
	assertHotEquals(t, ctx, db, []uuid.UUID{a}, map[uuid.UUID]string{a: before[a]})
	if p0HotExists(t, ctx, db, b) {
		t.Fatal("B 没有 pin 也没有引用，应保持移出热表")
	}
	if _, found, err := Locate(ctx, db, b); err != nil || !found {
		t.Fatalf("B 的冷副本必须可定位: found=%v err=%v", found, err)
	}
	// 物化后的 A 现在 pin 在热表：同日再次 swap 必须保留它
	if _, err := Swap(ctx, db, runID, day); err == nil || !strings.Contains(err.Error(), "无需切换") {
		t.Fatalf("A 已被 alert 引用，重跑 swap 应因 pin 全保留而报告无需操作，实际 %v", err)
	}
	if !p0HotExists(t, ctx, db, a) {
		t.Fatal("被引用的 A 必须留在热表（无悬空引用）")
	}
}

// T03b 顺序二（引用先持锁，R1）：引用事务先取共享锁、写引用但**不提交**，swap 在生命
// 周期锁上排队；引用提交后 swap 继续，锁内重读 PinnedIDs 把该行判为 pin 留热。
// 断言：swap 等待期间未动分区；最终 A 留热且逐字段不变、B 移出有冷副本、引用无悬空。
func TestR12T03bSwapWaitsForWriterPinSurvives(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
	before := hotSnapshot(t, ctx, db, []uuid.UUID{a, b})
	runID := p0VerifiedRun(t, ctx, db, day, day)
	conn := p3IndependentConn(t)

	// 引用写入者先持共享锁、写好引用、停在提交前
	parkWriter := make(chan struct{})
	defer r12ReleaseOnExit(parkWriter)
	writerDone := make(chan error, 1)
	go r12RefWriter(ctx, conn, day.Add(15*time.Minute), a, "r12-t03b-b", parkWriter, writerDone)
	// 写入者持锁但未提交：swap 应在排他生命周期锁上排队（可证伪：旧实现会直接完成切换）
	doneSwap := p3RunSwap(ctx, db, runID, day)
	r12NotDoneWithin(t, 400*time.Millisecond, "Swap", doneSwap)
	if got := p0PartitionRows(t, ctx, db, day); got != 2 {
		t.Fatalf("swap 排队期间不得动分区，应有 2 行，实际 %d", got)
	}

	close(parkWriter) // 引用提交 → alert 落库 → A 被 pin
	if err := <-writerDone; err != nil {
		t.Fatalf("引用写入者提交: %v", err)
	}
	out := p3WaitSwap(t, doneSwap)
	if out.err != nil {
		t.Fatalf("swap 应在引用提交后照常完成: %v", out.err)
	}
	// pin 生效：A 留热，B 移出；引用指向热行
	if out.plan.Kept != 1 || out.plan.Dropped != 1 {
		t.Fatalf("pin 的 A 应留热、B 移出：kept=%d dropped=%d", out.plan.Kept, out.plan.Dropped)
	}
	assertHotEquals(t, ctx, db, []uuid.UUID{a}, map[uuid.UUID]string{a: before[a]})
	if p0HotExists(t, ctx, db, b) {
		t.Fatal("未被引用的 B 应随 swap 移出热表")
	}
	if got := r12AlertCount(t, ctx, db, a); got != 1 {
		t.Fatalf("引用 A 的 alert 应恰一条，实际 %d", got)
	}
	if _, found, err := Locate(ctx, db, b); err != nil || !found {
		t.Fatalf("B 的冷副本必须可定位: found=%v err=%v", found, err)
	}
}

// T04b（R2）：restore 两块各一行，停在第一块提交后（块间隙）；同日 swap 拿不到生命周期
// 锁、穿不进间隙。放行后 restore 完成，返回 2 且 A/B 全部在热表；随后 swap 在锁内重读
// 中发现 A/B 已被 pin（夹具预置引用）、C 没有冷副本，无一行可删，明确报告无需操作——
// 「完成物化 C」的承诺不再被块间隙破坏。断言含 run.detail 的恢复记录。
func TestR12T04bSwapCannotInterleaveBetweenRestoreChunks(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
	// 每块 1 条：A、B 分属两个块（shadow 按 ts 扫描，seq 顺序确定）
	runID := p1VerifiedRun(t, ctx, db, day, day, 1, MaxPlainLen)
	// C 在 shadow 之后到达：没有冷副本，swap 必须留热——它让放行后的 swap 有候选可试，
	// 证明 swap 真的执行到了锁内重读，而不是被预检挡掉
	c := p0Event(t, ctx, client, day.Add(30*time.Minute), 4001, "agent", `{"mark":"C","conn":{"dst":"10.0.0.3:443"}}`)
	before := hotSnapshot(t, ctx, db, []uuid.UUID{a, b, c})

	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if p0HotExists(t, ctx, db, a) || p0HotExists(t, ctx, db, b) || !p0HotExists(t, ctx, db, c) {
		t.Fatal("切换后 A/B 应移出热表、C（无冷副本）留热")
	}
	// 预置引用：恢复完成后 A/B 立即受 pin 保护（同时是「证据页要能访问」的动因）
	r12PinDirect(t, ctx, db, day.Add(15*time.Minute), a, "r12-t04b-a")
	r12PinDirect(t, ctx, db, day.Add(25*time.Minute), b, "r12-t04b-b")

	// restore 停在第一块提交后：A 已回热表，B 还在冷层（只在首个块后停一次）
	parkRestore, releaseRestore := make(chan struct{}), make(chan struct{})
	defer r12ReleaseOnExit(releaseRestore)
	var parkedOnce bool
	restoreTestHook = func(stage string, chunkID uuid.UUID, inserted int64) error {
		if stage != "after_chunk" || parkedOnce {
			return nil
		}
		parkedOnce = true
		close(parkRestore)
		<-releaseRestore
		return nil
	}
	t.Cleanup(func() { restoreTestHook = nil })
	doneRestore := make(chan int64, 1)
	restoreErr := make(chan error, 1)
	go func() {
		n, err := Restore(ctx, db, runID, day)
		doneRestore <- n
		restoreErr <- err
	}()
	select {
	case <-parkRestore:
	case err := <-restoreErr:
		t.Fatalf("Restore 提前失败: %v", err)
	case <-time.After(time.Minute):
		t.Fatal("Restore 没有停在第一块之后")
	}
	if !p0HotExists(t, ctx, db, a) || p0HotExists(t, ctx, db, b) {
		t.Fatal("块间隙处应恰有 A 回热、B 仍在冷层")
	}

	// 块间隙里启动 swap：必须被会话级排他锁挡住（旧实现会在这里穿进间隙把 A 再切走）
	doneSwap := p3RunSwap(ctx, db, runID, day)
	r12NotDoneWithin(t, 400*time.Millisecond, "块间隙中的 Swap", doneSwap)

	close(releaseRestore)
	var restored int64
	select {
	case restored = <-doneRestore:
		if err := <-restoreErr; err != nil {
			t.Fatalf("Restore 应完成: %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("放行后 Restore 没有返回")
	}
	if restored != 2 {
		t.Fatalf("修复后 Restore 应返回 2（不再被块间隙破坏），实际 %d", restored)
	}
	// 完成边界：C 集合全体在热表，逐字段无丢失
	assertHotEquals(t, ctx, db, []uuid.UUID{a, b, c}, before)
	rec := r12RestoreRecord(t, ctx, db, runID, day)
	if rec.Status != "done" || rec.Inserted != 2 {
		t.Fatalf("detail.days.%s.restore 应为 done/inserted=2，实际 %+v", day.Format(time.DateOnly), rec)
	}

	// swap 解除阻塞后执行：A/B 被 pin、C 无冷副本 → 锁内核对后无一行可删，明确报告无需操作
	out := p3WaitSwap(t, doneSwap)
	if out.err == nil || !strings.Contains(out.err.Error(), "无需切换") {
		t.Fatalf("放行后的 swap 应明确处理（全保留 → 无需操作），实际 %v", out.err)
	}
	assertHotEquals(t, ctx, db, []uuid.UUID{a, b, c}, before)
	for _, id := range []uuid.UUID{a, b} {
		if got := r12AlertCount(t, ctx, db, id); got != 1 {
			t.Fatalf("事件 %s 的引用应恰一条且指向热行，实际 %d", id, got)
		}
	}
}

// T04b 反向（R2）：swap 先持排他生命周期锁（停在 after_copy），restore 的会话级锁排队
// 等待——带超时地观察到「进不去」，swap 完成后 restore 照常完成、返回 2。
func TestR12T04bRestoreWaitsWhileSwapHoldsLock(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
	runID := p1VerifiedRun(t, ctx, db, day, day, 1, MaxPlainLen)

	parked, release := p3Park(t, "after_copy")
	defer r12ReleaseOnExit(release)
	doneSwap := p3RunSwap(ctx, db, runID, day)
	select {
	case <-parked:
	case <-time.After(time.Minute):
		t.Fatal("Swap 没有停在 after_copy")
	}

	// swap 持锁期间 restore 排队：短超时把「被挡住」变成明确结果
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if n, err := Restore(rctx, db, runID, day); err == nil {
		t.Fatalf("swap 持有同日排他生命周期锁期间，Restore 不应开始（实际插入 %d 条）", n)
	}
	close(release)
	if out := p3WaitSwap(t, doneSwap); out.err != nil {
		t.Fatalf("swap 应照常完成: %v", out.err)
	}
	n, err := Restore(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("swap 完成后 Restore: %v", err)
	}
	if n != 2 {
		t.Fatalf("应还原 A/B 共 2 条，实际 %d", n)
	}
	if !p0HotExists(t, ctx, db, a) || !p0HotExists(t, ctx, db, b) {
		t.Fatal("A/B 应回到热表")
	}
}

// r12RetireLikeJanitor 按生产路径（janitor.retireExpired）的协议跑退役：先取到期日的
// 排他生命周期锁（lockTimeoutMs 是测试用的锁等待上限），锁内执行 eventpart.Retire。
// 返回是否拿锁成功；拿锁失败时（明确被挡）返回 false 与 nil。
func r12RetireLikeJanitor(t *testing.T, ctx context.Context, db *sql.DB, cutoff time.Time, lockTimeoutMs int) (bool, int, int64, error) {
	t.Helper()
	days, err := retireWindowDaysForTest(ctx, db, cutoff)
	if err != nil {
		return false, 0, 0, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`SET LOCAL lock_timeout = '`+(time.Duration(lockTimeoutMs)*time.Millisecond).String()+`'`); err != nil {
		return false, 0, 0, err
	}
	if err := eventpart.LifecycleLockExclusive(ctx, tx, days...); err != nil {
		// 等不到锁：明确被挡（同日操作持锁中），不当作错误上抛
		return false, 0, 0, nil
	}
	n, dropped, err := eventpart.Retire(ctx, db, cutoff)
	if err != nil {
		return true, n, dropped, err
	}
	return true, n, dropped, tx.Commit()
}

// retireWindowDaysForTest 与 janitor.retireWindowDays 同式（eventarchive 侧没有该 helper，
// 测试里内联一份；两条路径的判定必须保持一致）。
func retireWindowDaysForTest(ctx context.Context, db *sql.DB, cutoff time.Time) ([]time.Time, error) {
	rows, err := db.QueryContext(ctx, `SELECT c.relname FROM pg_inherits i
 JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = to_regclass($1)`, eventpart.Parent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var days []time.Time
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		day, ok := r12DailyPartitionDay(name)
		if !ok || day.AddDate(0, 0, 1).After(cutoff) {
			continue
		}
		days = append(days, day)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(days, func(i, j int) bool { return days[i].Before(days[j]) })
	return days, nil
}

func r12DailyPartitionDay(name string) (time.Time, bool) {
	const prefix = "events_p"
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+8 {
		return time.Time{}, false
	}
	day, err := time.Parse("20060102", strings.TrimPrefix(name, prefix))
	if err != nil {
		return time.Time{}, false
	}
	return day.UTC(), true
}

// swap / retire 互斥（R1/R2）：swap 持排他生命周期锁期间，按 janitor 协议的退役拿不到锁、
// 明确不动分区；swap 完成后退役正常执行。反向不再单测——retire 拿锁在 swap 的重写事务
// 之前，同为排他排队，语义与 restore/retire 反向用例一致。
func TestR12SwapAndRetireMutualExclusion(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 40)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	pin := p0Event(t, ctx, client, day.Add(1*time.Minute), 4001, "agent", `{"mark":"pin","conn":{"dst":"10.0.0.9:22"}}`)
	p0Pin(t, ctx, client, day.Add(1*time.Minute), pin)
	a := p0Event(t, ctx, client, day.Add(2*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	runID := p0VerifiedRun(t, ctx, db, day, day)
	month := time.Date(day.Year(), day.Month(), 1, 0, 0, 0, 0, time.UTC)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+eventpart.ArchiveName(month))
	})

	parked, release := p3Park(t, "before_replace")
	defer r12ReleaseOnExit(release)
	doneSwap := p3RunSwap(ctx, db, runID, day)
	select {
	case <-parked:
	case <-time.After(time.Minute):
		t.Fatal("Swap 没有停在 before_replace")
	}

	// swap 持锁期间退役拿不到生命周期锁：明确被挡（1 秒锁上限），分区原样
	locked, retired, _, err := r12RetireLikeJanitor(t, ctx, db, day.AddDate(0, 0, 1), 1000)
	if err != nil {
		t.Fatalf("持锁期间退役调用不应报错（应明确被挡）: %v", err)
	}
	if locked || retired != 0 {
		t.Fatalf("swap 持锁期间退役不得执行（locked=%v retired=%d）", locked, retired)
	}
	if !p0RelExists(t, ctx, db, eventpart.DailyName(day)) {
		t.Fatal("被挡下的退役不得动分区")
	}
	close(release)
	if out := p3WaitSwap(t, doneSwap); out.err != nil {
		t.Fatalf("swap 应照常完成: %v", out.err)
	}
	if !p0HotExists(t, ctx, db, pin) || p0HotExists(t, ctx, db, a) {
		t.Fatal("切换后应只有 pin 行留热")
	}

	// swap 完成后退役正常：pin 行并进月归档分区
	locked, retired, dropped, err := r12RetireLikeJanitor(t, ctx, db, day.AddDate(0, 0, 1), 1000)
	if err != nil || !locked {
		t.Fatalf("swap 完成后退役应拿到锁并执行: locked=%v err=%v", locked, err)
	}
	if retired < 1 || dropped != 0 {
		t.Fatalf("应退役该日分区且不丢 pin 行（retired=%d dropped=%d）", retired, dropped)
	}
	if got := routingOf(t, ctx, db, pin); got != eventpart.ArchiveName(month) {
		t.Fatalf("pin 行应随退役并进 %s，实际 %s", eventpart.ArchiveName(month), got)
	}
}

// restore / retire 互斥（R2）：restore 停在块间隙时，按 janitor 协议的退役拿不到锁、
// 不动分区；restore 完成边界后退役正常执行（恢复行未 pin 随退役丢弃属正常保留期语义，
// 这里只断言互斥与最终状态一致）。反向：retire 先持锁，restore 排队等待后完成。
func TestR12RestoreAndRetireMutualExclusion(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 40)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	pin := p0Event(t, ctx, client, day.Add(1*time.Minute), 4001, "agent", `{"mark":"pin","conn":{"dst":"10.0.0.9:22"}}`)
	p0Pin(t, ctx, client, day.Add(1*time.Minute), pin)
	a := p0Event(t, ctx, client, day.Add(2*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(3*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
	runID := p1VerifiedRun(t, ctx, db, day, day, 1, MaxPlainLen)
	month := time.Date(day.Year(), day.Month(), 1, 0, 0, 0, 0, time.UTC)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+eventpart.ArchiveName(month))
	})
	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("Swap: %v", err)
	}

	// restore 停在第一块提交后（A 已回热、B 还在冷层；只在首个块后停一次）
	parkRestore, releaseRestore := make(chan struct{}), make(chan struct{})
	defer r12ReleaseOnExit(releaseRestore)
	var parkedOnce bool
	restoreTestHook = func(stage string, chunkID uuid.UUID, inserted int64) error {
		if stage != "after_chunk" || parkedOnce {
			return nil
		}
		parkedOnce = true
		close(parkRestore)
		<-releaseRestore
		return nil
	}
	t.Cleanup(func() { restoreTestHook = nil })
	doneRestore := make(chan int64, 1)
	restoreErr := make(chan error, 1)
	go func() {
		n, err := Restore(ctx, db, runID, day)
		doneRestore <- n
		restoreErr <- err
	}()
	select {
	case <-parkRestore:
	case err := <-restoreErr:
		t.Fatalf("Restore 提前失败: %v", err)
	case <-time.After(time.Minute):
		t.Fatal("Restore 没有停在第一块之后")
	}

	// 块间隙里的退役被会话级排他锁挡住：明确不动分区
	locked, retired, _, err := r12RetireLikeJanitor(t, ctx, db, day.AddDate(0, 0, 1), 1000)
	if err != nil {
		t.Fatalf("块间隙中的退役调用不应报错（应明确被挡）: %v", err)
	}
	if locked || retired != 0 {
		t.Fatalf("restore 块间隙中退役不得执行（locked=%v retired=%d）", locked, retired)
	}
	if !p0RelExists(t, ctx, db, eventpart.DailyName(day)) {
		t.Fatal("被挡下的退役不得动分区")
	}

	close(releaseRestore)
	select {
	case n := <-doneRestore:
		if rerr := <-restoreErr; rerr != nil || n != 2 {
			t.Fatalf("Restore 应完成（A/B 共 2 行），实际 %d / %v", n, rerr)
		}
	case <-time.After(time.Minute):
		t.Fatal("放行后 Restore 没有返回")
	}
	if !p0HotExists(t, ctx, db, a) || !p0HotExists(t, ctx, db, b) {
		t.Fatal("块间隙后恢复的 A/B 应在热表")
	}

	// 反向：retire 先持锁（按 janitor 协议拿着不放），restore 的会话锁排队
	holdTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holdTx.Rollback() }()
	if err := eventpart.LifecycleLockExclusive(ctx, holdTx, day); err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := Restore(rctx, db, runID, day); err == nil {
		t.Fatal("retire 持有同日排他锁期间，Restore 不应开始")
	}
	_ = holdTx.Rollback()

	// restore 幂等重跑（A 已在热表，插入 0）
	if _, err := Restore(ctx, db, runID, day); err != nil {
		t.Fatalf("锁释放后重跑 Restore: %v", err)
	}
	// 退役最终正常执行：pin 行并进月归档分区
	locked, retired, _, err = r12RetireLikeJanitor(t, ctx, db, day.AddDate(0, 0, 1), 1000)
	if err != nil || !locked {
		t.Fatalf("锁释放后退役应执行: locked=%v err=%v", locked, err)
	}
	if retired < 1 {
		t.Fatalf("应退役该日分区，实际 %d 个", retired)
	}
	if got := routingOf(t, ctx, db, pin); got != eventpart.ArchiveName(month) {
		t.Fatalf("pin 行应随退役并进 %s，实际 %s", eventpart.ArchiveName(month), got)
	}
}

// 会话级锁随连接消失（R2）：专用连接被杀（模拟 restore 中途进程/连接死亡）后，会话锁
// 立即随连接释放，后续操作能拿到同一把锁；正常 Release 路径也先解锁再还连接。
func TestR12SessionLockDiesWithConnection(t *testing.T) {
	ctx, client, db := p0Open(t)
	_ = client
	day := p0Day(t, ctx, db, 8)

	// 独立连接池：被杀的连接不会污染共享测试池
	lockDB, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lockDB.Close() })
	tryLock := func() bool {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		var ok bool
		if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtext($1))`,
			eventpart.LifecycleLockKey(day)).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}

	guard, err := LockDaySessionExclusive(ctx, lockDB, day)
	if err != nil {
		t.Fatalf("取会话级锁: %v", err)
	}
	if tryLock() {
		t.Fatal("会话锁持有期间，其它连接不应能取到同日排他锁")
	}
	// 正常释放：先显式 unlock 再 close，之后锁立即可取
	guard.Release()
	if !tryLock() {
		t.Fatal("Release 后锁应立即可取（先 unlock 再还连接）")
	}

	// 模拟中途连接被杀：锁随会话消失（terminate 的 FATAL 应答是预期结果，不是失败）
	guard, err = LockDaySessionExclusive(ctx, lockDB, day)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = guard.conn.ExecContext(context.Background(), `SELECT pg_terminate_backend(pg_backend_pid())`)
	if err := guard.Alive(ctx); err == nil {
		t.Fatal("连接被杀后 Alive 必须报告锁已不可用")
	}
	guard.Release() // unlock 失败 → 走终结后端路径，连接按坏连接丢弃
	if !tryLock() {
		t.Fatal("持锁连接死亡后会话锁应随连接释放，后续操作能拿到锁")
	}
}
