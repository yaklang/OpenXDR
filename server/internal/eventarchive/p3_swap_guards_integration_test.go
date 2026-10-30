//go:build integration

// P3 集成测试：原子切换、证据保护与逐日记录（COLD_ARCHIVE_EVOLUTION.SCRATCH.md §P3、
// 5.2 节 T03–T06，V06/V07 的实现侧）。T01/T02/2f 的翻转在 p0_*.go 里。
//
// 并发用例全部用 channel 屏障确定性同步（swapTestHook 停在重写事务内的固定阶段），
// 不使用 sleep。专用测试库 openxdr_p0，与其它集成测试一样串行（-p 1）。
package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/internal/eventpart"
)

// p3DayRecords 解析 run.detail.days：P3 起的逐日切换记录（键为 UTC 日字符串）。
func p3DayRecords(t *testing.T, ctx context.Context, db *sql.DB, runID uuid.UUID) map[string]swapDayRecord {
	t.Helper()
	run, err := LoadRun(ctx, db, runID)
	if err != nil {
		t.Fatalf("读取 run %s: %v", runID, err)
	}
	var detail struct {
		Days map[string]swapDayRecord `json:"days"`
	}
	if err := json.Unmarshal(run.Detail, &detail); err != nil {
		t.Fatalf("解析 run %s 的 detail: %v（%s）", runID, err, run.Detail)
	}
	if detail.Days == nil {
		return map[string]swapDayRecord{}
	}
	return detail.Days
}

// p3Park 把 swapTestHook 配置成「停在指定阶段」：Swap 协程进到该阶段时 close(parked)
// 并阻塞，等测试 close(release) 后放行；其余阶段（含事务外的 prechecks_done）直接放行。
func p3Park(t *testing.T, stage string) (parked, release chan struct{}) {
	t.Helper()
	parked, release = make(chan struct{}), make(chan struct{})
	swapTestHook = func(s string, tx *sql.Tx) error {
		if s != stage {
			return nil
		}
		close(parked)
		<-release
		return nil
	}
	t.Cleanup(func() { swapTestHook = nil })
	return parked, release
}

// p3FailAt 把 swapTestHook 配置成「在指定阶段注入失败」；kill=true 时改为杀掉事务所在的
// 连接（模拟事务中途连接中断），并返回 nil 让后续语句/提交在断掉的连接上失败。
func p3FailAt(t *testing.T, stage string, kill bool) {
	t.Helper()
	swapTestHook = func(s string, tx *sql.Tx) error {
		if s != stage {
			return nil
		}
		if kill {
			_, _ = tx.ExecContext(context.Background(), `SELECT pg_terminate_backend(pg_backend_pid())`)
			return nil
		}
		return errors.New("p3 注入失败: " + s)
	}
	t.Cleanup(func() { swapTestHook = nil })
}

// p3IndependentConn 开一条与 Swap 的连接池完全独立的连接，模拟另一路并发写入方。
func p3IndependentConn(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// p3InjectPin 在独立连接上给事件建一条 alert 引用（PinnedIDs 的第一支）。
// 带 15 秒超时：SHARE 锁挡不住 alerts 的 INSERT，这里必须立刻成功；若被某种锁挡住，
// 用超时把「悄悄排队」变成明确的测试失败，而不是挂死测试。
func p3InjectPin(t *testing.T, conn *sql.DB, ts time.Time, id uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := conn.ExecContext(ctx, `INSERT INTO alerts (id, ts, rule_id, severity, event_id)
 VALUES (gen_random_uuid(), $1, 'p3-race', 4, $2)`, ts, id); err != nil {
		t.Fatalf("并发注入 pin（事件 %s）: %v", id, err)
	}
}

// p3RunSwap 在后台协程跑 Swap，返回结果通道（不吞错误）。
func p3RunSwap(ctx context.Context, db *sql.DB, runID uuid.UUID, day time.Time) <-chan p3SwapOutcome {
	done := make(chan p3SwapOutcome, 1)
	go func() {
		p, err := Swap(ctx, db, runID, day)
		done <- p3SwapOutcome{plan: p, err: err}
	}()
	return done
}

type p3SwapOutcome struct {
	plan SwapPlan
	err  error
}

func p3WaitSwap(t *testing.T, done <-chan p3SwapOutcome) p3SwapOutcome {
	t.Helper()
	select {
	case out := <-done:
		return out
	case <-time.After(time.Minute):
		t.Fatal("Swap 在放行后没有返回")
		return p3SwapOutcome{}
	}
}

// T03（pin 竞态，三时点中的两处注入）：swap 事务停在 after_copy（复制中，初检前）与
// before_replace（切换前，终检前），独立连接给「已计划移出的未 pin 行」建 alert。
// SHARE 锁只挡该日 events 的写入，挡不住 alerts 的并发 INSERT——pin 是否生效只能靠
// verify(tx) 在事务内重读 PinnedIDs 核对。断言：注入的 pin 让 verify 发现 keep 集合不符
// （应保留未保留，keep_missing），整个事务回滚，A/B 都留热、alert 完好指向热表行
// （无悬空证据）、alerts/temporal_* 快照不变、无暂存表残留、不写 detail.days。
// （三时点的第一处「确定 D 前」由 p0_counterexamples 的 T02 覆盖：钩子停在事务外
// prechecks_done，插入的行经锁内重读进入 H 而不进 D。）
func TestP3T03PinRaceRollsBackSwap(t *testing.T) {
	for _, stage := range []string{"after_copy", "before_replace"} {
		t.Run(stage, func(t *testing.T) {
			ctx, client, db := p0Open(t)
			day := p0Day(t, ctx, db, 8)
			// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
			t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
			p4SeedConsumed(t, ctx, db, day)
			a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
			b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
			runID := p0VerifiedRun(t, ctx, db, day, day)
			conn := p3IndependentConn(t)

			parked, release := p3Park(t, stage)
			done := p3RunSwap(ctx, db, runID, day)
			select {
			case <-parked:
			case <-time.After(time.Minute):
				select {
				case out := <-done:
					t.Fatalf("Swap 提前返回（没到注入阶段）: %v", out.err)
				default:
				}
				t.Fatal("Swap 没有停在注入阶段：阶段名或注入方式与实现不符")
			}

			// swap 事务此刻持有日分区 SHARE 锁；alerts 不受该锁影响，INSERT 立即成功——
			// 这正是必须在 verify(tx) 内重读 pin 的原因（本行若失败即 SHARE 锁错误地挡住了 alerts）。
			p3InjectPin(t, conn, day.Add(25*time.Minute), b)
			// 注入完成后的证据状态才是「并发写入方已提交」的基线：之后 swap 回滚不得动它
			evMid := evidenceSnapshot(t, ctx, db)
			close(release)

			out := p3WaitSwap(t, done)
			if out.err == nil || !strings.Contains(out.err.Error(), "keep_missing") {
				t.Fatalf("verify 应在 %s 阶段后的事务内重读中发现注入的 pin（keep_missing），实际 %v", stage, out.err)
			}
			if !strings.Contains(out.err.Error(), b.String()) {
				t.Fatalf("报错应列出应保留而未保留的 id %s：%v", b, out.err)
			}
			for _, id := range []uuid.UUID{a, b} {
				if !p0HotExists(t, ctx, db, id) {
					t.Fatalf("整体回滚后 %s 应仍在热表", id)
				}
			}
			var refs int64
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM alerts WHERE event_id = $1`, b).Scan(&refs); err != nil {
				t.Fatal(err)
			}
			if refs != 1 {
				t.Fatalf("注入的 pin 应原样保留且指向热表行（无悬空证据），实际 %d 条", refs)
			}
			if after := evidenceSnapshot(t, ctx, db); !sameMap(after, evMid) {
				t.Fatalf("回滚不得改动证据关联：\n注入后 %v\n回滚后 %v", evMid, after)
			}
			if got := p0PartitionRows(t, ctx, db, day); got != 2 {
				t.Fatalf("回滚后日分区应仍有 A、B 两行，实际 %d 行", got)
			}
			if p0RelExists(t, ctx, db, eventpart.DailyName(day)+"_rewrite") {
				t.Fatal("回滚后不该留下暂存表")
			}
			if days := p3DayRecords(t, ctx, db, runID); len(days) != 0 {
				t.Fatalf("失败回滚的切换不该写 detail.days，实际 %+v", days)
			}
		})
	}
}

// T04a（swap/swap 同日并发）：第二个 swap 必须被 advisory try 锁**立即明确拒绝**
// （不等待、不交错），第一个照常完成。选 try 锁而不是排队等待：分区重写是重操作，
// 排队只会放大锁窗口；不依赖 DDL 锁超时兜底（那要白等 3 秒）。
func TestP3T04ConcurrentSecondSwapRejected(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
	runID := p0VerifiedRun(t, ctx, db, day, day)

	parked, release := p3Park(t, "after_copy")
	done := p3RunSwap(ctx, db, runID, day)
	select {
	case <-parked:
	case <-time.After(time.Minute):
		t.Fatal("第一个 Swap 没有停在 after_copy")
	}

	// 第二个 swap：此刻第一个持有 advisory 事务锁，必须立即拒绝而不是排队
	if _, err := Swap(ctx, db, runID, day); err == nil || !strings.Contains(err.Error(), "拒绝并发执行") {
		t.Fatalf("同日第二个并发 swap 应被 advisory 锁明确拒绝，实际 %v", err)
	}
	close(release)
	if out := p3WaitSwap(t, done); out.err != nil {
		t.Fatalf("第一个 swap 应照常完成，实际 %v", out.err)
	}

	for _, id := range []uuid.UUID{a, b} {
		if p0HotExists(t, ctx, db, id) {
			t.Fatalf("事件 %s 应已随第一个 swap 移出热表", id)
		}
		if _, found, err := Locate(ctx, db, id); err != nil || !found {
			t.Fatalf("事件 %s 的冷副本必须可定位：found=%v err=%v", id, found, err)
		}
	}
	if got := p0PartitionRows(t, ctx, db, day); got != 0 {
		t.Fatalf("切换后日分区应为空，实际 %d 行", got)
	}
	if p0RelExists(t, ctx, db, eventpart.DailyName(day)+"_rewrite") {
		t.Fatal("不该留下暂存表")
	}
	days := p3DayRecords(t, ctx, db, runID)
	if len(days) != 1 {
		t.Fatalf("detail.days 应恰好记录一天，实际 %+v", days)
	}
	// 被拒绝的第二个 swap 之后重跑：幂等语义，报告无需操作
	if _, err := Swap(ctx, db, runID, day); err == nil || !strings.Contains(err.Error(), "无需切换") {
		t.Fatalf("已切完的日重跑 swap 应报告无需操作，实际 %v", err)
	}
}

// T04b（swap/restore 同日并发）：restore 的 INSERT 要拿该日分区的行级锁，与 swap 事务
// 的 SHARE 锁冲突 → restore 被**串行化**：持锁期间带超时地失败（观察到「进不去」而不是
// 悄悄排队），swap 提交后重跑 restore 幂等完成，不存在交错破坏。
func TestP3T04SwapAndRestoreSerialize(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
	runID := p0VerifiedRun(t, ctx, db, day, day)

	parked, release := p3Park(t, "after_copy")
	done := p3RunSwap(ctx, db, runID, day)
	select {
	case <-parked:
	case <-time.After(time.Minute):
		t.Fatal("Swap 没有停在 after_copy")
	}

	// swap 持锁期间 restore 进不去：短超时把「被挡住」变成明确结果
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := Restore(rctx, db, runID, day); err == nil {
		t.Fatal("swap 事务持有该日 SHARE 锁期间，restore 不应能插入（应被串行化挡住）")
	}
	close(release)
	if out := p3WaitSwap(t, done); out.err != nil {
		t.Fatalf("swap 应照常完成，实际 %v", out.err)
	}

	// swap 提交后 restore 正常完成：A/B 物化回热表
	n, err := Restore(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("swap 提交后 Restore: %v", err)
	}
	if n != 2 {
		t.Fatalf("应还原 A/B 共 2 条，实际 %d", n)
	}
	for _, id := range []uuid.UUID{a, b} {
		if !p0HotExists(t, ctx, db, id) {
			t.Fatalf("事件 %s 应回到热表", id)
		}
	}
	if got := p0PartitionRows(t, ctx, db, day); got != 2 {
		t.Fatalf("还原后日分区应有 2 行，实际 %d 行", got)
	}
}

// T04c（swap 与 janitor Retire 同日并发）：Retire 不取 advisory 锁——它自己的事务先对
// 日分区加 SHARE（与 swap 兼容），到 DETACH 需要排他锁时被 swap 的 SHARE 挡住，
// 3 秒锁超时后明确失败回滚；swap 提交后重跑 Retire 正常退役。两种顺序都不会产生
// 交错破坏：swap 先行时被移出的行都有冷副本，retire 只处理剩下的行。
func TestP3T04SwapAndRetireSerialize(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 40)
	// P4 闸门夹具前提(同上)
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
	done := p3RunSwap(ctx, db, runID, day)
	select {
	case <-parked:
	case <-time.After(time.Minute):
		t.Fatal("Swap 没有停在 before_replace")
	}

	// 并发退役：被 swap 的 SHARE 锁挡在 DETACH 上，锁超时后明确失败（无交错完成）
	retired, _, err := eventpart.Retire(ctx, db, day.AddDate(0, 0, 1))
	if err == nil {
		t.Fatal("swap 持锁期间 Retire 必须明确失败（锁超时），不能交错完成")
	}
	if retired != 0 {
		t.Fatalf("失败的 Retire 不应退役任何分区，实际 %d 个", retired)
	}
	close(release)
	if out := p3WaitSwap(t, done); out.err != nil {
		t.Fatalf("swap 应照常完成，实际 %v", out.err)
	}
	if !p0HotExists(t, ctx, db, pin) || p0HotExists(t, ctx, db, a) {
		t.Fatal("切换后应只有被 pin 的行留在热表")
	}

	// swap 提交后重跑退役：pin 行并进月归档分区，日分区消失
	retired2, dropped2, err := eventpart.Retire(ctx, db, day.AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("swap 提交后 Retire: %v", err)
	}
	if retired2 < 1 || dropped2 != 0 {
		t.Fatalf("应退役该日分区且不丢 pin 行（retired=%d dropped=%d）", retired2, dropped2)
	}
	if got := routingOf(t, ctx, db, pin); got != eventpart.ArchiveName(month) {
		t.Fatalf("pin 行应随退役并进 %s，实际 %s", eventpart.ArchiveName(month), got)
	}
}

// T05（失败注入）：复制后（after_copy）、索引构建后（after_indexes）、分区替换前
// （before_replace）注入错误，以及事务中途连接被杀——四种情况都必须整体回滚：
// 原分区行数与整行摘要不变、无暂存表残留、alerts/temporal_* 不变、不写 detail.days。
func TestP3T05FailuresRollBackAtomically(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage string
		kill  bool
	}{
		{"copy_failed", "after_copy", false},
		{"indexes_failed", "after_indexes", false},
		{"replace_failed", "before_replace", false},
		{"conn_killed_mid_tx", "before_replace", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, client, db := p0Open(t)
			day := p0Day(t, ctx, db, 8)
			// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
			t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
			p4SeedConsumed(t, ctx, db, day)
			a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
			b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
			runID := p0VerifiedRun(t, ctx, db, day, day)

			// 一条规则命中挂在会被移出的行上：派生状态清理发生在事务里，回滚必须原样留着它
			if _, err := db.ExecContext(ctx, `INSERT INTO temporal_rule_snapshots(revision, document) VALUES('p3','{}') ON CONFLICT DO NOTHING`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, `INSERT INTO temporal_matches(rule_id, event_id) VALUES('p3', $1)`, a); err != nil {
				t.Fatal(err)
			}
			ids := []uuid.UUID{a, b}
			beforeHot := hotSnapshot(t, ctx, db, ids)
			beforeEv := evidenceSnapshot(t, ctx, db)
			var matchesBefore int64
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM temporal_matches`).Scan(&matchesBefore); err != nil {
				t.Fatal(err)
			}

			p3FailAt(t, tc.stage, tc.kill)
			if _, err := Swap(ctx, db, runID, day); err == nil {
				t.Fatalf("%s：注入失败必须让 Swap 报错回滚", tc.name)
			}
			assertHotEquals(t, ctx, db, ids, beforeHot)
			if got := p0PartitionRows(t, ctx, db, day); got != 2 {
				t.Fatalf("%s：回滚后日分区应仍有 2 行，实际 %d 行", tc.name, got)
			}
			if p0RelExists(t, ctx, db, eventpart.DailyName(day)+"_rewrite") {
				t.Fatalf("%s：回滚后不该留下暂存表", tc.name)
			}
			if after := evidenceSnapshot(t, ctx, db); !sameMap(after, beforeEv) {
				t.Fatalf("%s：回滚不得改动证据关联：\n前 %v\n后 %v", tc.name, beforeEv, after)
			}
			var matchesAfter int64
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM temporal_matches`).Scan(&matchesAfter); err != nil {
				t.Fatal(err)
			}
			if matchesAfter != matchesBefore {
				t.Fatalf("%s：派生状态（temporal_matches）应原样保留：%d → %d", tc.name, matchesBefore, matchesAfter)
			}
			if days := p3DayRecords(t, ctx, db, runID); len(days) != 0 {
				t.Fatalf("%s：失败回滚不该写 detail.days，实际 %+v", tc.name, days)
			}

			// 故障排除后（摘掉钩子；连接被杀的用例先冲掉池里的坏连接）同一个 run 仍能正常切换
			swapTestHook = nil
			if tc.kill {
				if _, err := db.ExecContext(ctx, `SELECT 1`); err != nil {
					t.Fatalf("%s：冲洗连接池失败: %v", tc.name, err)
				}
			}
			if _, err := Swap(ctx, db, runID, day); err != nil {
				t.Fatalf("%s：故障排除后应能正常切换: %v", tc.name, err)
			}
			if got := p0PartitionRows(t, ctx, db, day); got != 0 {
				t.Fatalf("%s：重试后日分区应为空，实际 %d 行", tc.name, got)
			}
			days := p3DayRecords(t, ctx, db, runID)
			if len(days) != 1 {
				t.Fatalf("%s：重试成功后应恰好记一天，实际 %+v", tc.name, days)
			}
		})
	}
}

// T06（提交不确定）：单进程内无法真实模拟「COMMIT 已到达服务器、应答丢失」——驱动层的
// 提交与应答是一次不可拆分的调用；在事务内杀连接只能制造「提交未发出」（服务端按回滚
// 处理），无法制造「已提交但客户端不知道」。因此本条按 [读码记录] 文档化，并补一个
// 可执行的邻接用例（杀连接发生在记账之后、提交之前）：
//
//  1. RewriteDayGuarded 的 Commit 错误路径返回 (0, 0, err)，分区未变——代码路径见
//     eventpart/rewrite.go 末尾（提交失败即整体回滚，计数不当作已生效）；
//  2. 提交结果未知时，运维以持久事实对账：detail.days.<day>（与分区替换同事务，两者
//     必然一致）+ 分区实际行数 / plan 重查。detail.days 有记录且分区已瘦身 = 已提交；
//     两者不一致 = 未提交，可安全重试（重试要么报「无需操作」要么正常执行，
//     已提交的切换不会二次删除）。下方的成功路径断言就是这条对账路径本身。
func TestP3T06CommitUnknownDocumented(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
	runID := p0VerifiedRun(t, ctx, db, day, day)
	keep, err := keepSelect(day, mustRun(t, ctx, db, runID))
	if err != nil {
		t.Fatal(err)
	}

	// 邻接用例：记账完成后、提交前杀掉事务连接——Commit 在断掉的连接上失败。
	// 服务端没有收到提交，事务按回滚处理（这正是「提交未发出」一侧的可观测结果）。
	// 直接调 RewriteDayGuarded 是为了断言 (0,0,err) 的返回契约；观察点经 Observe 注入。
	p3FailAt(t, "after_record", true)
	hooks := eventpart.RewriteHooks{
		Observe: func(ctx context.Context, tx *sql.Tx, info eventpart.RewriteInfo, stage string) error {
			if swapTestHook == nil {
				return nil
			}
			return swapTestHook(stage, tx)
		},
	}
	kept, dropped, err := eventpart.RewriteDayGuarded(ctx, db, day, keep, hooks)
	if err == nil {
		t.Fatal("提交阶段连接断开必须返回错误")
	}
	if kept != 0 || dropped != 0 {
		t.Fatalf("提交失败路径必须返回 (0,0,err)，实际 kept=%d dropped=%d", kept, dropped)
	}
	swapTestHook = nil
	if _, err := db.ExecContext(ctx, `SELECT 1`); err != nil {
		t.Fatalf("冲洗连接池失败: %v", err)
	}
	if got := p0PartitionRows(t, ctx, db, day); got != 2 {
		t.Fatalf("未提交的切换不得生效：分区应仍有 2 行，实际 %d 行", got)
	}
	if days := p3DayRecords(t, ctx, db, runID); len(days) != 0 {
		t.Fatalf("未提交的记账不得出现，实际 %+v", days)
	}

	// 对账路径（生产处置入口）：成功提交后 detail.days 与分区实际状态必然一致
	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("重试应正常完成: %v", err)
	}
	days := p3DayRecords(t, ctx, db, runID)
	rec, ok := days[day.Format(time.DateOnly)]
	if !ok {
		t.Fatalf("成功提交后 detail.days 应有记录：%+v", days)
	}
	if rows := p0PartitionRows(t, ctx, db, day); rows != rec.Kept {
		t.Fatalf("对账失败：detail.days 记录保留 %d 行，分区实际 %d 行", rec.Kept, rows)
	}
	if rec.Dropped != 2 {
		t.Fatalf("应移出 A/B 共 2 行，实际 %d", rec.Dropped)
	}
	for _, id := range []uuid.UUID{a, b} {
		if p0HotExists(t, ctx, db, id) {
			t.Fatalf("事件 %s 应已移出热表", id)
		}
	}
}

// §P3 第 8 条：执行时没有可删事件（事务内 D 为空）必须明确报告「无需操作」且不重建分区。
// 两种到达方式：整天只剩没有冷副本的行（预检 Archived>0，事务内 D=∅）；以及成功切换后
// 重复执行（预检 Archived=0 快路径）。两者都不做 DETACH/DROP/RENAME/ATTACH。
func TestP3SwapNoopWhenNothingDroppable(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	// 该日只有一条超大（无冷副本）与一条类别外的行：预检 Archived=1，但 D=∅
	big := p0Event(t, ctx, client, day.Add(1*time.Minute), 4001, "agent",
		`{"blob":"`+strings.Repeat("x", MaxEventBytes)+`"}`)
	foreign := p0Event(t, ctx, client, day.Add(2*time.Minute), 1007, "agent", `{"mark":"foreign"}`)
	runID := p0VerifiedRun(t, ctx, db, day, day)
	ids := []uuid.UUID{big, foreign}
	before := hotSnapshot(t, ctx, db, ids)

	if _, err := Swap(ctx, db, runID, day); err == nil || !strings.Contains(err.Error(), "无需切换") {
		t.Fatalf("没有可删事件时应明确报告无需操作，实际 %v", err)
	}
	assertHotEquals(t, ctx, db, ids, before)
	if got := p0PartitionRows(t, ctx, db, day); got != 2 {
		t.Fatalf("无需操作的日不该重建分区，应仍有 2 行，实际 %d 行", got)
	}
	if p0RelExists(t, ctx, db, eventpart.DailyName(day)+"_rewrite") {
		t.Fatal("无需操作不该留下暂存表")
	}
	if days := p3DayRecords(t, ctx, db, runID); len(days) != 0 {
		t.Fatalf("无需操作不该写 detail.days，实际 %+v", days)
	}

	// 换一天正常切换成功后，重复执行同一日：快路径同样报告无需操作
	other := p0Day(t, ctx, db, 8)
	p4SeedConsumed(t, ctx, db, other)
	c := p0Event(t, ctx, client, other.Add(time.Minute), 4001, "agent", `{"mark":"C","conn":{"dst":"10.0.0.3:443"}}`)
	run2 := p0VerifiedRun(t, ctx, db, other, other)
	if _, err := Swap(ctx, db, run2, other); err != nil {
		t.Fatalf("正常切换: %v", err)
	}
	if p0HotExists(t, ctx, db, c) {
		t.Fatal("事件 C 应已移出热表")
	}
	if _, err := Swap(ctx, db, run2, other); err == nil || !strings.Contains(err.Error(), "无需切换") {
		t.Fatalf("重复 swap 应报告无需操作，实际 %v", err)
	}
	if days := p3DayRecords(t, ctx, db, run2); len(days) != 1 {
		t.Fatalf("重复 swap 不得重复记账，实际 %+v", days)
	}
}

// mustRun 是 p3 测试用的 run 读取捷径（错误即测试失败）。
func mustRun(t *testing.T, ctx context.Context, db *sql.DB, runID uuid.UUID) Run {
	t.Helper()
	run, err := LoadRun(ctx, db, runID)
	if err != nil {
		t.Fatal(err)
	}
	return run
}
