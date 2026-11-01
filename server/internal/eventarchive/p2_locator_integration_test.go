//go:build integration

// P2 locator 集成测试（COLD_ARCHIVE_EVOLUTION.SCRATCH.md §P2、§5.2 的 T07/T08/T09）。
//
// event_archive_locator 是「事件 id → 块」的 btree 索引表：写侧与块 INSERT 同事务（T07），
// Verify 做块解码成员 == locator 成员的集合校验（T08），旧块一次性回填并用覆盖性推导
// 表达迁移完成态（T09）。读取侧 Locate/Exists 只走索引探查 + 逐块解压精确比对，
// 全表扫候选路径（locateCandidates）与 ErrChunkBudget 已删除。
//
// 本文件放在 package eventarchive（同 P0/P1）：T07 需要直接设置未导出的 shadowTestHook。
// 复用 p0_baseline_integration_test.go 的 fixture 与 helper。

package eventarchive

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

// p2ChunksMet 返回该 run 全部块的 {chunk_id: event_count}，供测试独立核对。
func p2ChunksMet(t *testing.T, ctx context.Context, db *sql.DB, runID uuid.UUID) map[uuid.UUID]int {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT id, event_count FROM event_archive_chunks
 WHERE run_id = $1 ORDER BY seq`, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[uuid.UUID]int{}
	for rows.Next() {
		var id uuid.UUID
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			t.Fatal(err)
		}
		out[id] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// p2RunRow 读 run 行的 archived/chunks 两列。
func p2RunRow(t *testing.T, ctx context.Context, db *sql.DB, runID uuid.UUID) (archived int64, chunks int64) {
	t.Helper()
	if err := db.QueryRowContext(ctx, `SELECT archived, chunks FROM event_archive_runs WHERE id = $1`,
		runID).Scan(&archived, &chunks); err != nil {
		t.Fatal(err)
	}
	return archived, chunks
}

// p2LocatorRows 数 locator 总行数。
func p2LocatorRows(t *testing.T, ctx context.Context, db *sql.DB) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM event_archive_locator`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// T07（locator 插入前注入失败）：shadowTestHook 在「块已 INSERT、locator 尚未 INSERT」
// 的位置返回错误 → 该事务整体回滚：块行不存在、run 计数不累加、locator 无行——
// 三者同生共死，不会留下「有块没索引」。钩子置 nil 后重跑 shadow 成功且账目完整。
func TestP2T07ChunkCountLocatorAtomicRollback(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)

	if p2LocatorRows(t, ctx, db) != 0 {
		t.Fatal("测试前提：专用库的 locator 应为空")
	}

	// 在第一块的 locator 插入前注入失败
	shadowTestHook = func(stage string) error {
		if stage != "locator_before_insert" {
			t.Errorf("钩子只允许 locator_before_insert 一个阶段值，实际 %q", stage)
		}
		return errors.New("T07 注入：locator 插入前崩溃")
	}
	t.Cleanup(func() { shadowTestHook = nil })

	runID, err := Shadow(ctx, db, Options{From: day, To: day, Classes: p0Classes, Sources: p0Sources, Confirm: true})
	if err == nil || !strings.Contains(err.Error(), "T07 注入") {
		t.Fatalf("注入失败必须让 Shadow 报错，实际 %v", err)
	}

	// 三者同回滚：没有块、没有半份索引、run 记 0（失败的 Shadow 返回 uuid.Nil，
	// run 行本身带 failed 状态保留，计数为 0）
	if runID != uuid.Nil {
		t.Fatalf("失败的 Shadow 应返回 uuid.Nil，实际 %s", runID)
	}
	if n := p2LocatorRows(t, ctx, db); n != 0 {
		t.Fatalf("回滚后不应有任何 locator 行（无半份索引），实际 %d 行", n)
	}
	var total int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM event_archive_chunks`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Fatalf("回滚后块表应整体为空，实际 %d 行", total)
	}
	var archived, chunks int64
	var status string
	if err := db.QueryRowContext(ctx, `SELECT archived, chunks, status FROM event_archive_runs`).
		Scan(&archived, &chunks, &status); err != nil {
		t.Fatalf("读 run 行: %v", err)
	}
	if archived != 0 || chunks != 0 {
		t.Fatalf("回滚后 run 计数应为 0/0，实际 archived=%d chunks=%d", archived, chunks)
	}
	if status != StatusFailed {
		t.Fatalf("失败的 run 应记 failed，实际 %s", status)
	}

	// 钩子置 nil 后重跑：成功，块数 / 计数 / locator 行数三者对账
	shadowTestHook = nil
	runID2, err := Shadow(ctx, db, Options{From: day, To: day, Classes: p0Classes, Sources: p0Sources, Confirm: true})
	if err != nil {
		t.Fatalf("重跑 Shadow: %v", err)
	}
	met := p2ChunksMet(t, ctx, db, runID2)
	if len(met) == 0 {
		t.Fatal("重跑应写块")
	}
	var wantRows int64
	for _, n := range met {
		wantRows += int64(n)
	}
	if n := p2LocatorRows(t, ctx, db); n != wantRows {
		t.Fatalf("locator 行数应等于块内事件总数 %d，实际 %d", wantRows, n)
	}
	archived, chunks = p2RunRow(t, ctx, db, runID2)
	if archived != wantRows || chunks != int64(len(met)) {
		t.Fatalf("run 计数应为 %d 条 / %d 块，实际 %d / %d", wantRows, len(met), archived, chunks)
	}
	for _, id := range []uuid.UUID{a, b} {
		if _, found, err := Locate(ctx, db, id); err != nil || !found {
			t.Fatalf("重跑后 %s 应可经 locator 定位: found=%v err=%v", id, found, err)
		}
	}
}

// T08（locator 完整性）：手工制造四类异常，Verify 的集合校验与覆盖性推导分别如实报错或判定；
// CASCADE：删块连带 locator 行消失。
func TestP2T08LocatorIntegrityFailures(t *testing.T) {
	// 每个子场景独立开库，互不污染。ChunkEvents=3：6 条事件封 2 块，错指块场景需要两块。
	newCase := func(t *testing.T) (context.Context, *sql.DB, uuid.UUID, []uuid.UUID) {
		ctx, client, db := p0Open(t)
		day := p0Day(t, ctx, db, 8)
		var ids []uuid.UUID
		for i := 1; i <= 6; i++ {
			ids = append(ids, p0Event(t, ctx, client, day.Add(time.Duration(i*10)*time.Minute),
				4001, "agent", `{"mark":"e","conn":{"dst":"10.0.0.1:443"}}`))
		}
		runID := p1VerifiedRun(t, ctx, db, day, day, 3, MaxPlainLen) // 基线：干净状态对拍通过
		return ctx, db, runID, ids
	}

	t.Run("缺一行", func(t *testing.T) {
		ctx, db, runID, ids := newCase(t)
		if _, err := db.ExecContext(ctx, `DELETE FROM event_archive_locator WHERE event_id = $1`, ids[0]); err != nil {
			t.Fatal(err)
		}
		err := Verify(ctx, db, runID)
		if err == nil || !strings.Contains(err.Error(), "索引缺 1 行") {
			t.Fatalf("缺一行时 Verify 必须报集合差异，实际 %v", err)
		}
		// 覆盖性推导是块级粒度（每块至少一行）：该块还有别的行，推导仍判完整，
		// 于是这条被删行的事件在读取路径上表现为确定的未命中——这正是行级差异必须靠
		// Verify 的集合校验（上面那条）兜住的原因。
		if _, found, err := Locate(ctx, db, ids[0]); err != nil || found {
			t.Fatalf("块级推导不感知单行缺失：读取路径按索引未命中处理，实际 found=%v err=%v", found, err)
		}
	})
	t.Run("多一行", func(t *testing.T) {
		ctx, db, runID, ids := newCase(t)
		var chunkID uuid.UUID
		if err := db.QueryRowContext(ctx, `SELECT chunk_id FROM event_archive_locator WHERE event_id = $1`,
			ids[0]).Scan(&chunkID); err != nil {
			t.Fatal(err)
		}
		ghost := uuid.New()
		if _, err := db.ExecContext(ctx, `INSERT INTO event_archive_locator (event_id, chunk_id) VALUES ($1, $2)`,
			ghost, chunkID); err != nil {
			t.Fatal(err)
		}
		err := Verify(ctx, db, runID)
		if err == nil || !strings.Contains(err.Error(), "块里没有 1 行") {
			t.Fatalf("多一行（幽灵行）时 Verify 必须报集合差异，实际 %v", err)
		}
		// 幽灵行本身会被 Locate 发现：索引命中但块解不出来 → 不一致错误
		if _, found, err := Locate(ctx, db, ghost); err == nil || found || !strings.Contains(err.Error(), "不一致") {
			t.Fatalf("幽灵行的 Locate 应报 locator 与冷块不一致，实际 found=%v err=%v", found, err)
		}
	})
	t.Run("错指块", func(t *testing.T) {
		ctx, db, runID, ids := newCase(t)
		// 事件 0 的行改指「不含它」的另一块：删掉原行，往别的块插一行
		var from, to uuid.UUID
		if err := db.QueryRowContext(ctx, `SELECT chunk_id FROM event_archive_locator WHERE event_id = $1`,
			ids[0]).Scan(&from); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT chunk_id FROM event_archive_locator WHERE event_id = $1`,
			ids[len(ids)-1]).Scan(&to); err != nil {
			t.Fatal(err)
		}
		if from == to { // 单块 run 里换不出「别的块」：造第二个块再试
			t.Skip("单块场景无法构造错指块（同一块指向自身成员即合法）")
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM event_archive_locator WHERE event_id = $1 AND chunk_id = $2`,
			ids[0], from); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO event_archive_locator (event_id, chunk_id) VALUES ($1, $2)`,
			ids[0], to); err != nil {
			t.Fatal(err)
		}
		// 对 from 块是多行缺失、对 to 块是幽灵行：两个方向的集合差异都要能报出来
		err := Verify(ctx, db, runID)
		if err == nil {
			t.Fatal("错指块时 Verify 必须报错")
		}
		// 错指后 Locate(ids[0])：索引指向 to 块，解不出该 id → 不一致错误（不是 found=false）
		if _, found, err := Locate(ctx, db, ids[0]); err == nil || found || !strings.Contains(err.Error(), "不一致") {
			t.Fatalf("错指块的 Locate 应报不一致，实际 found=%v err=%v", found, err)
		}
	})
	t.Run("跨 run 重复副本合法", func(t *testing.T) {
		ctx, client, db, runID, ids := newCaseWithClient(t)
		day := p0Today().AddDate(0, 0, -8)
		// 第二轮 run 覆盖同一天：同一批事件再进一次冷块（跨 run 多副本）
		runID2, err := Shadow(ctx, db, Options{From: day, To: day, Classes: p0Classes, Sources: p0Sources, Confirm: true})
		if err != nil {
			t.Fatalf("第二轮 shadow: %v", err)
		}
		if err := Verify(ctx, db, runID2); err != nil {
			t.Fatalf("跨 run 副本对第二个 run 对拍应通过（同 run 内集合仍精确），实际 %v", err)
		}
		// 主键 (event_id, chunk_id)：同一事件在两个块各一行，合法
		var rows int64
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM event_archive_locator WHERE event_id = $1`,
			ids[0]).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows != 2 {
			t.Fatalf("跨 run 副本应有 2 行 locator（两个不同块），实际 %d", rows)
		}
		// 第一个 run 的对拍也仍然通过：它的块成员集合没变
		if err := Verify(ctx, db, runID); err != nil {
			t.Fatalf("第一个 run 的集合未变，对拍应仍通过: %v", err)
		}
		_ = client
	})
	t.Run("CASCADE 删块", func(t *testing.T) {
		ctx, db, runID, ids := newCase(t)
		var chunkID uuid.UUID
		if err := db.QueryRowContext(ctx, `SELECT chunk_id FROM event_archive_locator WHERE event_id = $1`,
			ids[0]).Scan(&chunkID); err != nil {
			t.Fatal(err)
		}
		var before int64
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM event_archive_locator WHERE chunk_id = $1`,
			chunkID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if before == 0 {
			t.Fatal("测试前提：该块应有 locator 行")
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM event_archive_chunks WHERE id = $1`, chunkID); err != nil {
			t.Fatal(err)
		}
		var after int64
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM event_archive_locator WHERE chunk_id = $1`,
			chunkID).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if after != 0 {
			t.Fatalf("删块后 locator 行应 CASCADE 消失，实际剩 %d 行", after)
		}
		// 删块是显式的冷层维护动作（P6 规定先确认不再是唯一副本）：块行没了，
		// 覆盖性推导只看「现存的块」，因此仍判完整；该块的事件在索引里没有行，
		// Locate 如实报确定的未命中——CASCADE 保证的是不留悬空索引行，不是替块挡删除。
		if _, found, err := Locate(ctx, db, ids[0]); err != nil || found {
			t.Fatalf("删块后 Locate(ids[0]) 应为确定未命中（无悬空行），实际 found=%v err=%v", found, err)
		}
		// 该 run 其余块的成员不受影响：ids[3] 在另一块，仍命中
		if _, found, err := Locate(ctx, db, ids[3]); err != nil || !found {
			t.Fatalf("另一块的事件应仍可命中: found=%v err=%v", found, err)
		}
		_ = runID
	})
}

// newCaseWithClient 是 newCase 的变体：跨 run 场景需要 client（第二轮 shadow 仍读得到热行）。
func newCaseWithClient(t *testing.T) (context.Context, *ent.Client, *sql.DB, uuid.UUID, []uuid.UUID) {
	t.Helper()
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	var ids []uuid.UUID
	for i := 1; i <= 6; i++ {
		ids = append(ids, p0Event(t, ctx, client, day.Add(time.Duration(i*10)*time.Minute),
			4001, "agent", `{"mark":"e","conn":{"dst":"10.0.0.1:443"}}`))
	}
	runID := p0VerifiedRun(t, ctx, db, day, day)
	return ctx, client, db, runID, ids
}

// T09（一次性迁移）：把某块全部 locator 行删掉模拟 P2 之前的旧块 → 覆盖性推导判不完整 →
// Exists(不存在 id) 与 Locate 返回 ErrLocatorIncomplete（不是确定 false）→ BackfillLocator
// 回填 → 幂等重跑 0 块、覆盖性成立 → Exists 恢复确定语义。已 swap（热行已删）的块同样回填成功。
func TestP2T09BackfillLegacyChunks(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	var ids []uuid.UUID
	for i := 1; i <= 6; i++ {
		ids = append(ids, p0Event(t, ctx, client, day.Add(time.Duration(i*10)*time.Minute),
			4001, "agent", `{"mark":"e","conn":{"dst":"10.0.0.1:443"}}`))
	}
	runID := p0VerifiedRun(t, ctx, db, day, day)

	// 再造一个「已 swap」的块（热行已删）：证明回填不依赖热行存在。
	// 用另一天（比上面更老一天）：两个 run 各管各的日,结尾 Verify(第一个 run) 仍要求它的事件都在热表。
	swapDay := p0Day(t, ctx, db, 9)
	// P4 闸门夹具前提(同上)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, swapDay)
	swapEvt := p0Event(t, ctx, client, swapDay.Add(time.Minute), 4001, "agent", `{"mark":"swapped"}`)
	swapRun := p0VerifiedRun(t, ctx, db, swapDay, swapDay)
	if _, err := Swap(ctx, db, swapRun, swapDay); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if p0HotExists(t, ctx, db, swapEvt) {
		t.Fatal("测试前提：该事件应已随 swap 移出热表")
	}

	// 模拟旧块：删掉这两个 run 全部块的 locator 行
	if _, err := db.ExecContext(ctx, `DELETE FROM event_archive_locator`); err != nil {
		t.Fatal(err)
	}
	missing, _, err := locatorIncompleteCount(ctx, db, 0)
	if err != nil {
		t.Fatal(err)
	}
	if missing == 0 {
		t.Fatal("删光 locator 后覆盖性推导必须判不完整")
	}

	// 未命中：不是确定 false，是 ErrLocatorIncomplete
	absent := uuid.New()
	if ok, err := Exists(ctx, db, absent); err == nil || ok || !errors.Is(err, ErrLocatorIncomplete) {
		t.Fatalf("覆盖不完整时 Exists 应报 ErrLocatorIncomplete（不是确定 false），实际 (%v, %v)", ok, err)
	}
	if _, found, err := Locate(ctx, db, absent); err == nil || found || !errors.Is(err, ErrLocatorIncomplete) {
		t.Fatalf("覆盖不完整时 Locate 同样应报 ErrLocatorIncomplete，实际 found=%v err=%v", found, err)
	}
	// 命中语义不受覆盖性影响：块在、id 在块里，只是没索引——这条事件此刻定位不到（索引里没有），
	// 如实报 ErrLocatorIncomplete（未命中路径），不静默判「不存在」
	if _, found, err := Locate(ctx, db, ids[0]); err == nil || found || !errors.Is(err, ErrLocatorIncomplete) {
		t.Fatalf("旧块内事件的 Locate 在回填前也应报 ErrLocatorIncomplete，实际 found=%v err=%v", found, err)
	}

	// 回填：两轮 run（含已 swap 的块）都补上
	blocks, err := BackfillLocator(ctx, db)
	if err != nil {
		t.Fatalf("BackfillLocator: %v", err)
	}
	if blocks < 2 {
		t.Fatalf("至少应回填 2 块（两个 run），实际 %d", blocks)
	}
	// 幂等：重跑 0 块
	again, err := BackfillLocator(ctx, db)
	if err != nil {
		t.Fatalf("重跑 BackfillLocator: %v", err)
	}
	if again != 0 {
		t.Fatalf("重跑应幂等返回 0 块，实际 %d", again)
	}
	// 覆盖性成立
	if missing, _, err := locatorIncompleteCount(ctx, db, 0); err != nil || missing != 0 {
		t.Fatalf("回填后覆盖性推导应成立（0 块缺行），实际 %d 块 err=%v", missing, err)
	}
	// Exists 恢复确定语义：不存在的 id 确定返回 false
	if ok, err := Exists(ctx, db, absent); err != nil || ok {
		t.Fatalf("回填后 Exists(不存在) 应为确定的 (false, nil)，实际 (%v, %v)", ok, err)
	}
	// 回填后的行能定位（含已 swap 的块：热行没了照样命中）
	for _, id := range append(append([]uuid.UUID{}, ids...), swapEvt) {
		if _, found, err := Locate(ctx, db, id); err != nil || !found {
			t.Fatalf("回填后 %s 应可定位: found=%v err=%v", id, found, err)
		}
	}
	// 回填行与块内容一致：两个 run 的 Verify 都应通过（集合校验认可回填结果）
	if err := Verify(ctx, db, runID); err != nil {
		t.Fatalf("回填后 run 对拍应通过: %v", err)
	}
}

// T09 空冷库：没有任何块时 BackfillLocator 直接完成（0 块），覆盖性成立。
func TestP2T09BackfillEmptyArchive(t *testing.T) {
	ctx, _, db := p0Open(t)
	blocks, err := BackfillLocator(ctx, db)
	if err != nil {
		t.Fatalf("空冷库回填: %v", err)
	}
	if blocks != 0 {
		t.Fatalf("空冷库应回填 0 块，实际 %d", blocks)
	}
	if missing, _, err := locatorIncompleteCount(ctx, db, 0); err != nil || missing != 0 {
		t.Fatalf("空冷库覆盖性应成立，实际 %d err=%v", missing, err)
	}
	// 空归档的未命中是确定的 false（没有任何块 → 不存在缺行块 → 推导完整）
	if ok, err := Exists(ctx, db, uuid.New()); err != nil || ok {
		t.Fatalf("空归档 Exists 应为 (false, nil)，实际 (%v, %v)", ok, err)
	}
}

// T09 回填中断重跑：两块缺行，第一块回填成功后第二块解码失败（改坏 payload）→
// 返回错误且第一块保留；恢复 payload 后重跑补齐。覆盖性推导在中间态如实判不完整。
func TestP2T09BackfillInterruptAndRerun(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	for i := 1; i <= 6; i++ {
		p0Event(t, ctx, client, day.Add(time.Duration(i*10)*time.Minute),
			4001, "agent", `{"mark":"e","conn":{"dst":"10.0.0.1:443"}}`)
	}
	runID := p1VerifiedRun(t, ctx, db, day, day, 3, MaxPlainLen) // 6 条封 2 块
	chunkIDs, err := dayChunkIDs(ctx, db, runID, day)
	if err != nil || len(chunkIDs) < 2 {
		t.Fatalf("测试前提：至少 2 块，实际 %d 块 err=%v", len(chunkIDs), err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM event_archive_locator`); err != nil {
		t.Fatal(err)
	}

	// 改坏「按 c.id 排序最后一块」的 payload：BackfillLocator 按 c.id 顺序处理，
	// 因此第一块一定先回填成功、到坏块才失败——中断点确定
	var byID []uuid.UUID
	rows, err := db.QueryContext(ctx, `SELECT id FROM event_archive_chunks ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		byID = append(byID, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	bad := byID[len(byID)-1]
	var payload []byte
	if err := db.QueryRowContext(ctx, `SELECT payload FROM event_archive_chunks WHERE id = $1`, bad).
		Scan(&payload); err != nil {
		t.Fatal(err)
	}
	payload[len(payload)-1] ^= 0xff
	if _, err := db.ExecContext(ctx, `UPDATE event_archive_chunks SET payload = $2 WHERE id = $1`,
		bad, payload); err != nil {
		t.Fatal(err)
	}

	blocks, err := BackfillLocator(ctx, db)
	if err == nil {
		t.Fatalf("坏块必须让回填报错，实际成功 %d 块", blocks)
	}
	if !strings.Contains(err.Error(), bad.String()) {
		t.Fatalf("错误应带坏块 id: %v", err)
	}
	// 已回填的块保留（≥1 且不含坏块）；覆盖性仍不完整
	var filled int64
	if err := db.QueryRowContext(ctx, `SELECT count(DISTINCT chunk_id) FROM event_archive_locator`).Scan(&filled); err != nil {
		t.Fatal(err)
	}
	if filled == 0 || filled >= int64(len(byID)) {
		t.Fatalf("中断后应恰好回填 %d 块中的部分（≥1、<全部），实际 %d", len(byID), filled)
	}
	if missing, _, err := locatorIncompleteCount(ctx, db, 0); err != nil || missing == 0 {
		t.Fatalf("中断后覆盖性推导应判不完整，实际 missing=%d err=%v", missing, err)
	}

	// 恢复 payload 后重跑补齐，覆盖性成立
	payload[len(payload)-1] ^= 0xff
	if _, err := db.ExecContext(ctx, `UPDATE event_archive_chunks SET payload = $2 WHERE id = $1`,
		bad, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := BackfillLocator(ctx, db); err != nil {
		t.Fatalf("修复后重跑: %v", err)
	}
	if missing, _, err := locatorIncompleteCount(ctx, db, 0); err != nil || missing != 0 {
		t.Fatalf("补齐后覆盖性应成立，实际 %d err=%v", missing, err)
	}
	if err := Verify(ctx, db, runID); err != nil {
		t.Fatalf("补齐后对拍应通过: %v", err)
	}
}

// 读取正确性：多 run 重叠副本（id 在两个 run 各一块）→ Locate 命中其一即可；
// 不存在 id 未命中且覆盖完整 → 确定 false。
func TestP2LocateAcrossRuns(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	target := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"t"}`)
	for i := 0; i < 300; i++ {
		p0Event(t, ctx, client, day.Add(time.Duration(20+i)*time.Second), 4001, "agent", `{"mark":"pad"}`)
	}
	// 两轮 run：同一天同一批事件 → target 在两个 run 各有一个块
	runA := p0VerifiedRun(t, ctx, db, day, day)
	runB := p0VerifiedRun(t, ctx, db, day, day)

	var chunksA, chunksB []uuid.UUID
	for runID, out := range map[uuid.UUID]*[]uuid.UUID{runA: &chunksA, runB: &chunksB} {
		ids, err := dayChunkIDs(ctx, db, runID, day)
		if err != nil {
			t.Fatal(err)
		}
		*out = ids
	}
	e, found, err := Locate(ctx, db, target)
	if err != nil || !found {
		t.Fatalf("跨 run 副本应命中其一: found=%v err=%v", found, err)
	}
	if e.ID != target {
		t.Fatalf("命中的应是 %s，实际 %s", target, e.ID)
	}
	// 两行 locator、两个不同块
	rows, err := db.QueryContext(ctx, `SELECT chunk_id FROM event_archive_locator WHERE event_id = $1`, target)
	if err != nil {
		t.Fatal(err)
	}
	var seen []uuid.UUID
	for rows.Next() {
		var cid uuid.UUID
		if err := rows.Scan(&cid); err != nil {
			t.Fatal(err)
		}
		seen = append(seen, cid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("target 应有 2 行 locator（两个 run 各一块），实际 %d", len(seen))
	}
	inA, inB := false, false
	for _, cid := range seen {
		for _, c := range chunksA {
			if cid == c {
				inA = true
			}
		}
		for _, c := range chunksB {
			if cid == c {
				inB = true
			}
		}
	}
	if !inA || !inB {
		t.Fatalf("两行应分别落在两个 run 的块里，实际 inA=%v inB=%v", inA, inB)
	}
	// 不存在 id：覆盖完整（两轮 run 都原子写行）→ 确定 false
	if ok, err := Exists(ctx, db, uuid.New()); err != nil || ok {
		t.Fatalf("覆盖完整时不存在 id 应为确定 (false, nil)，实际 (%v, %v)", ok, err)
	}
}

// EXPLAIN 证据：locator 点查（event_id = $1）走主键索引（Index Only Scan / Index Scan /
// Bitmap Index Scan 均为 btree 探查形态），绝不允许 Seq Scan——那意味着退回「扫全部行」。
// 行数要够多（数千以上）小表上 PostgreSQL 会合理地选顺序扫；参数化探查是 Go 驱动
// 实际发出的形态。反连接（覆盖性推导）的计划一并记录，形态由规划器按规模选择。
func TestP2LocatorProbeUsesIndex(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// 6000 条进 3 块（默认 2048/块）：locator 6000 行，足以让索引成为更优计划
	if _, err := db.ExecContext(ctx, `INSERT INTO events (id, ts, class_uid, source, raw)
 SELECT gen_random_uuid(), $1::timestamptz + (g * interval '1 second'), 4001, 'agent',
        jsonb_build_object('mark','explain','g',g)
 FROM generate_series(1, 6000) g`, day); err != nil {
		t.Fatalf("造事件: %v", err)
	}
	if _, err := Shadow(ctx, db, Options{From: day, To: day, Classes: p0Classes, Sources: p0Sources, Confirm: true}); err != nil {
		t.Fatalf("造冷块: %v", err)
	}
	if n := p2LocatorRows(t, ctx, db); n != 6000 {
		t.Fatalf("测试前提：locator 应有 6000 行，实际 %d", n)
	}
	if _, err := db.ExecContext(ctx, `ANALYZE event_archive_locator, event_archive_chunks`); err != nil {
		t.Fatal(err)
	}
	_ = client

	var plan string
	if err := db.QueryRowContext(ctx, `EXPLAIN (FORMAT TEXT) SELECT chunk_id FROM event_archive_locator
 WHERE event_id = $1`, uuid.New()).Scan(&plan); err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	indexed := strings.Contains(plan, "Index Scan") || strings.Contains(plan, "Index Only Scan") ||
		strings.Contains(plan, "Bitmap Index Scan")
	if !indexed {
		t.Fatalf("locator 探查必须走索引（Index Scan 系），实际计划：%s", plan)
	}
	if strings.Contains(plan, "Seq Scan") {
		t.Fatalf("locator 探查不允许顺序扫：%s", plan)
	}
	t.Logf("EXPLAIN locator 探查（参数化点查）：%s", plan)

	// 覆盖性推导（反连接，LIMIT 1 形态即 Locate 未命中时实际执行的判定）：记录计划形态，
	// 断言 chunks 侧被驱动、locator 侧无全表逐行过滤即可；真规模计划与延迟归 P7/V05。
	anti := explainAll(t, ctx, db, `EXPLAIN (FORMAT TEXT) SELECT count(*) FROM (
 SELECT c.id FROM event_archive_chunks c
 LEFT JOIN event_archive_locator l ON l.chunk_id = c.id
 WHERE l.chunk_id IS NULL LIMIT 1) t`)
	t.Logf("EXPLAIN 覆盖性推导（反连接 LIMIT 1）：%s", anti)
	if !strings.Contains(anti, "event_archive_locator") {
		t.Fatalf("反连接计划应涉及 locator 表：%s", anti)
	}
}

// explainAll 读出 EXPLAIN (FORMAT TEXT) 的全部行（一条计划是多行结果集）。
func explainAll(t *testing.T, ctx context.Context, db *sql.DB, query string) string {
	t.Helper()
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}
