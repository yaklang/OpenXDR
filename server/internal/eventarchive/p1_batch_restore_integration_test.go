//go:build integration

// P1 批量恢复集成测试（COLD_ARCHIVE_EVOLUTION.SCRATCH.md §P1、§5.2 的 T10/T11/T12）。
// Restore 已改为「每块一次解码 + typed unnest 批量 INSERT + 块级事务」，本文件验收：
//
//   - T10 批量保真：seedDiverseDay 的行经 shadow+verify+swap 后整块批量恢复，逐字段等于
//     热表快照（NULL vs 空串、微秒精度、260 KiB unicode/转义 raw、同 ts 不同 id）；
//     swap 后新到行不动；evidenceSnapshot 前后一致（比内容不比 count）。
//   - 最大块：用 Shadow Options.ChunkEvents 造接近 MaxCount(8192) 条的单块，整块恢复
//     完整、字段正确（一次 INSERT 一个事务，不再逐行物化）。
//   - T11 中途失败与重跑：≥3 块的 run，第 2 块载荷改坏一个字节 → Restore 报错且错误带该
//     块 id；第 1 块的行已在热表（部分完成可见）、第 2 块 0 行无部分提交；恢复载荷后重跑
//     成功，总插入数等于预期；再跑插入 0。
//   - T12 重复恢复：稳定环境第二次 Restore 插 0（P0 已测逐条版，这里重申批量版）。
//
// 复用 p0_baseline_integration_test.go 的 fixture 与 helper（同包）。

package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

// p1VerifiedRun 按给定封块阈值跑影子归档并对拍通过：与 p0VerifiedRun 的差别只在
// ChunkEvents / ChunkBytes 可调，用于构造「单块接近上限」或「固定多块」的 run。
func p1VerifiedRun(t *testing.T, ctx context.Context, db *sql.DB, from, to time.Time, chunkEvents, chunkBytes int) uuid.UUID {
	t.Helper()
	runID, err := Shadow(ctx, db, Options{From: from, To: to, Classes: p0Classes, Sources: p0Sources,
		ChunkEvents: chunkEvents, ChunkBytes: chunkBytes, Confirm: true})
	if err != nil {
		t.Fatalf("影子归档失败: %v", err)
	}
	if err := Verify(ctx, db, runID); err != nil {
		t.Fatalf("对拍失败: %v", err)
	}
	return runID
}

// p1ChunkCount 数某 run 某日的块数，独立于被测代码的枚举路径。
func p1ChunkCount(t *testing.T, ctx context.Context, db *sql.DB, runID uuid.UUID, day time.Time) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM event_archive_chunks
 WHERE run_id = $1 AND day = $2`, runID, day).Scan(&n); err != nil {
		t.Fatalf("统计块数: %v", err)
	}
	return n
}

// T10 批量保真：seedDiverseDay 的全量行批量恢复后逐字段等于热表快照；swap 之后新写入的
// 行原样不动；稳定环境第二次恢复插入 0；证据关联内容（alerts / temporal_*）前后不变。
func TestP1BatchRestoreFieldFidelity(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)

	// 证据关联放在今天（不在被切换的那天），保证「不变」不是「本来就是空的」
	anchor := p0Event(t, ctx, client, p0Today().Add(time.Minute), 4001, "agent", `{"mark":"anchor"}`)
	p0SeedTemporalEvidence(t, ctx, db, anchor, p0Today().Add(time.Minute))

	f := seedDiverseDay(t, ctx, client, day)
	// 证据快照在全部播种（含 seedDiverseDay 自带的 pin 告警）之后取：之后 swap/restore 都不该动它
	evBefore := evidenceSnapshot(t, ctx, db)
	if evBefore["alerts"] == "" {
		t.Fatal("测试前提：证据快照不应为空")
	}
	all := f.allIDs()
	before := hotSnapshot(t, ctx, db, all)
	inScope := f.inScopeIDs()

	runID := p0VerifiedRun(t, ctx, db, day, day)
	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	for _, id := range inScope {
		if p0HotExists(t, ctx, db, id) {
			t.Fatalf("事件 %s 应已随 Swap 移出热表", id)
		}
	}
	// swap 之后、restore 之前写入同日新事件：批量恢复不该动它，也不该把它算进恢复集
	e := p0Event(t, ctx, client, day.Add(23*time.Hour), 4001, "agent", `{"mark":"E","conn":{"dst":"10.0.0.5:443"}}`)
	snapE := hotSnapshot(t, ctx, db, []uuid.UUID{e})

	n, err := Restore(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("批量 Restore: %v", err)
	}
	if n != int64(len(inScope)) {
		t.Fatalf("批量 Restore 应插入口径内 %d 条，实际 %d 条", len(inScope), n)
	}
	// 逐字段保真：NULL vs 空串、微秒精度、大 raw、同 ts 不同 id 都在这一句里比对
	assertHotEquals(t, ctx, db, all, before)
	assertHotEquals(t, ctx, db, []uuid.UUID{e}, snapE)
	for _, id := range append(append([]uuid.UUID{}, inScope...), e) {
		if got := routingOf(t, ctx, db, id); got != "events_p"+day.Format("20060102") {
			t.Fatalf("事件 %s 应路由回日分区，实际 %s", id, got)
		}
	}

	// T12：稳定环境（无并发清理）第二次恢复插入 0
	again, err := Restore(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("第二次批量 Restore: %v", err)
	}
	if again != 0 {
		t.Fatalf("第二次批量 Restore 应插入 0 行，实际 %d", again)
	}
	assertHotEquals(t, ctx, db, all, before)
	if evAfter := evidenceSnapshot(t, ctx, db); !sameMap(evAfter, evBefore) {
		t.Fatalf("批量恢复前后证据关联内容变化：\n前 %v\n后 %v", evBefore, evAfter)
	}
}

// 最大块：ChunkEvents=MaxCount 时整日 8192 条进一个块，一次解码 + 一条 INSERT 恢复完整。
// 块内混入字段边界行（全 NULL 可空列、空串、微秒 ts、260 KiB unicode raw），证明列映射在
// 最大块规模下同样保真；该块是单事务（T11 另测块级回滚，这里断言块数与往返内容）。
func TestP1BatchRestoreMaxChunk(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)

	// 8188 条用 SQL 侧生成（快），4 条边界特征行用 ent 写，合计正好 MaxCount 条
	if _, err := db.ExecContext(ctx, `INSERT INTO events (id, ts, class_uid, source, raw)
 SELECT gen_random_uuid(), $1::timestamptz + (g * interval '10 seconds'), 4001, 'agent',
        jsonb_build_object('mark','bulk','g',g,'conn',jsonb_build_object('dst','10.0.0.1:443'))
 FROM generate_series(1, $2) g`, day, MaxCount-4); err != nil {
		t.Fatalf("批量造事件: %v", err)
	}
	mk := func(ts time.Time) *ent.EventCreate {
		return client.Event.Create().SetTs(ts).SetClassUID(4001).SetSource("agent")
	}
	mk(day.Add(9 * time.Hour)).
		SetRaw(json.RawMessage(`{"mark":"allnull","conn":{"dst":"10.0.0.2:443"}}`)).SaveX(ctx)
	mk(day.Add(9*time.Hour + 1*time.Second)).SetUsername("").SetConnTuple("").
		SetRaw(json.RawMessage(`{"mark":"emptystrings"}`)).SaveX(ctx)
	mk(day.Add(9*time.Hour + 2*time.Second + 123456789*time.Nanosecond)).
		SetUsername("root").
		SetRaw(json.RawMessage(`{"mark":"nanots","ret":0}`)).SaveX(ctx)
	pad := strings.Repeat(`值\"\\😀\u0001\t`, 14000) // ≈260 KiB，与 P0 的 bigraw 同构
	mk(day.Add(9*time.Hour + 3*time.Second)).
		SetRaw(json.RawMessage(`{"mark":"bigraw","pad":"` + pad + `"}`)).SaveX(ctx)

	var ids []uuid.UUID
	rows, err := db.QueryContext(ctx, `SELECT id FROM events WHERE ts >= $1 AND ts < $2`, day, day.AddDate(0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(ids) != MaxCount {
		t.Fatalf("测试前提：该日应有 %d 条事件，实际 %d 条", MaxCount, len(ids))
	}
	before := hotSnapshot(t, ctx, db, ids)

	// ChunkEvents=MaxCount、ChunkBytes=MaxPlainLen：整日 8192 条封成一个块
	runID := p1VerifiedRun(t, ctx, db, day, day, MaxCount, MaxPlainLen)
	if got := p1ChunkCount(t, ctx, db, runID, day); got != 1 {
		t.Fatalf("测试前提：应恰好 1 个最大块，实际 %d 个", got)
	}
	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if got := p0PartitionRows(t, ctx, db, day); got != 0 {
		t.Fatalf("切换后该日分区应为空，实际 %d 行", got)
	}

	n, err := Restore(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("最大块批量 Restore: %v", err)
	}
	if n != MaxCount {
		t.Fatalf("最大块批量 Restore 应插入 %d 条，实际 %d 条", MaxCount, n)
	}
	assertHotEquals(t, ctx, db, ids, before)

	again, err := Restore(ctx, db, runID, day)
	if err != nil || again != 0 {
		t.Fatalf("第二次最大块 Restore 应插入 0 行，实际 (%d, %v)", again, err)
	}
}

// T11 中途失败与重跑：300 条 / 3 块的 run，把第 2 块 payload 改坏一个字节。
// 断言：Restore 报错且错误含第 2 块 id；第 1 块 100 行已在热表（部分完成可见）；
// 第 2 块 0 行无部分提交；恢复 payload 后重跑补齐剩余 200 行；再跑插入 0。
func TestP1BatchRestoreChunkFailureAndRerun(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)

	// 300 条 ts 严格递增（每秒一条）：扫描顺序确定，前/中/后 100 条分别落在 3 个块里
	const total, perChunk = 300, 100
	for i := 1; i <= total; i++ {
		client.Event.Create().SetTs(day.Add(time.Duration(i) * time.Second)).
			SetClassUID(4001).SetSource("agent").
			SetRaw(json.RawMessage(fmt.Sprintf(`{"mark":"f%04d","conn":{"dst":"10.0.0.1:443"}}`, i))).SaveX(ctx)
	}

	runID := p1VerifiedRun(t, ctx, db, day, day, perChunk, MaxPlainLen)
	if got := p1ChunkCount(t, ctx, db, runID, day); got != 3 {
		t.Fatalf("测试前提：应恰好 3 块，实际 %d 个", got)
	}
	chunkIDs, err := dayChunkIDs(ctx, db, runID, day)
	if err != nil || len(chunkIDs) != 3 {
		t.Fatalf("列出 3 个块 id: %v %v", chunkIDs, err)
	}
	// 每块的时间上界（ts 严格递增时它就是块内行集的判据）
	var lastTs [3]time.Time
	for i, id := range chunkIDs {
		if err := db.QueryRowContext(ctx, `SELECT last_ts FROM event_archive_chunks WHERE id = $1`, id).
			Scan(&lastTs[i]); err != nil {
			t.Fatalf("读第 %d 块 last_ts: %v", i+1, err)
		}
	}
	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if got := p0PartitionRows(t, ctx, db, day); got != 0 {
		t.Fatalf("切换后该日分区应为空，实际 %d 行", got)
	}

	// 改坏第 2 块 payload 的最后一个字节（zstd 帧尾是内容校验和，必然解码失败）
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

	n, err := Restore(ctx, db, runID, day)
	if err == nil {
		t.Fatalf("第 2 块损坏时 Restore 必须报错，实际成功插入 %d 条", n)
	}
	if !strings.Contains(err.Error(), chunkIDs[1].String()) {
		t.Fatalf("错误必须带第 2 块 id %s，实际：%v", chunkIDs[1], err)
	}
	if n != perChunk {
		t.Fatalf("部分完成：第 1 块的 %d 行应已提交并如实返回，实际 %d", perChunk, n)
	}
	// 第 1 块的行已在热表（部分完成可见）
	var firstHot int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE ts >= $1 AND ts <= $2`,
		day, lastTs[0]).Scan(&firstHot); err != nil {
		t.Fatal(err)
	}
	if firstHot != perChunk {
		t.Fatalf("第 1 块的 %d 行应已在热表，实际 %d 行", perChunk, firstHot)
	}
	// 第 2 块 0 行无部分提交：该日热行总数恰为 100（第 2、3 块都还没写）
	if got := p0PartitionRows(t, ctx, db, day); got != perChunk {
		t.Fatalf("失败后该日分区应只有第 1 块的 %d 行（无部分提交），实际 %d 行", perChunk, got)
	}

	// 恢复 payload 后重跑：补齐剩余 200 行，总插入 300
	payload[len(payload)-1] ^= 0xff
	if _, err := db.ExecContext(ctx, `UPDATE event_archive_chunks SET payload = $2 WHERE id = $1`,
		chunkIDs[1], payload); err != nil {
		t.Fatalf("恢复第 2 块 payload: %v", err)
	}
	n2, err := Restore(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("修复后重跑 Restore: %v", err)
	}
	if n2 != total-perChunk {
		t.Fatalf("重跑应补插 %d 条，实际 %d 条", total-perChunk, n2)
	}
	if got := p0PartitionRows(t, ctx, db, day); got != total {
		t.Fatalf("重跑后该日分区应有 %d 行，实际 %d 行", total, got)
	}
	// 再跑：主键幂等，插入 0
	n3, err := Restore(ctx, db, runID, day)
	if err != nil || n3 != 0 {
		t.Fatalf("修复后第三次 Restore 应插入 0 行，实际 (%d, %v)", n3, err)
	}
}
