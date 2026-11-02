//go:build integration

package eventarchive_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/internal/eventarchive"
	"openxdr/server/internal/testdb"
)

// open 连测试库、建冷归档表并清空它。events 等业务表由 testdb 清。
func open(t *testing.T) (context.Context, *ent.Client, *sql.DB) {
	t.Helper()
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clean(t, ctx, db)
	return ctx, client, db
}

func clean(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	// 拆掉可能残留的月归档分区（events_aYYYYMM 跨整月，会挡住要建的历史日分区）。
	// 已知来源：janitor 集成测试的 t.Cleanup 里 DROP，但其 defer db.Close() 先于 cleanup
	// 执行而静默失败；本包对共享测试库的残留自身免疫（与 p0Open 同一口径）。
	if _, err := db.ExecContext(ctx, `DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT c.relname FROM pg_class c JOIN pg_inherits i ON c.oid=i.inhrelid
  WHERE i.inhparent='events'::regclass AND c.relname LIKE 'events_a%' LOOP
  EXECUTE format('DROP TABLE IF EXISTS %I', r.relname);
 END LOOP; END $$`); err != nil {
		t.Fatalf("清理残留月归档分区: %v", err)
	}
	for _, table := range []string{"event_archive_chunks", "event_archive_runs"} {
		if _, err := db.ExecContext(ctx, `DELETE FROM `+table); err != nil {
			t.Fatalf("清空 %s: %v", table, err)
		}
	}
}

// fixture 是一轮影子归档的输入：两天、两个来源、一个被告警钉住的事件、一条类别外事件、
// 一条超大事件。
type fixture struct {
	day1, day2 time.Time
	archived   []uuid.UUID // 4001/4003，应当被归档
	pinned     uuid.UUID   // 4001 但被 alerts.event_id 引用，必须跳过
	foreign    uuid.UUID   // 1007，类别之外
	oversized  uuid.UUID   // 4001 但编码后超过 4 MiB，跳过并计数
}

func seed(t *testing.T, ctx context.Context, client *ent.Client) fixture {
	t.Helper()
	day1 := eventpartToday().AddDate(0, 0, -1)
	day2 := eventpartToday()
	f := fixture{day1: day1, day2: day2}
	add := func(ts time.Time, class int, source, raw string) uuid.UUID {
		t.Helper()
		e := client.Event.Create().SetTs(ts).SetClassUID(class).SetSource(source).SetRaw(json.RawMessage(raw)).SaveX(ctx)
		return e.ID
	}
	f.archived = []uuid.UUID{
		add(day1.Add(1*time.Minute), 4001, "agent", `{"conn": {"dst": "10.0.0.1:443"}, "sni": "例子.测试", "ret": 0}`),
		add(day1.Add(2*time.Minute), 4001, "agent", `{"conn": {"dst": "10.0.0.2:80"}, "bytes": 1024}`),
		add(day1.Add(3*time.Minute), 4001, "sensor", `{"conn": {"dst": "10.0.0.3:53"}, "dns": {"qname": "a.b"}}`),
		add(day2.Add(1*time.Minute), 4003, "agent", `{"file": {"path": "/tmp/中文文件名"}, "op": "create"}`),
		add(day2.Add(2*time.Minute), 4003, "agent", `{"file": {"path": "/tmp/x"}, "op": "delete"}`),
		add(day2.Add(3*time.Minute), 4001, "sensor", `{"conn": {"dst": "10.0.0.4:443"},  "tls": {"sni": "e.f"}}`),
	}
	f.pinned = add(day1.Add(4*time.Minute), 4001, "agent", `{"conn": {"dst": "10.0.0.9:22"}, "pinned": true}`)
	f.foreign = add(day1.Add(5*time.Minute), 1007, "agent", `{"process": {"pid": 42}}`)
	f.oversized = add(day2.Add(4*time.Minute), 4001, "agent",
		`{"blob": "`+strings.Repeat("x", eventarchive.MaxEventBytes)+`"}`)
	// 钉住：告警引用这条 4001，冷归档必须跳过它
	if _, err := client.Alert.Create().SetTs(day1.Add(4 * time.Minute)).SetRuleID("test-pin").SetSeverity(3).
		SetEventID(f.pinned).Save(ctx); err != nil {
		t.Fatal(err)
	}
	return f
}

// eventpartToday 与 eventpart.Today 同口径：UTC 当天零点，分区预建覆盖当天与之后几天。
func eventpartToday() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

func dayOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func shadow(t *testing.T, ctx context.Context, db *sql.DB, f fixture) uuid.UUID {
	t.Helper()
	runID, err := eventarchive.Shadow(ctx, db, eventarchive.Options{
		From: f.day1, To: f.day2, Classes: []int{4001, 4003}, Confirm: true,
	})
	if err != nil {
		t.Fatalf("影子归档失败: %v", err)
	}
	return runID
}

// 8. EnsureSchema 连续两次都成功（幂等），第二次不报错也不丢数据。
func TestEnsureSchemaIdempotent(t *testing.T) {
	ctx, _, db := open(t)
	for i := 0; i < 2; i++ {
		if err := eventarchive.EnsureSchema(ctx, db); err != nil {
			t.Fatalf("第 %d 次 EnsureSchema 失败: %v", i+1, err)
		}
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM event_archive_chunks`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("新表应为空，实际 %d 行", n)
	}
}

// 不加 -confirm 一律拒绝，连 run 行都不建。
func TestShadowRequiresConfirm(t *testing.T) {
	ctx, _, db := open(t)
	_, err := eventarchive.Shadow(ctx, db, eventarchive.Options{
		From: eventpartToday(), To: eventpartToday(), Classes: []int{4001},
	})
	if err == nil || !strings.Contains(err.Error(), "确认") {
		t.Fatalf("没有 -confirm 必须拒绝，实际 %v", err)
	}
	var runs int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM event_archive_runs`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("被拒绝的请求不应留下 run 行，实际 %d 行", runs)
	}
}

// 9. 影子构建：类别内且没被钉住的进冷块，被钉住与类别外的不进，超大事件单独计数。
func TestShadowSkipsPinnedAndOtherClasses(t *testing.T) {
	ctx, client, db := open(t)
	f := seed(t, ctx, client)
	runID := shadow(t, ctx, db, f)

	run, err := eventarchive.LoadRun(ctx, db, runID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != eventarchive.StatusBuilding {
		t.Fatalf("构建后状态应保持 building（等对拍），实际 %s", run.Status)
	}
	if run.Archived != int64(len(f.archived)) {
		t.Fatalf("archived 应为 %d，实际 %d", len(f.archived), run.Archived)
	}
	if run.PinnedSkip != 1 {
		t.Fatalf("pinned_skipped 应为 1，实际 %d", run.PinnedSkip)
	}
	// 候选 = 6 条归档 + 1 条钉住 + 1 条超大；1007 不在类别内，不计
	if run.Scanned != 8 {
		t.Fatalf("scanned 应为 8，实际 %d", run.Scanned)
	}
	if run.Chunks == 0 {
		t.Fatal("应至少写出一块")
	}

	var detail struct {
		Oversized    int64    `json:"oversized"`
		OversizedIDs []string `json:"oversized_ids"`
		Scanned      int64    `json:"scanned"`
	}
	if err := json.Unmarshal(run.Detail, &detail); err != nil {
		t.Fatalf("解析 detail: %v", err)
	}
	if detail.Oversized != 1 || len(detail.OversizedIDs) != 1 || detail.OversizedIDs[0] != f.oversized.String() {
		t.Fatalf("超大事件应记进 detail.oversized 与 oversized_ids，实际 %+v", detail)
	}
	if detail.Scanned != 8 {
		t.Fatalf("detail 里应记录 scanned=8，实际 %d", detail.Scanned)
	}

	archivedIDs := decodeChunkIDs(t, ctx, db, runID)
	for _, id := range f.archived {
		if !archivedIDs[id] {
			t.Fatalf("事件 %s 应被归档，实际不在冷块里", id)
		}
	}
	for name, id := range map[string]uuid.UUID{"钉住": f.pinned, "类别外": f.foreign, "超大": f.oversized} {
		if archivedIDs[id] {
			t.Fatalf("%s事件 %s 不应进冷块", name, id)
		}
	}
}

// decodeChunkIDs 解开所有冷块，返回块里的事件 id 集合；顺带核对块的列与内容自洽。
func decodeChunkIDs(t *testing.T, ctx context.Context, db *sql.DB, runID uuid.UUID) map[uuid.UUID]bool {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT seq, day, class_uid, source, first_ts, last_ts, event_count,
 format, codec, plain_len, payload_len, plain_sha256, payload
 FROM event_archive_chunks WHERE run_id = $1 ORDER BY seq`, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	ids := map[uuid.UUID]bool{}
	for rows.Next() {
		var (
			seq, class, count    int
			source               string
			day                  time.Time
			first, last          time.Time
			format, codec        int16
			plainLen, payloadLen int64
			sha, payload         []byte
		)
		if err := rows.Scan(&seq, &day, &class, &source, &first, &last, &count,
			&format, &codec, &plainLen, &payloadLen, &sha, &payload); err != nil {
			t.Fatal(err)
		}
		if int64(len(payload)) != payloadLen {
			t.Fatalf("第 %d 块 payload_len 记 %d，实际 %d", seq, payloadLen, len(payload))
		}
		block := eventarchive.Block{Format: uint8(format), Codec: uint8(codec), Count: count,
			PlainLen: plainLen, Payload: payload}
		copy(block.PlainSHA256[:], sha)
		events, err := block.Decode()
		if err != nil {
			t.Fatalf("第 %d 块解码失败: %v", seq, err)
		}
		if len(events) != count {
			t.Fatalf("第 %d 块声明 %d 条，解出 %d 条", seq, count, len(events))
		}
		for _, e := range events {
			if e.ClassUID != int64(class) || e.Source != source {
				t.Fatalf("第 %d 块里的 %s 是 %d/%s，与块上的 %d/%s 不符", seq, e.ID, e.ClassUID, e.Source, class, source)
			}
			if day := dayOf(e.Ts); !day.Equal(dayOf(first)) {
				t.Fatalf("第 %d 块里的事件 %s 属于 %s，不在块上的 %s", seq, e.ID, day.Format(time.DateOnly), dayOf(first).Format(time.DateOnly))
			}
			ids[e.ID] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}

// 10. 对拍：全字段一致才算过；payload 被改一个字节必须失败。
func TestVerifyPassesAndCatchesCorruption(t *testing.T) {
	ctx, client, db := open(t)
	f := seed(t, ctx, client)
	runID := shadow(t, ctx, db, f)

	if err := eventarchive.Verify(ctx, db, runID); err != nil {
		t.Fatalf("对拍应通过，实际 %v", err)
	}
	run, err := eventarchive.LoadRun(ctx, db, runID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != eventarchive.StatusVerified {
		t.Fatalf("对拍通过后状态应为 verified，实际 %s", run.Status)
	}

	// 改坏第一块的载荷：翻一个字节
	res, err := db.ExecContext(ctx, `UPDATE event_archive_chunks
 SET payload = set_byte(payload, 4, (get_byte(payload, 4) + 1) % 256)
 WHERE run_id = $1 AND seq = (SELECT min(seq) FROM event_archive_chunks WHERE run_id = $1)`, runID)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("应改坏 1 块，实际 %d", n)
	}
	err = eventarchive.Verify(ctx, db, runID)
	if err == nil {
		t.Fatal("载荷被改坏后对拍必须失败")
	}
	if !strings.Contains(err.Error(), "块") {
		t.Fatalf("错误信息要能定位到块，实际 %v", err)
	}
}

// 影子构建之后又写进新事件：对拍必须报「候选集已变化」，不能误报成编码错误。
func TestVerifyReportsCandidateChange(t *testing.T) {
	ctx, client, db := open(t)
	f := seed(t, ctx, client)
	runID := shadow(t, ctx, db, f)

	if _, err := client.Event.Create().SetTs(f.day2.Add(10 * time.Minute)).SetClassUID(4001).
		SetSource("agent").SetRaw(json.RawMessage(`{"late": true}`)).Save(ctx); err != nil {
		t.Fatal(err)
	}
	err := eventarchive.Verify(ctx, db, runID)
	if err == nil {
		t.Fatal("候选集变了，对拍必须失败")
	}
	if !strings.Contains(err.Error(), "候选集已变化，请重新运行") {
		t.Fatalf("错误信息应说明候选集已变化，实际 %v", err)
	}
}

// 单条超过 ChunkBytes 但没超单条上限的事件必须单独成块，不能和别的事件挤在一块。
func TestShadowKeepsBigEventInOwnChunk(t *testing.T) {
	ctx, client, db := open(t)
	day := eventpartToday()
	client.Event.Create().SetTs(day.Add(time.Minute)).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"blob":"` + strings.Repeat("y", 1536*1024) + `"}`)).SaveX(ctx)
	client.Event.Create().SetTs(day.Add(2 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"conn": {"dst": "1.2.3.4"}}`)).SaveX(ctx)

	runID, err := eventarchive.Shadow(ctx, db, eventarchive.Options{
		From: day, To: day, Classes: []int{4001}, Confirm: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.QueryContext(ctx, `SELECT event_count, plain_len FROM event_archive_chunks
 WHERE run_id = $1 ORDER BY seq`, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type chunkInfo struct {
		count int
		plain int64
	}
	var got []chunkInfo
	for rows.Next() {
		var c chunkInfo
		if err := rows.Scan(&c.count, &c.plain); err != nil {
			t.Fatal(err)
		}
		got = append(got, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("应封成 2 块（1.5 MiB 的事件自己一块），实际 %+v", got)
	}
	if got[0].count != 1 || got[0].plain <= eventarchive.DefaultChunkBytes {
		t.Fatalf("第一块应只有那条超过 1 MiB 的事件，实际 %+v", got[0])
	}
	if got[1].count != 1 {
		t.Fatalf("第二块应只有小事件，实际 %+v", got[1])
	}
	if err := eventarchive.Verify(ctx, db, runID); err != nil {
		t.Fatalf("大事件单独成块后对拍仍应通过: %v", err)
	}
}

// 11. events 一行都不能动：影子归档前后 count、整行字节与 raw 摘要完全一致。
func TestShadowLeavesEventsUntouched(t *testing.T) {
	ctx, client, db := open(t)
	f := seed(t, ctx, client)
	before := eventsDigest(t, ctx, db)
	runID := shadow(t, ctx, db, f)
	after := eventsDigest(t, ctx, db)
	if before != after {
		t.Fatalf("影子归档改动了 events：\n前 %s\n后 %s", before, after)
	}
	// 再跑一次对拍与度量，events 仍必须一致
	if err := eventarchive.Verify(ctx, db, runID); err != nil {
		t.Fatal(err)
	}
	if _, err := eventarchive.Measure(ctx, db, runID); err != nil {
		t.Fatal(err)
	}
	if again := eventsDigest(t, ctx, db); again != before {
		t.Fatalf("对拍/度量改动了 events：\n前 %s\n后 %s", before, again)
	}
}

func eventsDigest(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()
	var n, bytes int64
	var digest string
	if err := db.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(pg_column_size(e.*)), 0),
 COALESCE(md5(string_agg(e.id::text || ':' || md5(e.raw::text), ',' ORDER BY e.id)), '')
 FROM events e`).Scan(&n, &bytes, &digest); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("count=%d rowbytes=%d digest=%s", n, bytes, digest)
}

// 12. 度量：数字来自真实查询，ratio 与手工 sum(plain_len)/sum(payload_len) 一致。
func TestReportNumbers(t *testing.T) {
	ctx, client, db := open(t)
	f := seed(t, ctx, client)
	runID := shadow(t, ctx, db, f)
	if err := eventarchive.Verify(ctx, db, runID); err != nil {
		t.Fatal(err)
	}
	r, err := eventarchive.Measure(ctx, db, runID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Archive.Chunks == 0 || r.Archive.Events != int64(len(f.archived)) {
		t.Fatalf("冷归档应有 %d 条事件，实际 %+v", len(f.archived), r.Archive)
	}
	if r.Archive.PlainBytes <= 0 || r.Archive.PayloadBytes <= 0 {
		t.Fatalf("明文与载荷字节应为正数，实际 %+v", r.Archive)
	}
	if r.Archive.ChunkTotalBytes <= 0 || r.Archive.ChunkDataBytes <= 0 {
		t.Fatalf("冷归档表大小应来自真实查询，实际 %+v", r.Archive)
	}
	var plain, payload int64
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(sum(plain_len), 0), COALESCE(sum(payload_len), 0)
 FROM event_archive_chunks WHERE run_id = $1`, runID).Scan(&plain, &payload); err != nil {
		t.Fatal(err)
	}
	if plain != r.Archive.PlainBytes || payload != r.Archive.PayloadBytes {
		t.Fatalf("度量与手工汇总不一致：plain %d/%d payload %d/%d",
			plain, r.Archive.PlainBytes, payload, r.Archive.PayloadBytes)
	}
	if want := float64(plain) / float64(payload); math.Abs(r.Archive.Ratio-want) > 1e-9 {
		t.Fatalf("ratio 应为 %.6f，实际 %.6f", want, r.Archive.Ratio)
	}
	if r.Live.Events != int64(len(f.archived)) {
		t.Fatalf("被归档事件应仍在 events 里（阶段 A 不删），实际 %d", r.Live.Events)
	}
	if r.Live.Missing != 0 {
		t.Fatalf("阶段 A 不删 events，missing 应为 0，实际 %d", r.Live.Missing)
	}
	if r.Live.RowBytes <= 0 {
		t.Fatalf("sum(pg_column_size) 应大于 0，实际 %d", r.Live.RowBytes)
	}
	if len(r.Live.Partitions) != 2 {
		t.Fatalf("两天的数据应列出 2 个日分区，实际 %+v", r.Live.Partitions)
	}
	exists := false
	for _, p := range r.Live.Partitions {
		if p.Exists {
			exists = true
			if p.Bytes <= 0 || p.Rows <= 0 {
				t.Fatalf("日分区 %s 的行数与大小应来自真实查询，实际 %+v", p.Name, p)
			}
		}
	}
	if exists && r.Live.PartitionBytes <= 0 {
		t.Fatalf("整分区口径合计应大于 0，实际 %d", r.Live.PartitionBytes)
	}
	out := r.String()
	for _, want := range []string{"压缩比", "含 TOAST 与索引", "整分区口径", "event_archive_chunks"} {
		if !strings.Contains(out, want) {
			t.Fatalf("度量输出缺少 %q:\n%s", want, out)
		}
	}
	t.Logf("\n%s", out)
}
