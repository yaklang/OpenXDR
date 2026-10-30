//go:build integration

package eventarchive_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/eventarchive"
)

// 与真实冷块验证阶段 B2：按 ID 定位（Locate / Exists）与证据物化（Materialize）。
// Bloom filter 的零漏报与假阳性率由 lookup_test.go 覆盖（无 DB），这里要验的是
// 「写进库的 filter 与块内容对得上」、候选顺序/预算/坏块的行为，以及物化的幂等与零副作用。

// locateFixture 是按 ID 定位的语料：一条字段全填的事件（资产、进程、父进程、用户名、连接元组）、
// 一条可空字段全 NULL 的事件、一条别的来源。
type locateFixture struct {
	day      time.Time
	full     uuid.UUID
	nullable uuid.UUID
	other    uuid.UUID
}

func seedLocate(t *testing.T, ctx context.Context, client *ent.Client) locateFixture {
	t.Helper()
	day := eventpartToday().AddDate(0, 0, -1)
	asset := client.Asset.Create().SetHostname("loc-asset").SaveX(ctx)
	proc, parent := uuid.New(), uuid.New()
	user, conn := "root", "10.0.0.1:50000>10.0.0.2:443"
	full := client.Event.Create().SetTs(day.Add(time.Minute)).SetClassUID(4001).SetSource("agent").
		SetAssetID(asset.ID).SetProcessGUID(proc).SetParentProcessGUID(parent).
		SetUsername(user).SetConnTuple(conn).
		SetRaw(json.RawMessage(`{"conn": {"dst": "10.0.0.2:443"}, "tls": {"sni": "例子.测试"}}`)).
		SaveX(ctx)
	nullable := client.Event.Create().SetTs(day.Add(2 * time.Minute)).SetClassUID(4003).SetSource("agent").
		SetRaw(json.RawMessage(`{"file": {"path": "/tmp/中文文件名"}, "op": "create"}`)).SaveX(ctx)
	other := client.Event.Create().SetTs(day.Add(3 * time.Minute)).SetClassUID(4001).SetSource("sensor").
		SetRaw(json.RawMessage(`{"conn": {"dst": "10.0.0.3:53"}}`)).SaveX(ctx)
	return locateFixture{day: day, full: full.ID, nullable: nullable.ID, other: other.ID}
}

// locateShadow 归档 locateFixture 那一天，返回 run id。
func locateShadow(t *testing.T, ctx context.Context, db *sql.DB, day time.Time) uuid.UUID {
	t.Helper()
	runID, err := eventarchive.Shadow(ctx, db, eventarchive.Options{
		From: day, To: day, Classes: []int{4001, 4003}, Confirm: true,
	})
	if err != nil {
		t.Fatalf("影子归档失败: %v", err)
	}
	return runID
}

// assertSameEvent 逐字段比对冷块里的事件与 events 里的行。raw 逐字节比（两边都是 jsonb 文本）。
func assertSameEvent(t *testing.T, got eventarchive.Event, want *ent.Event) {
	t.Helper()
	if got.ID != want.ID {
		t.Fatalf("id 不一致：冷块 %s，events %s", got.ID, want.ID)
	}
	if !got.Ts.Equal(want.Ts) {
		t.Fatalf("ts 不一致：冷块 %s，events %s", got.Ts.Format(time.RFC3339Nano), want.Ts.Format(time.RFC3339Nano))
	}
	if got.ClassUID != int64(want.ClassUID) {
		t.Fatalf("class_uid 不一致：冷块 %d，events %d", got.ClassUID, want.ClassUID)
	}
	if got.Source != want.Source {
		t.Fatalf("source 不一致：冷块 %q，events %q", got.Source, want.Source)
	}
	if !sameUUIDPtr(got.AssetID, want.AssetID) {
		t.Fatalf("asset_id 不一致：冷块 %s，events %s", uuidText(got.AssetID), uuidText(want.AssetID))
	}
	if !sameUUIDPtr(got.ProcessGUID, want.ProcessGUID) {
		t.Fatalf("process_guid 不一致：冷块 %s，events %s", uuidText(got.ProcessGUID), uuidText(want.ProcessGUID))
	}
	if !sameUUIDPtr(got.ParentProcessGUID, want.ParentProcessGUID) {
		t.Fatalf("parent_process_guid 不一致：冷块 %s，events %s",
			uuidText(got.ParentProcessGUID), uuidText(want.ParentProcessGUID))
	}
	if !sameStrPtr(got.Username, want.Username) {
		t.Fatalf("username 不一致：冷块 %s，events %s", strText(got.Username), strText(want.Username))
	}
	if !sameStrPtr(got.ConnTuple, want.ConnTuple) {
		t.Fatalf("conn_tuple 不一致：冷块 %s，events %s", strText(got.ConnTuple), strText(want.ConnTuple))
	}
	if string(got.Raw) != string(want.Raw) {
		t.Fatalf("raw 不是逐字节相同：\n冷块 %s\nevents %s", got.Raw, want.Raw)
	}
}

func sameUUIDPtr(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameStrPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func uuidText(id *uuid.UUID) string {
	if id == nil {
		return "NULL"
	}
	return id.String()
}

func strText(s *string) string {
	if s == nil {
		return "NULL"
	}
	return *s
}

// assertBloomCoversChunks 逐个解开冷块，断言 id_bloom 覆盖了块里的每一条事件：
// 这是「写进库的 filter 与块内容对得上」的直接证据（列顺序错、filter 写错块都会在这里露）。
// 返回检查过的块数。
func assertBloomCoversChunks(t *testing.T, ctx context.Context, db *sql.DB) int {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT id, event_count, format, codec, plain_len, payload_len,
 plain_sha256, payload, id_bloom FROM event_archive_chunks ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	chunks, events := 0, 0
	for rows.Next() {
		var (
			id                   uuid.UUID
			count                int
			format, codec        int16
			plainLen, payloadLen int64
			sha, payload, bloom  []byte
		)
		if err := rows.Scan(&id, &count, &format, &codec, &plainLen, &payloadLen, &sha, &payload, &bloom); err != nil {
			t.Fatal(err)
		}
		if bloom == nil {
			t.Fatalf("新写的冷块 %s 没有 id_bloom：按 ID 定位会退化成全表解压", id)
		}
		block := eventarchive.Block{Format: uint8(format), Codec: uint8(codec), Count: count,
			PlainLen: plainLen, Payload: payload}
		copy(block.PlainSHA256[:], sha)
		items, err := block.Decode()
		if err != nil {
			t.Fatalf("冷块 %s 解码失败: %v", id, err)
		}
		for _, e := range items {
			if !eventarchive.MayContainID(bloom, e.ID) {
				t.Fatalf("冷块 %s 的 id_bloom 漏掉了自己块里的事件 %s", id, e.ID)
			}
			events++
		}
		chunks++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if chunks == 0 || events == 0 {
		t.Fatalf("没有冷块可检查：chunks=%d events=%d", chunks, events)
	}
	return chunks
}

// 5. Locate 命中：影子归档后按 ID 找到，全字段与原事件逐字段一致；新块都带 filter；
// 加列不影响 B1 的 Query 与阶段 A 的 Verify。
func TestLocateFindsArchivedEvent(t *testing.T) {
	ctx, client, db := open(t)
	f := seedLocate(t, ctx, client)
	runID := locateShadow(t, ctx, db, f.day)

	for name, id := range map[string]uuid.UUID{"字段全填": f.full, "可空字段全 NULL": f.nullable, "另一个来源": f.other} {
		t.Run(name, func(t *testing.T) {
			got, found, err := eventarchive.Locate(ctx, db, id)
			if err != nil {
				t.Fatalf("定位失败: %v", err)
			}
			if !found {
				t.Fatalf("事件 %s 已归档，应能定位到", id)
			}
			want, err := client.Event.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			assertSameEvent(t, got, want)
			// Exists 的口径必须与 Locate 一致
			if ok, err := eventarchive.Exists(ctx, db, id); err != nil || !ok {
				t.Fatalf("Exists 应为 (true, nil)，实际 (%v, %v)", ok, err)
			}
		})
	}

	chunks := assertBloomCoversChunks(t, ctx, db)
	t.Logf("检查了 %d 块冷块，filter 覆盖块内全部事件", chunks)

	// B1 的 Query 与阶段 A 的对拍都不受新增列影响
	if events, _, err := eventarchive.Query(ctx, db, eventarchive.Filter{IDs: []uuid.UUID{f.full}}); err != nil {
		t.Fatalf("B1 的 Query 按 ID 查仍然要能用: %v", err)
	} else if len(events) != 1 || events[0].ID != f.full {
		t.Fatalf("B1 的 Query 应返回 1 条，实际 %v", events)
	}
	if err := eventarchive.Verify(ctx, db, runID); err != nil {
		t.Fatalf("加了 id_bloom 之后对拍仍应通过: %v", err)
	}
}

// 6. Locate 未命中：返回 found=false, err=nil；表在但没有块、表不存在分别按「没有」与
// ErrNoSchema 处理，都不该伪装成「查过、没有」。
func TestLocateMissingEvent(t *testing.T) {
	ctx, client, db := open(t)
	f := seedLocate(t, ctx, client)
	locateShadow(t, ctx, db, f.day)

	absent := uuid.New()
	got, found, err := eventarchive.Locate(ctx, db, absent)
	if err != nil {
		t.Fatalf("冷层没有这条事件不该报错: %v", err)
	}
	if found || got.ID != uuid.Nil {
		t.Fatalf("不存在的 id 应返回 (零值, false)，实际 %+v found=%v", got, found)
	}
	if ok, err := eventarchive.Exists(ctx, db, absent); err != nil || ok {
		t.Fatalf("Exists 应为 (false, nil)，实际 (%v, %v)", ok, err)
	}

	// 表在、但一块冷块都没有：同样是「确实没有」
	clean(t, ctx, db)
	if _, found, err := eventarchive.Locate(ctx, db, f.full); err != nil || found {
		t.Fatalf("空归档应返回 (false, nil)，实际 found=%v err=%v", found, err)
	}

	// 表都不存在（没跑过 ensure-schema）：部署状态，报 ErrNoSchema 而不是 found=false
	if _, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS event_archive_locator, event_archive_chunks, event_archive_runs`); err != nil {
		t.Fatal(err)
	}
	if _, found, err := eventarchive.Locate(ctx, db, f.full); !errors.Is(err, eventarchive.ErrNoSchema) {
		t.Fatalf("没有冷归档表时应报 ErrNoSchema，实际 found=%v err=%v", found, err)
	}
	if _, err := eventarchive.Exists(ctx, db, f.full); !errors.Is(err, eventarchive.ErrNoSchema) {
		t.Fatalf("Exists 同样应报 ErrNoSchema，实际 %v", err)
	}
}

// 7. 老块（id_bloom 为 NULL，阶段 B2 之前写的）照样能按 ID 命中：没有过滤器就解压后精确比对。
func TestLocateLegacyChunkWithoutBloom(t *testing.T) {
	ctx, client, db := open(t)
	f := seedLocate(t, ctx, client)
	locateShadow(t, ctx, db, f.day)

	if _, err := db.ExecContext(ctx, `UPDATE event_archive_chunks SET id_bloom = NULL`); err != nil {
		t.Fatal(err)
	}
	var withBloom int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM event_archive_chunks WHERE id_bloom IS NOT NULL`).
		Scan(&withBloom); err != nil {
		t.Fatal(err)
	}
	if withBloom != 0 {
		t.Fatalf("应已把全部冷块置为老块，实际仍有 %d 块带 filter", withBloom)
	}

	got, found, err := eventarchive.Locate(ctx, db, f.nullable)
	if err != nil {
		t.Fatalf("老块没有 filter 不该报错: %v", err)
	}
	if !found {
		t.Fatal("老块没有 filter 时必须解压后精确比对，不能直接判为不存在")
	}
	want, err := client.Event.Get(ctx, f.nullable)
	if err != nil {
		t.Fatal(err)
	}
	assertSameEvent(t, got, want)
	// 老块的 filter 是 NULL，MayContainID 的语义是「必须解压」
	if !eventarchive.MayContainID(nil, uuid.New()) {
		t.Fatal("nil filter 必须让所有块进入候选")
	}
}

// 8. 块损坏：整体报错并带块 id，绝不返回 found=false——那会把「读不出来」说成「不存在」。
func TestLocateCorruptChunk(t *testing.T) {
	ctx, client, db := open(t)
	f := seedLocate(t, ctx, client)
	locateShadow(t, ctx, db, f.day)

	// 目标 id 的 locator 行指向哪块就改坏哪块：索引命中后必须解压校验，坏块一定被碰到
	var chunkID uuid.UUID
	if err := db.QueryRowContext(ctx, `SELECT chunk_id FROM event_archive_locator WHERE event_id = $1`,
		f.other).Scan(&chunkID); err != nil {
		t.Fatalf("读 %s 的 locator 行: %v", f.other, err)
	}
	// 改坏该块载荷：翻 payload 第 5 个字节
	if _, err := db.ExecContext(ctx, `UPDATE event_archive_chunks
 SET payload = set_byte(payload, 4, (get_byte(payload, 4) + 1) % 256) WHERE id = $1`, chunkID); err != nil {
		t.Fatal(err)
	}

	got, found, err := eventarchive.Locate(ctx, db, f.other)
	if err == nil {
		t.Fatalf("块损坏必须返回错误，实际 found=%v", found)
	}
	if found {
		t.Fatalf("块损坏时不能返回命中，实际 %+v", got)
	}
	if !strings.Contains(err.Error(), chunkID.String()) {
		t.Fatalf("错误里应带坏块 id %s: %v", chunkID, err)
	}
	if errors.Is(err, eventarchive.ErrLocatorIncomplete) {
		t.Fatalf("坏块不是索引覆盖问题: %v", err)
	}
}

// 9. 索引行与载荷不一致（改块不并行）：locator 说事件在这块里，块解出来却没有——
// 必须报错而不是 found=false。改坏 payload 让解码直接失败已由上一条覆盖，这里改
// event_count 与实际内容脱节的方式：把目标块的 payload 换成另一块的内容，块自洽
// 校验（check）与逐 id 比对至少有一个会失败。
func TestLocateIndexPayloadMismatch(t *testing.T) {
	ctx, client, db := open(t)
	f := seedLocate(t, ctx, client)
	locateShadow(t, ctx, db, f.day)

	var target, donor uuid.UUID
	if err := db.QueryRowContext(ctx, `SELECT chunk_id FROM event_archive_locator WHERE event_id = $1`,
		f.full).Scan(&target); err != nil {
		t.Fatal(err)
	}
	// 供体块：不含 full 的另一来源块
	if err := db.QueryRowContext(ctx, `SELECT c.id FROM event_archive_chunks c
 JOIN event_archive_locator l ON l.chunk_id = c.id AND l.event_id = $1
 WHERE c.id <> $2`, f.other, target).Scan(&donor); err != nil {
		t.Fatalf("找供体块: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE event_archive_chunks c
 SET payload = d.payload, plain_sha256 = d.plain_sha256, plain_len = d.plain_len,
     payload_len = d.payload_len, first_ts = d.first_ts, last_ts = d.last_ts
 FROM (SELECT payload, plain_sha256, plain_len, payload_len, first_ts, last_ts
       FROM event_archive_chunks WHERE id = $1) d
 WHERE c.id = $2`, donor, target); err != nil {
		t.Fatalf("替换目标块载荷: %v", err)
	}
	_, found, err := eventarchive.Locate(ctx, db, f.full)
	if err == nil || found {
		t.Fatalf("索引行指向的块解不出该事件时必须报错，实际 found=%v err=%v", found, err)
	}
	if !strings.Contains(err.Error(), "不一致") && !strings.Contains(err.Error(), "不符") {
		t.Fatalf("错误应说明 locator 与块内容不一致: %v", err)
	}
}

// 9b. P2 之前 ErrChunkBudget 承担的「候选块超预算」保护已随全表扫路径删除：
// 候选块数量现在由主键探查直接界定（一个 id 最多几个跨 run 副本），不再有
// 「扫多少块」的预算概念；读取侧的资源边界只剩 Query 的时间窗扫描预算
// （maxScannedChunks，P5 处理）。本用例把原来 201 块的语料改证新语义：
// 大量块存在时未命中仍是确定的 (false, nil)，且命中不受块数影响。
func TestLocateWithManyChunksNoBudgetPath(t *testing.T) {
	ctx, client, db := open(t)
	day := eventpartToday().AddDate(0, 0, -1)
	const total = 201 // 旧预算上限是 200，故意多一块
	for i := 0; i < total; i++ {
		client.Event.Create().SetTs(day.Add(time.Duration(i) * time.Second)).SetClassUID(4001).
			SetSource("agent").SetRaw(json.RawMessage(`{"conn": {"dst": "10.0.0.9:443"}}`)).SaveX(ctx)
	}
	runID, err := eventarchive.Shadow(ctx, db, eventarchive.Options{
		From: day, To: day, Classes: []int{4001}, ChunkEvents: 1, Confirm: true,
	})
	if err != nil {
		t.Fatalf("影子归档失败: %v", err)
	}
	run, err := eventarchive.LoadRun(ctx, db, runID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Chunks != total {
		t.Fatalf("每个事件应单独成块（共 %d 块），实际 %d 块", total, run.Chunks)
	}

	// 未命中：201 块 > 旧预算 200，结论仍是确定的「没有」，不再是 ErrChunkBudget
	absent := uuid.New()
	if _, found, err := eventarchive.Locate(ctx, db, absent); err != nil || found {
		t.Fatalf("索引未命中且覆盖完整时应为确定的 (false, nil)，实际 found=%v err=%v", found, err)
	}
	if ok, err := eventarchive.Exists(ctx, db, absent); err != nil || ok {
		t.Fatalf("Exists 同样应为 (false, nil)，实际 (%v, %v)", ok, err)
	}
	// 命中：不再受候选顺序与预算影响，最旧的一块（旧路径里预算最靠后的）也能命中
	oldest, err := client.Event.Query().Order(ent.Asc("ts")).First(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := eventarchive.Locate(ctx, db, oldest.ID); err != nil || !found {
		t.Fatalf("存在的事件应命中（与块数无关），实际 found=%v err=%v", found, err)
	}
}

// 10. Materialize 幂等：第一次 inserted=true，第二次 false；events 里只有一行，
// 字段与冷块（以及物化前的原事件）完全一致；冷块保持不可变。
func TestMaterializeIsIdempotent(t *testing.T) {
	ctx, client, db := open(t)
	f := seedLocate(t, ctx, client)
	locateShadow(t, ctx, db, f.day)
	orig, err := client.Event.Get(ctx, f.full)
	if err != nil {
		t.Fatal(err)
	}
	chunksBefore := coldChunksDigest(t, ctx, db)

	// 模拟「保留期把 events 的行清掉了，只剩冷块」
	if _, err := db.ExecContext(ctx, `DELETE FROM events WHERE id = $1`, f.full); err != nil {
		t.Fatal(err)
	}
	if _, found, err := eventarchive.Locate(ctx, db, f.full); err != nil || !found {
		t.Fatalf("events 里删掉之后冷层仍应命中: found=%v err=%v", found, err)
	}

	inserted, err := eventarchive.Materialize(ctx, db, f.full)
	if err != nil {
		t.Fatalf("物化失败: %v", err)
	}
	if !inserted {
		t.Fatal("events 里没有这一行，第一次物化应返回 inserted=true")
	}
	inserted, err = eventarchive.Materialize(ctx, db, f.full)
	if err != nil {
		t.Fatalf("重复物化不该报错: %v", err)
	}
	if inserted {
		t.Fatal("重复物化必须幂等：第二次应返回 inserted=false")
	}

	var rows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE id = $1`, f.full).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("events 里应恰好一行，实际 %d 行", rows)
	}
	// 物化出来的行与原事件逐字段一致
	got, err := client.Event.Get(ctx, f.full)
	if err != nil {
		t.Fatal(err)
	}
	assertSameEvent(t, eventFromEnt(got), orig)
	// 冷块不可变：物化前后块字节一致
	if chunksAfter := coldChunksDigest(t, ctx, db); chunksAfter != chunksBefore {
		t.Fatalf("物化改动了冷块：\n前 %s\n后 %s", chunksBefore, chunksAfter)
	}
}

func eventFromEnt(e *ent.Event) eventarchive.Event {
	return eventarchive.Event{
		ID: e.ID, Ts: e.Ts.UTC(), ClassUID: int64(e.ClassUID), Source: e.Source,
		AssetID: e.AssetID, ProcessGUID: e.ProcessGUID, ParentProcessGUID: e.ParentProcessGUID,
		Username: e.Username, ConnTuple: e.ConnTuple, Raw: e.Raw,
	}
}

// coldChunksDigest 是冷块的整行摘要：用来证明物化没有回写冷块。
func coldChunksDigest(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()
	var n int64
	var digest string
	if err := db.QueryRowContext(ctx, `SELECT count(*),
 COALESCE(md5(string_agg(id::text || ':' || plain_sha256::text || ':' || coalesce(id_bloom::text, 'null'), ','
   ORDER BY id)), '')
 FROM event_archive_chunks`).Scan(&n, &digest); err != nil {
		t.Fatal(err)
	}
	return digest
}

// 11. Materialize 不产告警、不碰派生表：物化前后 alerts 与 temporal_* 的计数完全不变。
func TestMaterializeProducesNoAlerts(t *testing.T) {
	ctx, client, db := open(t)
	f := seedLocate(t, ctx, client)
	locateShadow(t, ctx, db, f.day)
	// 基线不是 0：先造一条告警，确认「不变」不是「本来就是空的」
	if err := client.Alert.Create().SetTs(f.day.Add(time.Minute)).SetRuleID("baseline").
		SetSeverity(3).SetEventID(f.nullable).Exec(ctx); err != nil {
		t.Fatal(err)
	}

	tables := []string{"alerts", "temporal_matches", "temporal_candidates", "temporal_evaluation_gaps",
		"temporal_detections", "temporal_evidence"}
	before := map[string]int64{}
	for _, table := range tables {
		before[table] = tableCount(t, ctx, db, table)
	}
	if before["alerts"] == 0 {
		t.Fatal("基线告警应为 1 条")
	}

	if _, err := db.ExecContext(ctx, `DELETE FROM events WHERE id = $1`, f.full); err != nil {
		t.Fatal(err)
	}
	inserted, err := eventarchive.Materialize(ctx, db, f.full)
	if err != nil || !inserted {
		t.Fatalf("物化应成功: inserted=%v err=%v", inserted, err)
	}
	for _, table := range tables {
		if after := tableCount(t, ctx, db, table); after != before[table] {
			t.Fatalf("物化不该改动 %s：前 %d 行，后 %d 行", table, before[table], after)
		}
	}
}

// tableCount 数一张业务表的行数；表还没建时返回 -1（测试库只建了一部分模块的情形）。
func tableCount(t *testing.T, ctx context.Context, db *sql.DB, table string) int64 {
	t.Helper()
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		return -1
	}
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		t.Fatalf("统计 %s: %v", table, err)
	}
	return n
}

// 12. Materialize 对不存在的事件不插入任何行，也不报错（冷层确实没有，是正常结论）。
func TestMaterializeMissingEvent(t *testing.T) {
	ctx, client, db := open(t)
	f := seedLocate(t, ctx, client)
	locateShadow(t, ctx, db, f.day)

	var before int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	absent := uuid.New()
	inserted, err := eventarchive.Materialize(ctx, db, absent)
	if err != nil {
		t.Fatalf("冷层没有这条事件不该报错: %v", err)
	}
	if inserted {
		t.Fatal("冷层没有这条事件时不能插入任何行")
	}
	var after, rows int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM events`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE id = $1`, absent).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if after != before || rows != 0 {
		t.Fatalf("不该插入任何行：events 前 %d 行、后 %d 行，目标 id 命中 %d 行", before, after, rows)
	}
}
