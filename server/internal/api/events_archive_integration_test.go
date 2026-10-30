//go:build integration

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/internal/eventarchive"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// 冷热合流、组权限、覆盖度头、坏块与「没有冷数据」的逐字节回归。
//
// 冷块用 eventarchive.EncodeBlock 自己封、直接写 event_archive_chunks：这些事件只存在于冷层，
// 正是阶段 C 退役分区之后的形态，靠影子归档造不出来。

// archiveDB 连测试库并把冷归档清成「没有冷归档」的状态。testdb 只清业务表，
// 不碰 event_archive_*，所以每个用例自己负责起点与收尾。
func archiveDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	dropArchive(t, ctx, db)
	t.Cleanup(func() { dropArchive(t, ctx, db) })
	return db
}

func dropArchive(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS event_archive_locator, event_archive_chunks, event_archive_runs`); err != nil {
		t.Fatalf("清掉冷归档表: %v", err)
	}
}

// insertChunk 把一组事件封成一块写进 event_archive_chunks，返回块 id。
func insertChunk(t *testing.T, ctx context.Context, db *sql.DB, seq int, events []eventarchive.Event) uuid.UUID {
	t.Helper()
	block, err := eventarchive.EncodeBlock(events)
	if err != nil {
		t.Fatalf("编码冷块: %v", err)
	}
	first, last := events[0].Ts.UTC(), events[len(events)-1].Ts.UTC()
	day := time.Date(first.Year(), first.Month(), first.Day(), 0, 0, 0, 0, time.UTC)
	chunkID := uuid.New()
	if _, err := db.ExecContext(ctx, `INSERT INTO event_archive_chunks
 (id, run_id, seq, day, class_uid, source, first_ts, last_ts, event_count, format, codec,
  plain_len, payload_len, plain_sha256, payload)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		chunkID, uuid.New(), seq, day, int(events[0].ClassUID), events[0].Source, first, last, len(events),
		int16(block.Format), int16(block.Codec), block.PlainLen, len(block.Payload), block.PlainSHA256[:], block.Payload); err != nil {
		t.Fatalf("写入冷块: %v", err)
	}
	return chunkID
}

// archiveTime 造一个远离「当前 24 小时」的时间点，避免和别的用例默认窗口互相影响。
func archiveTime() time.Time {
	return time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Minute)
}

func coldEvent(ts time.Time, asset *uuid.UUID, raw string) eventarchive.Event {
	return eventarchive.Event{
		ID: uuid.New(), Ts: ts.UTC(), ClassUID: 4001, Source: "agent",
		AssetID: asset, Raw: json.RawMessage(raw),
	}
}

// eventQuery 用一组参数请求 /api/events，返回状态、解码后的行与原始响应体。
// P5 起响应是对象契约 {items, truncated, coverage}，这里取 items。
func queryEvents(t *testing.T, ts *httptest.Server, base time.Time, extra string) (*http.Response, []eventRow, []byte) {
	t.Helper()
	q := url.Values{}
	q.Set("from", base.Add(-time.Hour).Format(time.RFC3339))
	q.Set("to", base.Add(time.Hour).Format(time.RFC3339))
	path := "/api/events?" + q.Encode()
	if extra != "" {
		path += "&" + extra
	}
	resp, body := get(t, ts, path)
	var out eventsResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("解析响应: %v（%s）", err, body)
		}
	}
	return resp, out.Items, body
}

// 8. 热冷合流：热表有的事件、只存在于冷块的事件都返回；冷块里重复归档的热表事件只出现一次。
func TestEventSearchMergesHotAndCold(t *testing.T) {
	ctx, client := testdb.New(t)
	db := archiveDB(t, ctx)
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}

	base := archiveTime()
	hot1 := client.Event.Create().SetTs(base.Add(10 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"conn":{"dst":"10.0.0.1:443"},"mark":"hot-one"}`)).SaveX(ctx)
	hot2 := client.Event.Create().SetTs(base.Add(20 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"conn":{"dst":"10.0.0.2:443"},"mark":"hot-two"}`)).SaveX(ctx)
	// 冷块里：一条只存在于冷层的事件，加上一条与 hot1 完全同 id 同 ts 的重复归档
	// （原文故意与热表不同，用来确认合流时取的是热表那一份）
	coldOnly := coldEvent(base.Add(30*time.Minute), nil, `{"conn":{"dst":"10.0.0.3:443"},"mark":"cold-only"}`)
	duplicate := eventarchive.Event{ID: hot1.ID, Ts: base.Add(10 * time.Minute), ClassUID: 4001, Source: "agent",
		Raw: json.RawMessage(`{"mark":"stale-cold-copy"}`)}
	insertChunk(t, ctx, db, 1, []eventarchive.Event{duplicate, coldOnly})

	ts := httptest.NewServer(asAdmin(Handler(client, db, loadRules(t), response.NewHub(client, false),
		suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)))
	t.Cleanup(ts.Close)

	resp, rows, body := queryEvents(t, ts, base, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	// matched 是冷层的命中数（含与热表重复的那条），不是合流后的新增条数
	if cov := resp.Header.Get("X-Archive-Coverage"); cov != "chunks=1;matched=2;truncated=0" {
		t.Errorf("覆盖度头 = %q", cov)
	}
	if len(rows) != 3 {
		t.Fatalf("合流后应有 3 条（热表 2 条 + 只存在于冷块 1 条），实际 %d: %s", len(rows), body)
	}
	// (ts, id) 倒序
	if rows[0].ID != coldOnly.ID || rows[1].ID != hot2.ID || rows[2].ID != hot1.ID {
		t.Errorf("顺序不符: %v %v %v", rows[0].ID, rows[1].ID, rows[2].ID)
	}
	seen := map[uuid.UUID]int{}
	for _, r := range rows {
		seen[r.ID]++
	}
	if seen[hot1.ID] != 1 {
		t.Errorf("同 id 同 ts 的重复归档应只返回一条，实际 %d 条", seen[hot1.ID])
	}
	// 热表优先：重复归档那条取热表的原文，不取冷块那份旧拷贝
	if raw := string(rows[2].Raw); !strings.Contains(raw, "hot-one") || strings.Contains(raw, "stale-cold-copy") {
		t.Errorf("重复事件应取热表的原文，实际 %s", raw)
	}
}

// 9. 组权限：非 admin 看不到组外资产与 asset_id IS NULL 的冷事件；没有可见资产时一无所见。
func TestEventSearchColdScope(t *testing.T) {
	ctx, client := testdb.New(t)
	db := archiveDB(t, ctx)
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	a1 := client.Asset.Create().SetHostname("a1").SetGroupID(gA.ID).SaveX(ctx)
	b1 := client.Asset.Create().SetHostname("b1").SetGroupID(gB.ID).SaveX(ctx)

	base := archiveTime()
	inGroup := coldEvent(base.Add(10*time.Minute), &a1.ID, `{"mark":"group-a"}`)
	outGroup := coldEvent(base.Add(20*time.Minute), &b1.ID, `{"mark":"group-b"}`)
	noAsset := coldEvent(base.Add(30*time.Minute), nil, `{"mark":"no-asset"}`)
	insertChunk(t, ctx, db, 1, []eventarchive.Event{inGroup, outGroup, noAsset})

	member := func(name string) *ent.User {
		u := client.User.Create().SetUsername(name).SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
		client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(u.ID).SetRole("viewer").SaveX(ctx)
		return u
	}
	alice := member("alice")
	nobody := client.User.Create().SetUsername("bob").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	h := Handler(client, db, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	serve := func(u *ent.User) *httptest.Server {
		ts := httptest.NewServer(as(u, h))
		t.Cleanup(ts.Close)
		return ts
	}

	cases := []struct {
		name string
		user *ent.User
		want []uuid.UUID
		// deny 非空表示这条用例是受限视角：该资产与无归属事件都不许出现
		deny *uuid.UUID
	}{
		{"admin 看到全部", &ent.User{Username: "admin", Role: "admin"}, []uuid.UUID{noAsset.ID, outGroup.ID, inGroup.ID}, nil},
		{"组内 viewer 只看本组资产", alice, []uuid.UUID{inGroup.ID}, &b1.ID},
		{"没有任何组时一无所见", nobody, nil, &a1.ID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, rows, body := queryEvents(t, serve(c.user), base, "")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d: %s", resp.StatusCode, body)
			}
			if len(rows) != len(c.want) {
				t.Fatalf("返回 %d 条，期望 %d 条: %s", len(rows), len(c.want), body)
			}
			for i, want := range c.want {
				if rows[i].ID != want {
					t.Errorf("第 %d 条是 %s，期望 %s", i, rows[i].ID, want)
				}
			}
			if c.deny == nil {
				return
			}
			for _, r := range rows {
				if r.AssetID == nil {
					t.Error("受限视角不该看到无归属的冷事件")
				} else if *r.AssetID == *c.deny {
					t.Errorf("组外资产的冷事件泄露了: %s", r.ID)
				}
			}
		})
	}

	// 显式筛组外资产：热冷两边都必须空
	resp, rows, body := queryEvents(t, serve(alice), base, "assetId="+b1.ID.String())
	if resp.StatusCode != http.StatusOK || len(rows) != 0 {
		t.Errorf("组外资产筛选应返回空，得到 %d: %s", len(rows), body)
	}
}

// 10. 覆盖度头：查了冷层报 chunks/matched/truncated；关键词查询报 skipped=keyword 且不返回冷数据。
func TestEventSearchArchiveCoverage(t *testing.T) {
	ctx, client := testdb.New(t)
	db := archiveDB(t, ctx)
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	base := archiveTime()
	coldOnly := coldEvent(base.Add(10*time.Minute), nil, `{"mark":"archive-keyword-marker"}`)
	second := coldEvent(base.Add(20*time.Minute), nil, `{"mark":"second"}`)
	insertChunk(t, ctx, db, 1, []eventarchive.Event{coldOnly, second})

	ts := httptest.NewServer(asAdmin(Handler(client, db, loadRules(t), response.NewHub(client, false),
		suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)))
	t.Cleanup(ts.Close)

	resp, rows, body := queryEvents(t, ts, base, "")
	if resp.StatusCode != http.StatusOK || len(rows) != 2 {
		t.Fatalf("应返回冷块里的 2 条，得到 %d: %s", len(rows), body)
	}
	if cov := resp.Header.Get("X-Archive-Coverage"); cov != "chunks=1;matched=2;truncated=0" {
		t.Errorf("覆盖度头 = %q", cov)
	}
	if resp.Header.Get("X-Truncated") != "" {
		t.Error("没取满 limit 时不该带 X-Truncated")
	}

	// limit 截断：冷层的 truncated 与 X-Truncated 都要如实说出来
	resp, rows, body = queryEvents(t, ts, base, "limit=1")
	if resp.StatusCode != http.StatusOK || len(rows) != 1 {
		t.Fatalf("limit=1 应返回 1 条，得到 %d: %s", len(rows), body)
	}
	if cov := resp.Header.Get("X-Archive-Coverage"); cov != "chunks=1;matched=2;truncated=1" {
		t.Errorf("截断时的覆盖度头 = %q", cov)
	}
	if resp.Header.Get("X-Truncated") != "1" {
		t.Error("取满 limit 应带 X-Truncated")
	}
	if rows[0].ID != second.ID {
		t.Errorf("截断后应保留最新的一条，实际 %s", rows[0].ID)
	}

	// 关键词：不查冷层，并用头说明原因；冷块里那条不会出现在结果里
	resp, rows, body = queryEvents(t, ts, base, "q=archive-keyword-marker")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if cov := resp.Header.Get("X-Archive-Coverage"); cov != "skipped=keyword" {
		t.Errorf("关键词查询的覆盖度头 = %q，期望 skipped=keyword", cov)
	}
	if len(rows) != 0 {
		t.Errorf("关键词查询不该返回只存在于冷块的事件，实际 %d 条", len(rows))
	}

	// 窗口整体早于最早冷块：如实标注 skipped=before_archive
	q := url.Values{}
	q.Set("from", base.AddDate(0, 0, -5).Format(time.RFC3339))
	q.Set("to", base.AddDate(0, 0, -4).Format(time.RFC3339))
	resp, _ = get(t, ts, "/api/events?"+q.Encode())
	if cov := resp.Header.Get("X-Archive-Coverage"); cov != "skipped=before_archive" {
		t.Errorf("早于归档的窗口覆盖度头 = %q", cov)
	}
}

// 11. 坏块：接口返回 500 并带上块 id，不降级成只返回热表。
func TestEventSearchCorruptChunkFails(t *testing.T) {
	ctx, client := testdb.New(t)
	db := archiveDB(t, ctx)
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	base := archiveTime()
	chunkID := insertChunk(t, ctx, db, 1, []eventarchive.Event{
		coldEvent(base.Add(10*time.Minute), nil, `{"mark":"corrupt-target"}`),
	})
	// 热表里也放一条：坏块时也不能只返回热表结果
	client.Event.Create().SetTs(base.Add(20 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"mark":"hot"}`)).SaveX(ctx)

	var payload []byte
	if err := db.QueryRowContext(ctx, `SELECT payload FROM event_archive_chunks WHERE id = $1`, chunkID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	payload[0] ^= 0xff
	if _, err := db.ExecContext(ctx, `UPDATE event_archive_chunks SET payload = $2 WHERE id = $1`, chunkID, payload); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(asAdmin(Handler(client, db, loadRules(t), response.NewHub(client, false),
		suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)))
	t.Cleanup(ts.Close)

	resp, rows, body := queryEvents(t, ts, base, "")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("坏块应返回 500，实际 %d: %s", resp.StatusCode, body)
	}
	if len(rows) != 0 {
		t.Errorf("500 时不该返回部分结果，实际 %d 条", len(rows))
	}
	if !strings.Contains(string(body), chunkID.String()) {
		t.Errorf("错误信息应带块 id %s: %s", chunkID, body)
	}
}

// 12. 冷层不可用时的对象契约（P5）：
//   - 冷读开关关闭（conn 为 nil）：items 与改动前同样的合流结果（只有热表行）、
//     不写覆盖度头；coverage 无缺口（与改动前一致，配置错误由启动日志告警）；
//   - 开关开了但库里没有冷归档表：不 500，items 与开关关闭时逐字节一致，
//     头写 skipped=no-schema，coverage.reason=no_archive_schema；
//   - 表在但一条冷块都没有：items 一致、头不写，coverage 无缺口
//     （冷层确实没有数据，谈不上缺口）。
func TestEventSearchWithoutArchiveUnchanged(t *testing.T) {
	ctx, client := testdb.New(t)
	db := archiveDB(t, ctx)
	base := archiveTime()
	client.Event.Create().SetTs(base.Add(10 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"conn":{"dst":"10.0.0.1:443"},"mark":"plain"}`)).SaveX(ctx)

	// 开关关闭：根本拿不到冷库连接
	off := httptest.NewServer(asAdmin(Handler(client, nil, loadRules(t), response.NewHub(client, false),
		suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)))
	t.Cleanup(off.Close)
	// 开关开着：连接拿到了，但库里还没有冷归档表
	on := httptest.NewServer(asAdmin(Handler(client, db, loadRules(t), response.NewHub(client, false),
		suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)))
	t.Cleanup(on.Close)

	// itemsOf 解出 items 的原始 JSON，用来逐字节比较「合流结果」本身
	itemsOf := func(t *testing.T, body []byte) []byte {
		t.Helper()
		var raw struct {
			Items json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatalf("解析响应: %v（%s）", err, body)
		}
		return raw.Items
	}

	offResp, offRows, offBody := queryEvents(t, off, base, "")
	if offResp.StatusCode != http.StatusOK || len(offRows) != 1 {
		t.Fatalf("开关关闭时应正常返回 1 条，得到 %d: %s", len(offRows), offBody)
	}
	if cov := offResp.Header.Get("X-Archive-Coverage"); cov != "" {
		t.Errorf("冷读关闭时不该写覆盖度头，实际 %q", cov)
	}
	// 响应体形状：items 里还是那 8 个字段，没有多出任何冷归档痕迹
	var shape []map[string]json.RawMessage
	if err := json.Unmarshal(itemsOf(t, offBody), &shape); err != nil || len(shape) != 1 {
		t.Fatalf("items 解析失败或条数不对: %v %s", err, offBody)
	}
	fields := []string{"id", "ts", "classUid", "source", "assetId", "username", "connTuple", "raw"}
	for k := range shape[0] {
		if !slices.Contains(fields, k) {
			t.Errorf("响应多出了字段 %q", k)
		}
	}
	if len(shape[0]) != len(fields) {
		t.Errorf("响应字段数 %d，期望 %d: %s", len(shape[0]), len(fields), offBody)
	}
	// 冷读关闭与改动前一致：不报冷层缺口
	var offOut eventsResponse
	if err := json.Unmarshal(offBody, &offOut); err != nil {
		t.Fatal(err)
	}
	wantOff := eventsCoverage{HotSearched: true, ColdSearched: false, ScanComplete: true}
	if offOut.Coverage != wantOff {
		t.Errorf("冷读关闭的 coverage = %+v，期望 %+v", offOut.Coverage, wantOff)
	}

	// 表不存在：200，items 与开关关闭时逐字节一致，头如实写 skipped=no-schema
	noSchemaResp, noSchemaRows, noSchemaBody := queryEvents(t, on, base, "")
	if noSchemaResp.StatusCode != http.StatusOK || len(noSchemaRows) != 1 {
		t.Fatalf("没有冷归档表也不能失败，得到 %d 条: %s", len(noSchemaRows), noSchemaBody)
	}
	if cov := noSchemaResp.Header.Get("X-Archive-Coverage"); cov != "skipped=no-schema" {
		t.Errorf("没有冷归档表时覆盖度头 = %q，期望 skipped=no-schema", cov)
	}
	if string(itemsOf(t, noSchemaBody)) != string(itemsOf(t, offBody)) {
		t.Errorf("表不存在时的 items 应与开关关闭时逐字节一致:\n%s\n%s", itemsOf(t, noSchemaBody), itemsOf(t, offBody))
	}
	var noSchemaOut eventsResponse
	if err := json.Unmarshal(noSchemaBody, &noSchemaOut); err != nil {
		t.Fatal(err)
	}
	if noSchemaOut.Coverage.Reason != "no_archive_schema" || noSchemaOut.Coverage.ScanComplete || noSchemaOut.Coverage.ColdSearched {
		t.Errorf("没有冷归档表的 coverage = %+v", noSchemaOut.Coverage)
	}
	if noSchemaOut.Truncated {
		t.Error("1 条结果不该报 truncated")
	}

	// 表在、但没有冷块：头不写；coverage 无缺口——冷层确实没有数据
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	emptyResp, emptyRows, emptyBody := queryEvents(t, on, base, "")
	if emptyResp.StatusCode != http.StatusOK || len(emptyRows) != 1 {
		t.Fatalf("空归档时应正常返回 1 条，得到 %d 条: %s", len(emptyRows), emptyBody)
	}
	if cov := emptyResp.Header.Get("X-Archive-Coverage"); cov != "" {
		t.Errorf("空归档时不该写覆盖度头，实际 %q", cov)
	}
	if string(itemsOf(t, emptyBody)) != string(itemsOf(t, offBody)) {
		t.Errorf("空归档时的 items 应与开关关闭时逐字节一致:\n%s\n%s", itemsOf(t, emptyBody), itemsOf(t, offBody))
	}
	// 头语义一致：都不带归档头。Content-Length 会随 coverage.reason 的文字差不同，跳过
	if diff := headerDiffExcept(offResp.Header, emptyResp.Header, "Content-Length"); diff != "" {
		t.Errorf("空归档时的响应头应与开关关闭时一致，差异: %s", diff)
	}
	var emptyOut eventsResponse
	if err := json.Unmarshal(emptyBody, &emptyOut); err != nil {
		t.Fatal(err)
	}
	wantEmpty := eventsCoverage{HotSearched: true, ColdSearched: false, ScanComplete: true, Reason: ""}
	if emptyOut.Coverage != wantEmpty {
		t.Errorf("空归档的 coverage = %+v，期望 %+v（无缺口）", emptyOut.Coverage, wantEmpty)
	}
}

// headerDiffExcept 比较两个响应头（跳过随请求时间变化的 Date 与 skip 指定的头），
// 返回差异描述。
func headerDiffExcept(a, b http.Header, skip string) string {
	var diffs []string
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	for k := range keys {
		if k == "Date" || (skip != "" && strings.EqualFold(k, skip)) {
			continue
		}
		if av, bv := strings.Join(a.Values(k), ","), strings.Join(b.Values(k), ","); av != bv {
			diffs = append(diffs, k+": "+av+" vs "+bv)
		}
	}
	return strings.Join(diffs, "; ")
}
