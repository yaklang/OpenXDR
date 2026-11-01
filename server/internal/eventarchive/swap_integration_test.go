//go:build integration

package eventarchive_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/api"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/eventarchive"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

// 阶段 C：单日分区切换（plan → swap → restore）的集成测试。
//
// 夹具是一天完整的分区：4 条归档候选（含另一个 source）、1 条被 alerts 钉住、1 条类别外（1007）、
// 1 条来源外（syslog，run 口径只含 agent/sensor），外加今天 1 条（切换不该碰它）。
// run 用固定类别与来源跑 shadow + verify，所以「将被移出」的集合是确定的 4 条。

type swapFixture struct {
	day      time.Time   // 要切换的那一天（UTC 日）
	archived []uuid.UUID // run 口径内且未被钉住 → 被移出热表
	pinned   []uuid.UUID // run 口径内但被 alerts 引用 → 保留
	foreign  []uuid.UUID // 类别之外 → 保留
	other    []uuid.UUID // 来源之外 → 保留
	nextDay  []uuid.UUID // 另一天的事件 → 一切操作都不该碰
}

// swapOpen 连测试库、清冷归档表，并确保「3 天前」有独立日分区（testdb 只预建今天起的分区；
// P4 闸门上线后昨天/前天的日结束都过不了 temporal 安全边界，夹具统一用 3 天前）。
// 同时满足 P4 闸门的夹具前提：min-age 归零 + 播种 beacon/assetmap 的持久进度
// （本文件验证 swap/restore 自身语义，闸门有专项测试 p4_guards_integration_test.go）。
func swapOpen(t *testing.T) (context.Context, *ent.Client, *sql.DB) {
	t.Helper()
	ctx, client, db := open(t)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	day := eventpartToday().AddDate(0, 0, -8)
	if _, err := eventpart.EnsureDays(ctx, db, eventpart.Parent, day, 0); err != nil {
		t.Fatalf("建 8 天前的日分区: %v", err)
	}
	// 同 p0Day:老日分区用完即拆，别落进 janitor 集成测试的退役窗口
	t.Cleanup(func() {
		_, _ = db.Exec(`DROP TABLE IF EXISTS ` + eventpart.DailyName(day))
	})
	seedGuardConsumers(t, ctx, db, day)
	return ctx, client, db
}

// seedGuardConsumers 让 4001 口径的 run 通过消费进度闸门：beacon 的扫描完成标记
// 与 assetmap 游标都越过日结束（与 eventarchive 包内 p4SeedConsumed 同口径，
// 外部测试包够不着它）。R3 起走引擎同款写入器，不再播种 beacon_baselines.first_seen。
func seedGuardConsumers(t *testing.T, ctx context.Context, db *sql.DB, day time.Time) {
	t.Helper()
	if err := eventarchive.RecordBeaconScan(ctx, db, time.Now(), time.Now(), 7*24*time.Hour, 12*time.Hour); err != nil {
		t.Fatalf("播种 beacon 扫描完成标记: %v", err)
	}
	cursor, _ := json.Marshal(time.Now())
	if _, err := db.ExecContext(ctx, `INSERT INTO settings (id, value, updated_at)
 VALUES ('assetmap.cursor', $1::jsonb, now()) ON CONFLICT (id) DO UPDATE SET value = EXCLUDED.value`,
		string(cursor)); err != nil {
		t.Fatalf("播种 assetmap 游标: %v", err)
	}
}

func seedSwap(t *testing.T, ctx context.Context, client *ent.Client) swapFixture {
	t.Helper()
	day := eventpartToday().AddDate(0, 0, -8)
	f := swapFixture{day: day}
	add := func(ts time.Time, class int, source, raw string) uuid.UUID {
		t.Helper()
		e := client.Event.Create().SetTs(ts).SetClassUID(class).SetSource(source).
			SetRaw(json.RawMessage(raw)).SaveX(ctx)
		return e.ID
	}
	f.archived = []uuid.UUID{
		add(day.Add(1*time.Minute), 4001, "agent", `{"conn": {"dst": "10.0.0.1:443"}, "mark": "a1"}`),
		add(day.Add(2*time.Minute), 4001, "agent", `{"conn": {"dst": "10.0.0.2:80"}, "mark": "a2"}`),
		add(day.Add(3*time.Minute), 4001, "agent", `{"file": {"path": "/tmp/中文文件名"}, "mark": "a3"}`),
		add(day.Add(4*time.Minute), 4001, "sensor", `{"conn": {"dst": "10.0.0.3:53"}, "mark": "a4"}`),
	}
	f.pinned = []uuid.UUID{
		add(day.Add(5*time.Minute), 4001, "agent", `{"conn": {"dst": "10.0.0.9:22"}, "mark": "pinned"}`),
	}
	f.foreign = []uuid.UUID{
		add(day.Add(6*time.Minute), 1007, "agent", `{"process": {"pid": 42}, "mark": "foreign"}`),
	}
	f.other = []uuid.UUID{
		add(day.Add(7*time.Minute), 4001, "syslog", `{"message": "other source", "mark": "other"}`),
	}
	f.nextDay = []uuid.UUID{
		// 「另一天」放在今天：run 跨到今天，但切换只动被指定的那一天
		add(eventpartToday().Add(time.Minute), 4001, "agent", `{"conn": {"dst": "10.0.0.4:443"}, "mark": "day2"}`),
	}
	client.Alert.Create().SetTs(day.Add(5 * time.Minute)).SetRuleID("test-pin").SetSeverity(3).
		SetEventID(f.pinned[0]).SaveX(ctx)
	return f
}

// archiveRun 按固定口径跑一轮影子归档并等对拍通过：phase C 只接受 verified 的 run。
func archiveRun(t *testing.T, ctx context.Context, db *sql.DB, from, to time.Time, classes []int, sources []string) uuid.UUID {
	t.Helper()
	runID, err := eventarchive.Shadow(ctx, db, eventarchive.Options{
		From: from, To: to, Classes: classes, Sources: sources, Confirm: true,
	})
	if err != nil {
		t.Fatalf("影子归档失败: %v", err)
	}
	if err := eventarchive.Verify(ctx, db, runID); err != nil {
		t.Fatalf("对拍失败: %v", err)
	}
	return runID
}

// swapClasses / swapSources 是夹具的归档口径：类别只含 4001，来源只含 agent/sensor，
// 所以 syslog 那条属于「来源外」，1007 那条属于「类别外」。
var (
	swapClasses = []int{4001}
	swapSources = []string{"agent", "sensor"}
)

// fixtureRun 跑一轮覆盖「要切换的那天 + 今天的另一批事件」的归档：真实的 run 往往跨多天，
// 切换只应动被指定的那一天。
func fixtureRun(t *testing.T, ctx context.Context, db *sql.DB, f swapFixture) uuid.UUID {
	t.Helper()
	return archiveRun(t, ctx, db, f.day, eventpartToday(), swapClasses, swapSources)
}

func allIDs(f swapFixture) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(f.archived)+len(f.pinned)+len(f.foreign)+len(f.other))
	out = append(out, f.archived...)
	return append(append(append(out, f.pinned...), f.foreign...), f.other...)
}

func partitionRows(t *testing.T, ctx context.Context, db *sql.DB, day time.Time) int64 {
	t.Helper()
	var n int64
	name := eventpart.DailyName(day)
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+name).Scan(&n); err != nil {
		t.Fatalf("统计分区 %s: %v", name, err)
	}
	return n
}

func relExistsInDB(t *testing.T, ctx context.Context, db *sql.DB, name string) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&ok); err != nil {
		t.Fatalf("查找 %s: %v", name, err)
	}
	return ok
}

func rowExists(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE id = $1)`, id).Scan(&ok); err != nil {
		t.Fatalf("查事件 %s: %v", id, err)
	}
	return ok
}

// rowsDigest 是一组事件的整行摘要：条数、每个字段、raw 文本，少一行或改一个字都会变。
func rowsDigest(t *testing.T, ctx context.Context, db *sql.DB, ids []uuid.UUID) string {
	t.Helper()
	var counts int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE id = ANY($1::uuid[])`, ids).Scan(&counts); err != nil {
		t.Fatalf("统计事件行数: %v", err)
	}
	var digest sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT md5(string_agg(
  id::text || '|' || ts::text || '|' || class_uid::text || '|' || source || '|' ||
  COALESCE(asset_id::text, 'NULL') || '|' || COALESCE(process_guid::text, 'NULL') || '|' ||
  COALESCE(parent_process_guid::text, 'NULL') || '|' || COALESCE('=' || username, 'NULL') || '|' ||
  COALESCE('=' || conn_tuple, 'NULL') || '|' || raw::text, E'\n' ORDER BY id))
 FROM events WHERE id = ANY($1::uuid[])`, ids).Scan(&digest); err != nil {
		t.Fatalf("计算整行摘要: %v", err)
	}
	return fmt.Sprintf("count=%d digest=%s", counts, digest.String)
}

// hotFingerprint / coldFingerprint 用同一套字段格式，把 events 的一行与冷块里的事件
// 表示成可逐字比较的字符串（NULL 与空串区分开）。
func hotFingerprint(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var (
		ts                 time.Time
		class              int64
		source             string
		asset, proc, par   sql.NullString
		user, conn, rawStr sql.NullString
	)
	if err := db.QueryRowContext(ctx, `SELECT ts, class_uid, source, asset_id::text, process_guid::text,
 parent_process_guid::text, username, conn_tuple, raw::text FROM events WHERE id = $1`, id).
		Scan(&ts, &class, &source, &asset, &proc, &par, &user, &conn, &rawStr); err != nil {
		t.Fatalf("读事件 %s: %v", id, err)
	}
	return joinFingerprint(id, ts, class, source, asset, proc, par, user, conn, rawStr)
}

func coldFingerprint(e eventarchive.Event) string {
	text := func(s *string) sql.NullString {
		if s == nil {
			return sql.NullString{}
		}
		return sql.NullString{String: *s, Valid: true}
	}
	idText := func(id *uuid.UUID) sql.NullString {
		if id == nil {
			return sql.NullString{}
		}
		return sql.NullString{String: id.String(), Valid: true}
	}
	return joinFingerprint(e.ID, e.Ts, e.ClassUID, e.Source, idText(e.AssetID), idText(e.ProcessGUID),
		idText(e.ParentProcessGUID), text(e.Username), text(e.ConnTuple),
		sql.NullString{String: string(e.Raw), Valid: true})
}

func joinFingerprint(id uuid.UUID, ts time.Time, class int64, source string,
	asset, proc, parent, user, conn, raw sql.NullString) string {
	opt := func(s sql.NullString) string {
		if !s.Valid {
			return "NULL"
		}
		return "=" + s.String
	}
	return strings.Join([]string{
		id.String(), ts.UTC().Format(time.RFC3339Nano), strconv.FormatInt(class, 10), source,
		opt(asset), opt(proc), opt(parent), opt(user), opt(conn), opt(raw),
	}, "|")
}

func runChunksDigest(t *testing.T, ctx context.Context, db *sql.DB, runID uuid.UUID) string {
	t.Helper()
	var digest sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT md5(string_agg(
  seq::text || '|' || day::text || '|' || class_uid::text || '|' || source || '|' ||
  event_count::text || '|' || encode(plain_sha256, 'hex'), E'\n' ORDER BY seq))
 FROM event_archive_chunks WHERE run_id = $1`, runID).Scan(&digest); err != nil {
		t.Fatalf("计算冷块摘要: %v", err)
	}
	return digest.String
}

// runRowCounts 是切换必须保持不动的派生状态：告警与几张 lineage 表。
func runRowCounts(t *testing.T, ctx context.Context, db *sql.DB) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, table := range []string{"alerts", "incidents", "temporal_matches", "temporal_candidates",
		"temporal_evidence", "temporal_detections", "identity_observations"} {
		var n int64
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
			t.Fatalf("统计 %s: %v", table, err)
		}
		out[table] = n
	}
	return out
}

// 1. Plan 的四个计数互斥且穷尽，且 Archived 与阶段 A 在该日的归档条数一致；Plan 不写任何东西。
func TestSwapPlanIsSelfConsistent(t *testing.T) {
	ctx, client, db := swapOpen(t)
	f := seedSwap(t, ctx, client)
	runID := fixtureRun(t, ctx, db, f)

	before := eventsDigest(t, ctx, db)
	p, err := eventarchive.Plan(ctx, db, runID, f.day)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if p.Total != 7 || p.Archived != 4 || p.KeepPinned != 1 || p.KeepOther != 2 {
		t.Fatalf("计划计数不符：%+v（期望 total=7 archived=4 pinned=1 other=2）", p)
	}
	if p.Archived+p.KeepPinned+p.KeepOther != p.Total {
		t.Fatalf("三个桶之和应等于分区行数：%+v", p)
	}
	if !p.Day.Equal(dayOf(f.day)) || p.Day.Location() != time.UTC {
		t.Fatalf("Day 应是 UTC 日零点：%v", p.Day)
	}
	if got := partitionRows(t, ctx, db, f.day); got != p.Total {
		t.Fatalf("Plan 的 Total %d 与分区实际行数 %d 不符", p.Total, got)
	}
	// Archived 必须等于阶段 A 落在这一天的归档条数（从冷块解出来数）
	archivedIDs := decodeChunkIDs(t, ctx, db, runID)
	var inDay int64
	for _, id := range f.archived {
		if archivedIDs[id] {
			inDay++
		}
	}
	if inDay != p.Archived {
		t.Fatalf("Archived %d 与阶段 A 该日归档条数 %d 不符", p.Archived, inDay)
	}
	run, err := eventarchive.LoadRun(ctx, db, runID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Archived != inDay+int64(len(f.nextDay)) {
		t.Fatalf("run 共归档 %d 条（两天），该日 %d 条 + 另一天 %d 条才对得上", run.Archived, inDay, len(f.nextDay))
	}
	if p.Archived == run.Archived {
		t.Fatalf("run 跨两天，但切换计划只该算 %s 这一天", f.day.Format(time.DateOnly))
	}
	if after := eventsDigest(t, ctx, db); after != before {
		t.Fatalf("Plan 必须是只读的：\n前 %s\n后 %s", before, after)
	}
	if relExistsInDB(t, ctx, db, eventpart.DailyName(f.day)+"_rewrite") {
		t.Fatal("Plan 不应留下暂存表")
	}
}

// 2. Swap 之后：分区行数 = 钉住 + 其它；被移出的 id 在 events 里查不到；
// 其它类别/来源与被钉住的行一行不少、内容一字不变；另一天的分区不受影响。
func TestSwapMovesOnlyArchivedRows(t *testing.T) {
	ctx, client, db := swapOpen(t)
	f := seedSwap(t, ctx, client)
	runID := fixtureRun(t, ctx, db, f)

	keptIDs := append(append(append([]uuid.UUID{}, f.pinned...), f.foreign...), f.other...)
	keptBefore := rowsDigest(t, ctx, db, keptIDs)
	nextBefore := rowsDigest(t, ctx, db, f.nextDay)
	chunksBefore := runChunksDigest(t, ctx, db, runID)
	alertsBefore := runRowCounts(t, ctx, db)["alerts"]

	// 一条规则命中挂在会被移出的事件上：删分区不触发逐行级联，RewriteDay 要按 retire 的
	// 同一清单显式清理它
	if _, err := db.ExecContext(ctx, `INSERT INTO temporal_rule_snapshots(revision, document) VALUES('v','{}') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO temporal_matches(rule_id, event_id) VALUES('m', $1)`, f.archived[0]); err != nil {
		t.Fatal(err)
	}

	p, err := eventarchive.Swap(ctx, db, runID, f.day)
	if err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if p.Archived != 4 || p.KeepPinned != 1 || p.KeepOther != 2 || p.Total != 7 {
		t.Fatalf("Swap 返回的计划不符：%+v", p)
	}
	if got := partitionRows(t, ctx, db, f.day); got != p.KeepPinned+p.KeepOther {
		t.Fatalf("切换后分区应有 %d 行（钉住 %d + 其它 %d），实际 %d",
			p.KeepPinned+p.KeepOther, p.KeepPinned, p.KeepOther, got)
	}
	for _, id := range f.archived {
		if rowExists(t, ctx, db, id) {
			t.Fatalf("被归档的事件 %s 应已移出热表", id)
		}
	}
	if after := rowsDigest(t, ctx, db, keptIDs); after != keptBefore {
		t.Fatalf("钉住/类别外/来源外的行被动过：\n前 %s\n后 %s", keptBefore, after)
	}
	if after := rowsDigest(t, ctx, db, f.nextDay); after != nextBefore {
		t.Fatalf("另一天的分区不应受影响：\n前 %s\n后 %s", nextBefore, after)
	}
	if after := runChunksDigest(t, ctx, db, runID); after != chunksBefore {
		t.Fatalf("切换不该改冷块：\n前 %s\n后 %s", chunksBefore, after)
	}
	if n := runRowCounts(t, ctx, db)["alerts"]; n != alertsBefore {
		t.Fatalf("alerts 行数从 %d 变成 %d", alertsBefore, n)
	}
	var matches int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM temporal_matches WHERE event_id = $1`, f.archived[0]).Scan(&matches); err != nil {
		t.Fatal(err)
	}
	if matches != 0 {
		t.Fatal("被移出事件的规则命中应随分区重建清理（与 retire 同一口径）")
	}

	// detail.days 按日记下实际切换结果（P3 起取代单个 detail.swapped 值），status 不变
	run, err := eventarchive.LoadRun(ctx, db, runID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != eventarchive.StatusVerified {
		t.Fatalf("Swap 不该改 status，实际 %s", run.Status)
	}
	var detail struct {
		Days map[string]struct {
			SwappedAt      string `json:"swapped_at"`
			Kept           int64  `json:"kept"`
			Dropped        int64  `json:"dropped"`
			RunDayVerified bool   `json:"run_day_verified"`
		} `json:"days"`
	}
	if err := json.Unmarshal(run.Detail, &detail); err != nil {
		t.Fatalf("解析 detail: %v（%s）", err, run.Detail)
	}
	rec, ok := detail.Days[f.day.Format(time.DateOnly)]
	if !ok {
		t.Fatalf("detail.days 应记录 %s：%s", f.day.Format(time.DateOnly), run.Detail)
	}
	if rec.Kept != 3 || rec.Dropped != 4 || !rec.RunDayVerified {
		t.Fatalf("detail.days.%s 应是 kept=3（钉住1+其它2）dropped=4 run_day_verified=true，实际 %+v",
			f.day.Format(time.DateOnly), rec)
	}
	if p.Kept != 3 || p.Dropped != 4 {
		t.Fatalf("Swap 返回的事务内实测应是 kept=3 dropped=4，实际 kept=%d dropped=%d", p.Kept, p.Dropped)
	}
	if relExistsInDB(t, ctx, db, eventpart.DailyName(f.day)+"_rewrite") {
		t.Fatal("切换后不应留下暂存表")
	}
}

// 3. 切换后冷层仍然可读：Locate 按 ID 命中且字段与切换前逐字一致，Query 按时间窗读回，
// /api/events（阶段 B1 的冷热合流）也能返回这些只在冷块里的事件。
func TestColdLayerServesSwappedEvents(t *testing.T) {
	ctx, client, db := swapOpen(t)
	f := seedSwap(t, ctx, client)
	runID := fixtureRun(t, ctx, db, f)

	hot := map[uuid.UUID]string{}
	for _, id := range f.archived {
		hot[id] = hotFingerprint(t, ctx, db, id)
	}
	if _, err := eventarchive.Swap(ctx, db, runID, f.day); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	for _, id := range f.archived {
		e, found, err := eventarchive.Locate(ctx, db, id)
		if err != nil {
			t.Fatalf("Locate %s: %v", id, err)
		}
		if !found {
			t.Fatalf("切换到冷层后 Locate 必须命中 %s", id)
		}
		if got := coldFingerprint(e); got != hot[id] {
			t.Fatalf("冷块里的事件与切换前不一致：\n切换前 %s\n冷块   %s", hot[id], got)
		}
	}
	events, cov, err := eventarchive.Query(ctx, db, eventarchive.Filter{
		From: f.day, To: f.day.AddDate(0, 0, 1), Classes: swapClasses, Sources: swapSources,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	got := map[uuid.UUID]bool{}
	for _, e := range events {
		got[e.ID] = true
	}
	if len(events) != len(f.archived) {
		t.Fatalf("Query 应返回该日 4 条冷事件，实际 %d 条（覆盖度 %+v）", len(events), cov)
	}
	for _, id := range f.archived {
		if !got[id] {
			t.Fatalf("Query 没返回已被移出的 %s", id)
		}
	}
	if cov.ScannedChunks == 0 || cov.Truncated {
		t.Fatalf("覆盖度应如实说明扫过的块：%+v", cov)
	}

	// /api/events：热表里已经没有这些事件，响应只能来自冷块
	srv := eventAPI(t, client, db)
	rows, resp := queryEventAPI(t, srv, f.day, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/events status = %d", resp.StatusCode)
	}
	if cov := resp.Header.Get("X-Archive-Coverage"); !strings.Contains(cov, "matched=") {
		t.Fatalf("/api/events 应回报冷层覆盖度，实际 %q", cov)
	}
	seen := map[uuid.UUID]bool{}
	for _, r := range rows {
		seen[r.ID] = true
	}
	for _, id := range f.archived {
		if !seen[id] {
			t.Fatalf("/api/events 没返回只在冷块里的 %s", id)
		}
	}
	for _, id := range f.pinned {
		if !seen[id] {
			t.Fatalf("/api/events 没返回钉住的事件 %s（它还在热表里）", id)
		}
	}
}

// 4. Restore 把这一天被移出的事件全部还原：行数、每个字段与 raw 与切换前逐字一致；
// 重复 Restore 幂等，第二次插入 0 行，冷块与派生状态都不变。
func TestRestoreBringsBackSwappedDay(t *testing.T) {
	ctx, client, db := swapOpen(t)
	f := seedSwap(t, ctx, client)
	runID := fixtureRun(t, ctx, db, f)

	ids := allIDs(f)
	before := rowsDigest(t, ctx, db, ids)
	chunksBefore := runChunksDigest(t, ctx, db, runID)
	if _, err := eventarchive.Swap(ctx, db, runID, f.day); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if got := partitionRows(t, ctx, db, f.day); got != 3 {
		t.Fatalf("切换后分区应有 3 行，实际 %d", got)
	}
	n, err := eventarchive.Restore(ctx, db, runID, f.day)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if n != 4 {
		t.Fatalf("应还原 4 条，实际 %d", n)
	}
	if after := rowsDigest(t, ctx, db, ids); after != before {
		t.Fatalf("还原后的行与切换前不一致：\n前 %s\n后 %s", before, after)
	}
	if got := partitionRows(t, ctx, db, f.day); got != 7 {
		t.Fatalf("还原后分区应有 7 行，实际 %d", got)
	}
	if after := runChunksDigest(t, ctx, db, runID); after != chunksBefore {
		t.Fatalf("还原不该改冷块：\n前 %s\n后 %s", chunksBefore, after)
	}
	again, err := eventarchive.Restore(ctx, db, runID, f.day)
	if err != nil {
		t.Fatalf("第二次 Restore: %v", err)
	}
	if again != 0 {
		t.Fatalf("重复 Restore 应幂等（第二次插入 0 行），实际 %d", again)
	}
	if after := rowsDigest(t, ctx, db, ids); after != before {
		t.Fatalf("重复 Restore 改了行：\n前 %s\n后 %s", before, after)
	}
}

// 5a. run 还没 verified：拒绝，且一个字节都没动。
func TestSwapRefusesUnverifiedRun(t *testing.T) {
	ctx, client, db := swapOpen(t)
	f := seedSwap(t, ctx, client)
	runID, err := eventarchive.Shadow(ctx, db, eventarchive.Options{
		From: f.day, To: f.day, Classes: swapClasses, Sources: swapSources, Confirm: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertRefused(t, ctx, db, f.day, func() error {
		_, err := eventarchive.Swap(ctx, db, runID, f.day)
		return err
	}, "verified")
}

// 5b. day 超出 run 的日期范围：拒绝。
func TestSwapRefusesDayOutsideRun(t *testing.T) {
	ctx, client, db := swapOpen(t)
	f := seedSwap(t, ctx, client)
	runID := fixtureRun(t, ctx, db, f)           // run 覆盖昨天与今天
	outside := eventpartToday().AddDate(0, 0, 2) // 后天：有独立日分区，但不在 run 的范围里
	assertRefused(t, ctx, db, outside, func() error {
		_, err := eventarchive.Swap(ctx, db, runID, outside)
		return err
	}, "不在 run")
}

// 5c. 该日没有独立日分区（行在默认分区）：拒绝，并指明先 EnsureDays；默认分区一行不动。
func TestSwapRefusesDayWithoutPartition(t *testing.T) {
	ctx, client, db := swapOpen(t)
	day := eventpartToday().AddDate(0, 0, -40) // 超出预建范围
	if relExistsInDB(t, ctx, db, eventpart.DailyName(day)) {
		t.Fatalf("测试前提：%s 不该有日分区", day.Format(time.DateOnly))
	}
	ids := make([]uuid.UUID, 0, 2)
	for i := 1; i <= 2; i++ {
		e := client.Event.Create().SetTs(day.Add(time.Duration(i) * time.Minute)).SetClassUID(4001).
			SetSource("agent").SetRaw(json.RawMessage(`{"mark": "default-partition"}`)).SaveX(ctx)
		ids = append(ids, e.ID)
	}
	var part string
	if err := db.QueryRowContext(ctx, `SELECT tableoid::regclass::text FROM events WHERE id = $1`, ids[0]).Scan(&part); err != nil {
		t.Fatal(err)
	}
	if part != eventpart.DefaultName {
		t.Fatalf("测试前提：这天的行应在默认分区，实际在 %s", part)
	}
	runID := archiveRun(t, ctx, db, day, day, swapClasses, swapSources)
	assertRefused(t, ctx, db, day, func() error {
		_, err := eventarchive.Swap(ctx, db, runID, day)
		return err
	}, "EnsureDays")
	if relExistsInDB(t, ctx, db, eventpart.DailyName(day)) {
		t.Fatal("拒绝时不该顺手把日分区建出来")
	}
}

// 5d. 该日没有被归档的事件（Archived=0）：拒绝。这里 run 的类别是 4001，而那天只有 1007。
func TestSwapRefusesWhenNothingArchived(t *testing.T) {
	ctx, client, db := swapOpen(t)
	day := eventpartToday().AddDate(0, 0, -1)
	if _, err := eventpart.EnsureDays(ctx, db, eventpart.Parent, day, 0); err != nil {
		t.Fatal(err)
	}
	e := client.Event.Create().SetTs(day.Add(time.Minute)).SetClassUID(1007).SetSource("agent").
		SetRaw(json.RawMessage(`{"mark": "not-a-candidate"}`)).SaveX(ctx)
	runID := fixtureRun(t, ctx, db, swapFixture{day: day})
	assertRefused(t, ctx, db, day, func() error {
		_, err := eventarchive.Swap(ctx, db, runID, day)
		return err
	}, "Archived=0")
	if !rowExists(t, ctx, db, e.ID) {
		t.Fatalf("类别外的事件 %s 不该被删", e.ID)
	}
}

// 5e. 超大事件不在冷块（阶段 A 跳过编码后超过 4 MiB 的事件）：这类行在热表里、却不在
// 本 run 的 locator。P3 起它不进删除集——留在热表，Swap 照常移出其余行（旧实现整日拒绝）；
// 断言超大行留热、其余移出、无静默丢，事务内实测数写进 detail.days。
func TestSwapKeepsOversizedRowHot(t *testing.T) {
	ctx, client, db := swapOpen(t)
	f := seedSwap(t, ctx, client)
	big := client.Event.Create().SetTs(f.day.Add(8 * time.Minute)).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"blob": "` + strings.Repeat("x", eventarchive.MaxEventBytes) + `"}`)).SaveX(ctx)
	runID := fixtureRun(t, ctx, db, f)

	p, err := eventarchive.Plan(ctx, db, runID, f.day)
	if err != nil {
		t.Fatal(err)
	}
	if p.Archived != 5 || p.Total != 8 {
		t.Fatalf("超大事件也在归档口径里，计划应是 8 = 5 + 1 + 2，实际 %+v", p)
	}
	out, err := eventarchive.Swap(ctx, db, runID, f.day)
	if err != nil {
		t.Fatalf("P3：超大行留热、其余照常移出，Swap 不再整日拒绝，实际 %v", err)
	}
	if out.Kept != 4 || out.Dropped != 4 {
		t.Fatalf("事务内实测应是 kept=4（钉住1+其它2+超大1）dropped=4，实际 kept=%d dropped=%d",
			out.Kept, out.Dropped)
	}
	if !rowExists(t, ctx, db, big.ID) {
		t.Fatal("没有被归档的事件绝不能随切换消失")
	}
	for _, id := range f.archived {
		if rowExists(t, ctx, db, id) {
			t.Fatalf("有冷副本的事件 %s 应已移出热表", id)
		}
	}
	if got := partitionRows(t, ctx, db, f.day); got != 4 {
		t.Fatalf("切换后分区应有 4 行（钉住+其它+超大），实际 %d 行", got)
	}
	run, err := eventarchive.LoadRun(ctx, db, runID)
	if err != nil {
		t.Fatal(err)
	}
	var detail struct {
		Days map[string]struct {
			Kept    int64  `json:"kept"`
			Dropped int64  `json:"dropped"`
			Note    string `json:"note"`
		} `json:"days"`
	}
	if err := json.Unmarshal(run.Detail, &detail); err != nil {
		t.Fatalf("解析 detail: %v（%s）", err, run.Detail)
	}
	rec, ok := detail.Days[f.day.Format(time.DateOnly)]
	if !ok || rec.Kept != 4 || rec.Dropped != 4 || !strings.Contains(rec.Note, "没有冷副本") {
		t.Fatalf("detail.days 应记录 kept=4 dropped=4 且 note 说明差额，实际 %+v", rec)
	}
}

// assertRefused 断言「拒绝且没有任何写入」：分区整行摘要不变、没有暂存表、run 的 detail 没被写。
func assertRefused(t *testing.T, ctx context.Context, db *sql.DB, day time.Time, call func() error, want string) {
	t.Helper()
	before := rowsDigest(t, ctx, db, allEventsInDay(t, ctx, db, day))
	err := call()
	if err == nil {
		t.Fatal("这个情形必须拒绝执行")
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("错误信息应说明原因（含 %q），实际 %v", want, err)
	}
	if after := rowsDigest(t, ctx, db, allEventsInDay(t, ctx, db, day)); after != before {
		t.Fatalf("被拒绝的操作改动了这一天的行：\n前 %s\n后 %s", before, after)
	}
	if relExistsInDB(t, ctx, db, eventpart.DailyName(day)+"_rewrite") {
		t.Fatal("被拒绝的操作留下了暂存表")
	}
	if got := coldSwapRecords(t, ctx, db); got != 0 {
		t.Fatalf("被拒绝的操作不该写 detail.days，实际有 %d 条记录", got)
	}
}

func allEventsInDay(t *testing.T, ctx context.Context, db *sql.DB, day time.Time) []uuid.UUID {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT id FROM events WHERE ts >= $1 AND ts < $2`, day, day.AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("列出 %s 的事件: %v", day.Format(time.DateOnly), err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}

func coldSwapRecords(t *testing.T, ctx context.Context, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM event_archive_runs WHERE detail ? 'days'`).Scan(&n); err != nil {
		t.Fatalf("统计 detail.days: %v", err)
	}
	return n
}

// 6. 计数不符时中止：keepSelect 指向别的日分区（选出的 id 不在这个分区里）必须报错，
// 原分区行数不变；只保留部分行本身是正常路径，不该被误判成错误。
func TestRewriteDayAbortsOnCountMismatch(t *testing.T) {
	ctx, client, db := swapOpen(t)
	f := seedSwap(t, ctx, client)
	if got := partitionRows(t, ctx, db, eventpartToday()); got != 1 {
		t.Fatalf("测试前提：今天分区应有 1 行，实际 %d", got)
	}
	ids := allIDs(f)
	before := rowsDigest(t, ctx, db, ids)

	// 选出的 id 全在另一天的分区里：保留 0 条，却选了 1 条 → 计数不符
	keep := `SELECT id FROM ` + eventpart.DailyName(eventpartToday())
	kept, dropped, err := eventpart.RewriteDay(ctx, db, f.day, keep)
	if err == nil {
		t.Fatal("keepSelect 与日分区不是同一批行时必须中止")
	}
	if !strings.Contains(err.Error(), "保留计数不符") {
		t.Fatalf("错误信息应指出保留计数不符，实际 %v", err)
	}
	if kept != 0 || dropped != 0 {
		t.Fatalf("中止时应返回 0/0，实际 kept=%d dropped=%d", kept, dropped)
	}
	if after := rowsDigest(t, ctx, db, ids); after != before {
		t.Fatalf("中止后原分区必须完好：\n前 %s\n后 %s", before, after)
	}
	if relExistsInDB(t, ctx, db, eventpart.DailyName(f.day)+"_rewrite") {
		t.Fatal("中止后不该留下暂存表")
	}

	// 非 SELECT 与带分号的输入一律拒绝，连事务都不开
	for _, bad := range []string{"", "DELETE FROM events", "SELECT id FROM events; DROP TABLE x",
		"SELECT id FROM (SELECT id FROM events) k WHERE false OR ts > now()"} {
		if _, _, err := eventpart.RewriteDay(ctx, db, f.day, bad); err == nil {
			t.Fatalf("非法 keepSelect %q 必须被拒绝", bad)
		}
	}
	if after := rowsDigest(t, ctx, db, ids); after != before {
		t.Fatalf("拒绝非法 keepSelect 时不能动分区：\n前 %s\n后 %s", before, after)
	}

	// 只保留部分行是正常路径：留下 1007 与钉住的那条，其余移出
	keep = fmt.Sprintf(`SELECT id FROM %s WHERE class_uid = 1007 OR id IN (%s)`,
		eventpart.DailyName(f.day), eventpart.PinnedIDs)
	kept, dropped, err = eventpart.RewriteDay(ctx, db, f.day, keep)
	if err != nil {
		t.Fatalf("部分保留应成功: %v", err)
	}
	if kept != 2 || dropped != 5 {
		t.Fatalf("应保留 2 条、移出 5 条，实际 kept=%d dropped=%d", kept, dropped)
	}
	if got := partitionRows(t, ctx, db, f.day); got != 2 {
		t.Fatalf("重建后分区应有 2 行，实际 %d", got)
	}
}

// 7. 故障注入：暂存表名被占、事务中途（DETACH 等锁）失败、context 已取消——
// 三种情况下原分区都必须完好，之后还能继续读写并正常完成切换。
func TestSwapFailureLeavesPartitionIntact(t *testing.T) {
	ctx, client, db := swapOpen(t)
	f := seedSwap(t, ctx, client)
	runID := fixtureRun(t, ctx, db, f)
	ids := allIDs(f)
	before := rowsDigest(t, ctx, db, ids)
	staging := eventpart.DailyName(f.day) + "_rewrite"

	// (1) 暂存表名被占：事务里的 CREATE TABLE 直接失败
	if _, err := db.ExecContext(ctx, `CREATE TABLE `+staging+` (x int)`); err != nil {
		t.Fatal(err)
	}
	if _, err := eventarchive.Swap(ctx, db, runID, f.day); err == nil {
		t.Fatal("暂存表名被占时应失败")
	}
	if after := rowsDigest(t, ctx, db, ids); after != before {
		t.Fatalf("失败后原分区必须完好：\n前 %s\n后 %s", before, after)
	}
	if got := partitionRows(t, ctx, db, f.day); got != 7 {
		t.Fatalf("失败后分区行数应为 7，实际 %d", got)
	}
	if got := coldSwapRecords(t, ctx, db); got != 0 {
		t.Fatalf("失败的切换不该写 detail.days，实际 %d 条", got)
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE `+staging); err != nil {
		t.Fatal(err)
	}

	// (2) 事务中途失败：一个视图依赖着日分区，DETACH 之后 DROP TABLE 必然失败——
	// 故障点正好落在「旧分区已经摘下来」之后，回滚必须把它原样挂回去
	view := "v_dep_" + eventpart.DailyName(f.day)
	if _, err := db.ExecContext(ctx, `CREATE VIEW `+view+` AS SELECT id, ts FROM `+eventpart.DailyName(f.day)); err != nil {
		t.Fatal(err)
	}
	_, swapErr := eventarchive.Swap(ctx, db, runID, f.day)
	if swapErr == nil {
		t.Fatalf("DROP TABLE 有依赖时必须失败")
	}
	if after := rowsDigest(t, ctx, db, ids); after != before {
		t.Fatalf("事务中途失败后原分区必须完好：\n前 %s\n后 %s", before, after)
	}
	if !relExistsInDB(t, ctx, db, view) {
		t.Fatal("依赖的视图不该被顺手删掉")
	}
	if relExistsInDB(t, ctx, db, staging) {
		t.Fatal("回滚后不该留下暂存表")
	}
	if got := coldSwapRecords(t, ctx, db); got != 0 {
		t.Fatalf("失败的切换不该写 detail.days，实际 %d 条", got)
	}
	if _, err := db.ExecContext(ctx, `DROP VIEW `+view); err != nil {
		t.Fatal(err)
	}

	// (3) context 已取消：连事务都开不起来
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := eventarchive.Swap(cancelled, db, runID, f.day); err == nil {
		t.Fatal("context 取消后必须失败")
	}
	if after := rowsDigest(t, ctx, db, ids); after != before {
		t.Fatalf("取消后原分区必须完好：\n前 %s\n后 %s", before, after)
	}

	// 分区仍然可正常读写：写一条迟到事件再删掉
	late := client.Event.Create().SetTs(f.day.Add(23 * time.Hour)).SetClassUID(1007).SetSource("agent").
		SetRaw(json.RawMessage(`{"mark": "late"}`)).SaveX(ctx)
	if !rowExists(t, ctx, db, late.ID) {
		t.Fatal("失败后分区仍应可写")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM events WHERE id = $1`, late.ID); err != nil {
		t.Fatalf("失败后分区仍应可删: %v", err)
	}
	if after := rowsDigest(t, ctx, db, ids); after != before {
		t.Fatalf("迟到事件清理后应与注入前一致：\n前 %s\n后 %s", before, after)
	}

	// 故障排除后同一个 run 仍能正常切换
	if _, err := eventarchive.Swap(ctx, db, runID, f.day); err != nil {
		t.Fatalf("故障排除后应能切换: %v", err)
	}
	if got := partitionRows(t, ctx, db, f.day); got != 3 {
		t.Fatalf("切换后分区应有 3 行，实际 %d", got)
	}
}

// 8. 切换与还原都不产告警：alerts 计数在 swap + restore 前后完全不变。
func TestSwapAndRestoreDoNotTouchAlerts(t *testing.T) {
	ctx, client, db := swapOpen(t)
	f := seedSwap(t, ctx, client)
	runID := fixtureRun(t, ctx, db, f)
	before := runRowCounts(t, ctx, db)
	if before["alerts"] != 1 {
		t.Fatalf("测试前提：应有 1 条告警，实际 %d", before["alerts"])
	}
	if _, err := eventarchive.Swap(ctx, db, runID, f.day); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if mid := runRowCounts(t, ctx, db); !sameCounts(before, mid) {
		t.Fatalf("切换改变了派生状态：前 %v，后 %v", before, mid)
	}
	if n, err := eventarchive.Restore(ctx, db, runID, f.day); err != nil || n != 4 {
		t.Fatalf("Restore: n=%d err=%v", n, err)
	}
	if after := runRowCounts(t, ctx, db); !sameCounts(before, after) {
		t.Fatalf("还原改变了派生状态：前 %v，后 %v", before, after)
	}
}

func sameCounts(a, b map[string]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// ---- /api/events（阶段 B1）的调用 ----

type apiEventRow struct {
	ID       uuid.UUID       `json:"id"`
	Ts       time.Time       `json:"ts"`
	ClassUID int             `json:"classUid"`
	Source   string          `json:"source"`
	Raw      json.RawMessage `json:"raw"`
}

// eventAPI 起一个以 admin 身份访问的 API 处理器，冷读连接直接给 db（EVENT_ARCHIVE_READ 的
// 开关在 main.go，这里按测试需要接上）。
func eventAPI(t *testing.T, client *ent.Client, db *sql.DB) *httptest.Server {
	t.Helper()
	h := api.Handler(client, db, sigma.LoadDir(t.TempDir()), response.NewHub(client, false),
		suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	admin := &ent.User{Username: "admin", Role: "admin"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), admin)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func queryEventAPI(t *testing.T, srv *httptest.Server, day time.Time, extra string) ([]apiEventRow, *http.Response) {
	t.Helper()
	q := url.Values{}
	q.Set("from", day.Format(time.RFC3339))
	q.Set("to", day.AddDate(0, 0, 1).Add(-time.Nanosecond).Format(time.RFC3339Nano))
	q.Set("limit", "200")
	path := "/api/events?" + q.Encode()
	if extra != "" {
		path += "&" + extra
	}
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("请求 %s: %v", path, err)
	}
	defer resp.Body.Close()
	var rows []apiEventRow
	if resp.StatusCode == http.StatusOK {
		// /api/events 是对象契约 {items, truncated, coverage}（P5）：事件行在 items 里
		var out struct {
			Items []apiEventRow `json:"items"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("解析 /api/events 响应: %v", err)
		}
		rows = out.Items
	}
	return rows, resp
}
