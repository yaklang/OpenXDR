//go:build integration

// P0 基线集成测试：冷归档方案 P0 阶段（COLD_ARCHIVE_EVOLUTION.SCRATCH.md 第 3 章、5.2 节
// T10/T12/T21 对应的现状版）。本文件断言的是「当前实现的行为」，不是目标契约——P0 不修复
// 任何缺陷，只把现状固定成可重复的基线，供 P1/P3 用同一套 fixture 对照。
//
// 本文件放在 package eventarchive（而不是 eventarchive_test）里的唯一原因是 T02 需要
// 直接设置未导出的 swapTestHook；seedDiverseDay / hotSnapshot / evidenceSnapshot /
// routingOf 是可复用 helper，P1 的批量恢复改造直接拿它们当输入。
//
// 专用测试库（INTEGRATION_DATABASE_URL 指向 openxdr_p0）可随意清表；与其它集成测试一样
// 必须串行（-p 1），testdb.New 会在每个用例前清空业务表。

package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/identity"
	"openxdr/server/internal/temporal"
	"openxdr/server/internal/testdb"
)

// p0Classes / p0Sources 是本文件所有 run 的固定口径：只有 4001/agent 进冷块，
// 1007 是类别外，非 agent 来源是来源外。
var (
	p0Classes = []int{4001}
	p0Sources = []string{"agent"}
)

// p0Open 连专用测试库、建冷归档表并清空它；确保测试钩子是干净的（上一个用例泄漏会立刻暴露）。
func p0Open(t *testing.T) (context.Context, *ent.Client, *sql.DB) {
	t.Helper()
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureSchema(ctx, db); err != nil {
		t.Fatalf("建冷归档表: %v", err)
	}
	// 专用库是新建的：RewriteDay/Retire 的派生状态清理会碰 temporal_* / identity_* 表，
	// 生产里由 main.go 启动时统一初始化，这里用同一批入口把它们建出来（幂等）。
	// 注意不能 import ingest.EnsureSchema：ingest 为 R1 引用补链反向依赖本包
	// （eventarchive.EnsureHotEvents），测试同包引用 ingest 会成环；接入侧的
	// temporal_matches 按 ingest.EnsureSchema 的同一 DDL 建在本夹具里（该处是唯一权威）。
	if err := temporal.EnsureSchema(ctx, db); err != nil {
		t.Fatalf("建时序表: %v", err)
	}
	if err := identity.EnsureSchema(ctx, db); err != nil {
		t.Fatalf("建身份图表: %v", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS temporal_matches (
 rule_id text NOT NULL,
 event_id uuid NOT NULL,
 PRIMARY KEY(rule_id,event_id)
);
CREATE INDEX IF NOT EXISTS temporal_matches_event ON temporal_matches(event_id);`); err != nil {
		t.Fatalf("建接入侧 temporal_matches: %v", err)
	}
	for _, table := range []string{"event_archive_chunks", "event_archive_runs"} {
		if _, err := db.ExecContext(ctx, `DELETE FROM `+table); err != nil {
			t.Fatalf("清空 %s: %v", table, err)
		}
	}
	// 拆掉可能残留的月归档分区（events_aYYYYMM，跨整月会挡住本包要建的历史日分区）。
	// 已知来源：janitor 的集成测试在其 t.Cleanup 里 DROP，但它的 defer db.Close() 先于
	// cleanup 执行，DROP 静默失败（该测试自身的问题，不在本包修）；本包对共享测试库的
	// 残留要自身免疫，不依赖跑测试前手工清库。
	if _, err := db.ExecContext(ctx, `DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT c.relname FROM pg_class c JOIN pg_inherits i ON c.oid=i.inhrelid
  WHERE i.inhparent='events'::regclass AND c.relname LIKE 'events_a%' LOOP
  EXECUTE format('DROP TABLE IF EXISTS %I', r.relname);
 END LOOP; END $$`); err != nil {
		t.Fatalf("清理残留月归档分区: %v", err)
	}
	if swapTestHook != nil {
		t.Fatal("测试前提：swapTestHook 必须为 nil（上一个用例的清理没执行）")
	}
	return ctx, client, db
}

// p0Today 与 eventpart.Today 同口径：UTC 当天零点。
func p0Today() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

// p0Day 取「今天减 daysAgo 天」的 UTC 日，并确保该日有独立日分区
// （testdb 只预建今天起的分区，历史日必须显式建，否则 Swap 会因行在默认分区而拒绝）。
// P4 起夹具要用一周以上的老日子（min-age/beacon/assetmap 回读窗口之外），这些日分区
// 会落进 janitor 集成测试的退役窗口（它按个数断言自己退役的分区），用完即拆，不跨包泄漏。
func p0Day(t *testing.T, ctx context.Context, db *sql.DB, daysAgo int) time.Time {
	t.Helper()
	day := p0Today().AddDate(0, 0, -daysAgo)
	if _, err := eventpart.EnsureDays(ctx, db, eventpart.Parent, day, 0); err != nil {
		t.Fatalf("建 %s 的日分区: %v", day.Format(time.DateOnly), err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DROP TABLE IF EXISTS ` + eventpart.DailyName(day))
	})
	return day
}

// p0Event 插一条事件并返回 id（raw 必须是合法 JSON 文本）。
func p0Event(t *testing.T, ctx context.Context, client *ent.Client, ts time.Time, class int, source, raw string) uuid.UUID {
	t.Helper()
	e := client.Event.Create().SetTs(ts).SetClassUID(class).SetSource(source).
		SetRaw(json.RawMessage(raw)).SaveX(ctx)
	return e.ID
}

// p0Pin 用一条 alerts 引用把事件钉住（PinnedIDs 的第一支：告警引用）。
func p0Pin(t *testing.T, ctx context.Context, client *ent.Client, ts time.Time, id uuid.UUID) {
	t.Helper()
	client.Alert.Create().SetTs(ts).SetRuleID("p0-pin").SetSeverity(3).SetEventID(id).SaveX(ctx)
}

// p0VerifiedRun 按固定口径跑影子归档并对拍通过：P0 的切换一律以 verified 的 run 为删除依据。
func p0VerifiedRun(t *testing.T, ctx context.Context, db *sql.DB, from, to time.Time) uuid.UUID {
	t.Helper()
	runID, err := Shadow(ctx, db, Options{From: from, To: to, Classes: p0Classes, Sources: p0Sources, Confirm: true})
	if err != nil {
		t.Fatalf("影子归档失败: %v", err)
	}
	if err := Verify(ctx, db, runID); err != nil {
		t.Fatalf("对拍失败: %v", err)
	}
	return runID
}

// p0ColdDayCount 用与 Swap.coldCount 相同的 SQL 数某 run 在某日的冷块事件条数，
// 让测试能独立核对「计数门禁」的现状，而不是复用被测代码的返回值。
func p0ColdDayCount(t *testing.T, ctx context.Context, db *sql.DB, runID uuid.UUID, day time.Time) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(sum(event_count), 0) FROM event_archive_chunks
 WHERE run_id = $1 AND day = $2`, runID, day).Scan(&n); err != nil {
		t.Fatalf("统计 run %s 在 %s 的冷块: %v", runID, day.Format(time.DateOnly), err)
	}
	return n
}

// p0HotExists 报告事件是否仍在热表。
func p0HotExists(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE id = $1)`, id).Scan(&ok); err != nil {
		t.Fatalf("查事件 %s: %v", id, err)
	}
	return ok
}

// p0RelExists 报告表是否存在。
func p0RelExists(t *testing.T, ctx context.Context, db *sql.DB, name string) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&ok); err != nil {
		t.Fatalf("查找 %s: %v", name, err)
	}
	return ok
}

// p0PartitionRows 数某日分区当前的行数。
func p0PartitionRows(t *testing.T, ctx context.Context, db *sql.DB, day time.Time) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+eventpart.DailyName(day)).Scan(&n); err != nil {
		t.Fatalf("统计分区 %s: %v", eventpart.DailyName(day), err)
	}
	return n
}

// routingOf 按 id 查行当前落在哪个物理分区（tableoid），用于断言 swap/retire/restore 的路由现状。
func routingOf(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var part sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT tableoid::regclass::text FROM events WHERE id = $1`, id).Scan(&part); err != nil {
		t.Fatalf("查 %s 的分区: %v", id, err)
	}
	if !part.Valid {
		t.Fatalf("事件 %s 不在 events 里，无从谈路由", id)
	}
	return part.String
}

// hotSnapshot 取一组事件在热表里的全字段快照（按 id 索引）。可空列用 '=值' 与 'NULL'
// 显式区分空串与 NULL，ts 打印数据库里实际保存的精度（RFC3339Nano），raw 用 jsonb 文本表示。
// 比较内容、不比条数：少一行、多一行或改一个字节都表现为 map 差异。
func hotSnapshot(t *testing.T, ctx context.Context, db *sql.DB, ids []uuid.UUID) map[uuid.UUID]string {
	t.Helper()
	out := make(map[uuid.UUID]string, len(ids))
	rows, err := db.QueryContext(ctx, `SELECT id, ts, class_uid, source,
 COALESCE(asset_id::text, 'NULL'), COALESCE(process_guid::text, 'NULL'),
 COALESCE(parent_process_guid::text, 'NULL'), COALESCE('=' || username, 'NULL'),
 COALESCE('=' || conn_tuple, 'NULL'), raw::text
 FROM events WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		t.Fatalf("读取热表快照: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id           uuid.UUID
			ts           time.Time
			class        int64
			source       string
			asset, proc  string
			parent, user string
			conn, raw    string
		)
		if err := rows.Scan(&id, &ts, &class, &source, &asset, &proc, &parent, &user, &conn, &raw); err != nil {
			t.Fatalf("读取热表快照行: %v", err)
		}
		out[id] = strings.Join([]string{
			ts.UTC().Format(time.RFC3339Nano), fmt.Sprintf("%d", class), source,
			asset, proc, parent, user, conn, raw,
		}, "|")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("读取热表快照: %v", err)
	}
	if len(out) != len(ids) {
		t.Fatalf("快照应覆盖全部 %d 条事件，实际取到 %d 条", len(ids), len(out))
	}
	return out
}

// assertHotEquals 断言当前热表内容与快照完全一致（集合相同、逐字段相同），差异逐条报出来。
func assertHotEquals(t *testing.T, ctx context.Context, db *sql.DB, ids []uuid.UUID, want map[uuid.UUID]string) {
	t.Helper()
	got := hotSnapshot(t, ctx, db, ids)
	for _, id := range ids {
		if got[id] != want[id] {
			t.Errorf("事件 %s 与快照不符：\n快照 %s\n当前 %s", id, want[id], got[id])
		}
	}
	if len(got) != len(want) {
		t.Errorf("快照集合大小不符：want %d 条，got %d 条", len(want), len(got))
	}
}

// assertHotRow 断言单条事件当前的热表内容与快照一致（供只比较部分行的场景）。
func assertHotRow(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID, want map[uuid.UUID]string) {
	t.Helper()
	got := hotSnapshot(t, ctx, db, []uuid.UUID{id})
	if got[id] != want[id] {
		t.Fatalf("事件 %s 与快照不符：\n快照 %s\n当前 %s", id, want[id], got[id])
	}
}

// evidenceSnapshot 取「证据关联内容」快照：alerts（含 event_id 关联）、
// temporal_detections（含 anchor 与 alert_id 的关联）、temporal_evidence（anchor/event 关联）。
// 内容级比较（逐行字段聚合摘要），不是只比行数。
func evidenceSnapshot(t *testing.T, ctx context.Context, db *sql.DB) map[string]string {
	t.Helper()
	out := map[string]string{}
	one := func(name, query string) {
		t.Helper()
		var digest sql.NullString
		if err := db.QueryRowContext(ctx, query).Scan(&digest); err != nil {
			t.Fatalf("快照 %s: %v", name, err)
		}
		out[name] = digest.String
	}
	one("alerts", `SELECT md5(string_agg(id::text || '|' || COALESCE(event_id::text,'NULL') || '|' ||
 rule_id || '|' || severity::text, ',' ORDER BY id)) FROM alerts`)
	one("temporal_detections", `SELECT md5(string_agg(revision || '|' || rule_id || '|' ||
 anchor_id::text || '|' || COALESCE(alert_id::text,'NULL'), ',' ORDER BY anchor_id, rule_id))
 FROM temporal_detections`)
	one("temporal_evidence", `SELECT md5(string_agg(revision || '|' || rule_id || '|' ||
 anchor_id::text || '|' || event_id::text, ',' ORDER BY anchor_id, event_id))
 FROM temporal_evidence`)
	return out
}

// p0SeedTemporalEvidence 造一组非空的证据关联：锚点告警、带 alert_id 的时序检测锚点，
// 以及一条指向锚点事件的时序证据。锚点事件因此被 PinnedIDs 的两支（alerts 引用与
// 已出告警的检测锚点）同时钉住。返回告警 id。锚点事件本身应留在不被切换的分区里。
func p0SeedTemporalEvidence(t *testing.T, ctx context.Context, db *sql.DB, anchor uuid.UUID, ts time.Time) uuid.UUID {
	t.Helper()
	var alertID uuid.UUID
	if err := db.QueryRowContext(ctx, `INSERT INTO alerts (id, ts, rule_id, severity, event_id)
 VALUES (gen_random_uuid(), $1, 'p0-anchor', 4, $2) RETURNING id`, ts, anchor).Scan(&alertID); err != nil {
		t.Fatalf("建锚点告警: %v", err)
	}
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO temporal_rule_snapshots(revision, document) VALUES('p0', '{}') ON CONFLICT DO NOTHING`, nil},
		{`INSERT INTO temporal_detections(revision, rule_id, anchor_id, group_id, entity, evidence, alert_id)
 VALUES('p0', 'p0-rule', $1, $2, 'host.process', '[]'::jsonb, $3)`, []any{anchor, uuid.New(), alertID}},
		{`INSERT INTO temporal_evidence(revision, rule_id, anchor_id, event_id)
 VALUES('p0', 'p0-rule', $1, $1)`, []any{anchor}},
	} {
		if _, err := db.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("造时序证据: %v", err)
		}
	}
	return alertID
}

// diverseFixture 是 seedDiverseDay 的产物：inScope 按特征名映射到 id（4001/agent 且未被
// 钉住 → 进冷块、可被 Swap 移出），pinned 是被 alert 引用的 4001，foreign 是类别外的 1007。
type diverseFixture struct {
	day     time.Time
	inScope map[string]uuid.UUID
	pinned  uuid.UUID
	foreign uuid.UUID
	assetID uuid.UUID
}

// inScopeIDs 返回全部口径内未钉住的事件 id（顺序固定：按特征名排序）。
func (f diverseFixture) inScopeIDs() []uuid.UUID {
	names := make([]string, 0, len(f.inScope))
	for name := range f.inScope {
		names = append(names, name)
	}
	slices.Sort(names)
	ids := make([]uuid.UUID, 0, len(names))
	for _, name := range names {
		ids = append(ids, f.inScope[name])
	}
	return ids
}

// allIDs 返回该日全部事件 id。
func (f diverseFixture) allIDs() []uuid.UUID {
	return append(append([]uuid.UUID{}, f.inScopeIDs()...), f.pinned, f.foreign)
}

// seedDiverseDay 播一组覆盖字段边界的事件（T10 的现状基线，P1 直接复用）：
//   - allnull：五个可空列（asset/进程/父进程/用户名/连接元组）全 NULL
//   - emptyuser：username=”（空串）与 conn_tuple=NULL 并存，进程 GUID 已填
//   - emptyconn：username=NULL 与 conn_tuple=” 并存，并挂资产
//   - nanots：亚秒精度 ts。PostgreSQL timestamptz 实际保留微秒，输入带纳秒会在落库时
//     截断；断言的是「数据库里真实保存的精度往返不变」（.123456）
//   - samets1 / samets2：同一 ts、不同 id 的两行
//   - bigraw：约 260 KiB 的 raw，含中文、emoji 与 \" \\ \u0001 \t 转义
//   - pinned：4001/agent 被 alert 引用（留热）
//   - foreign：1007（run 口径之外，留热）
func seedDiverseDay(t *testing.T, ctx context.Context, client *ent.Client, day time.Time) diverseFixture {
	t.Helper()
	f := diverseFixture{day: day, inScope: map[string]uuid.UUID{}}
	mk := func(ts time.Time) *ent.EventCreate {
		return client.Event.Create().SetTs(ts).SetClassUID(4001).SetSource("agent")
	}
	f.inScope["allnull"] = mk(day.Add(1 * time.Minute)).
		SetRaw(json.RawMessage(`{"mark":"allnull","conn":{"dst":"10.0.0.1:443"}}`)).SaveX(ctx).ID

	proc, parent := uuid.New(), uuid.New()
	f.inScope["emptyuser"] = mk(day.Add(2 * time.Minute)).
		SetProcessGUID(proc).SetParentProcessGUID(parent).SetUsername("").
		SetRaw(json.RawMessage(`{"mark":"emptyuser","file":{"path":"/tmp/空用户"}}`)).SaveX(ctx).ID

	asset := client.Asset.Create().SetHostname("p0-diversity").SaveX(ctx)
	f.assetID = asset.ID
	f.inScope["emptyconn"] = mk(day.Add(3 * time.Minute)).
		SetAssetID(asset.ID).SetConnTuple("").
		SetRaw(json.RawMessage(`{"mark":"emptyconn","conn":{"dst":"10.0.0.2:8443"}}`)).SaveX(ctx).ID

	f.inScope["nanots"] = mk(day.Add(4*time.Minute + 123456789*time.Nanosecond)).
		SetRaw(json.RawMessage(`{"mark":"nanots","ret":0}`)).SaveX(ctx).ID

	sameTs := day.Add(5 * time.Minute)
	f.inScope["samets1"] = mk(sameTs).
		SetRaw(json.RawMessage(`{"mark":"same-ts-a","conn":{"dst":"10.0.0.3:53"}}`)).SaveX(ctx).ID
	f.inScope["samets2"] = mk(sameTs).SetUsername("root").
		SetRaw(json.RawMessage(`{"mark":"same-ts-b","conn":{"dst":"10.0.0.4:53"}}`)).SaveX(ctx).ID

	pad := strings.Repeat(`值\"\\😀\u0001\t`, 14000) // 19 字节/次 × 14000 ≈ 260 KiB
	f.inScope["bigraw"] = mk(day.Add(6 * time.Minute)).
		SetRaw(json.RawMessage(`{"mark":"bigraw","pad":"` + pad + `"}`)).SaveX(ctx).ID

	f.pinned = mk(day.Add(7 * time.Minute)).
		SetRaw(json.RawMessage(`{"mark":"pinned","conn":{"dst":"10.0.0.9:22"}}`)).SaveX(ctx).ID
	p0Pin(t, ctx, client, day.Add(7*time.Minute), f.pinned)

	f.foreign = client.Event.Create().SetTs(day.Add(8 * time.Minute)).SetClassUID(1007).SetSource("agent").
		SetRaw(json.RawMessage(`{"mark":"foreign","process":{"pid":42}}`)).SaveX(ctx).ID
	return f
}

// 2d（restore 目标基线，现状固定，供 P1 对照）：swap 移出 A/B → 同日写入新事件 E →
// Restore 只物化冷块里的 A/B：E 原样不动，A/B 逐字段回到热表（含路由回该日分区）；
// 重复 Restore 插入 0 行；alerts / temporal_* 的关联内容前后不变。
func TestP0RestoreBaselineKeepsLaterRowsAndEvidence(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)

	// 证据关联放在今天（不在被切换的那天），保证「不变」不是「本来就是空的」
	anchor := p0Event(t, ctx, client, p0Today().Add(time.Minute), 4001, "agent", `{"mark":"anchor"}`)
	p0SeedTemporalEvidence(t, ctx, db, anchor, p0Today().Add(time.Minute))

	a := p0Event(t, ctx, client, day.Add(10*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(20*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
	ab := []uuid.UUID{a, b}
	before := hotSnapshot(t, ctx, db, ab)
	evBefore := evidenceSnapshot(t, ctx, db)
	if evBefore["alerts"] == "" {
		t.Fatal("测试前提：证据快照不应为空")
	}

	runID := p0VerifiedRun(t, ctx, db, day, day)
	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if got := p0PartitionRows(t, ctx, db, day); got != 0 {
		t.Fatalf("切换后该日分区应为空（A/B 已移出），实际 %d 行", got)
	}
	// swap 之后、restore 之前写入同日新事件：restore 不该动它，也不该把它算进恢复集
	e := p0Event(t, ctx, client, day.Add(23*time.Hour), 4001, "agent", `{"mark":"E","conn":{"dst":"10.0.0.5:443"}}`)
	snapE := hotSnapshot(t, ctx, db, []uuid.UUID{e})

	n, err := Restore(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if n != 2 {
		t.Fatalf("现状：Restore 应物化冷块里的 A/B 共 2 条，实际插入 %d 条", n)
	}
	assertHotEquals(t, ctx, db, ab, before)
	assertHotEquals(t, ctx, db, []uuid.UUID{e}, snapE)
	for _, id := range []uuid.UUID{a, b, e} {
		if got := routingOf(t, ctx, db, id); got != eventpart.DailyName(day) {
			t.Fatalf("事件 %s 应路由回日分区 %s，实际 %s", id, eventpart.DailyName(day), got)
		}
	}
	if got := p0PartitionRows(t, ctx, db, day); got != 3 {
		t.Fatalf("还原后该日分区应有 3 行（A/B/E），实际 %d 行", got)
	}

	again, err := Restore(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("第二次 Restore: %v", err)
	}
	if again != 0 {
		t.Fatalf("现状：稳定环境下第二次 Restore 应插入 0 行，实际 %d", again)
	}
	if evAfter := evidenceSnapshot(t, ctx, db); !sameMap(evAfter, evBefore) {
		t.Fatalf("restore 前后证据关联内容发生变化：\n前 %v\n后 %v", evBefore, evAfter)
	}
}

// 2e（单条 Materialize 字段保真基线，T10 的现状版）：seedDiverseDay 的每一行物化后
// 全字段与原行一致——NULL 与空串区分、亚秒精度、大 raw/转义字符逐字节相同；
// 已在热表（冷层没有）的行不覆盖；冷层确实没有的事件返回 false 且不插行；重复物化幂等。
func TestP0MaterializeFieldFidelityBaseline(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	f := seedDiverseDay(t, ctx, client, day)

	all := f.allIDs()
	before := hotSnapshot(t, ctx, db, all)
	// 特征抽查：NULL 与空串必须可区分，纳秒输入被 PostgreSQL 截断到微秒后仍要原样往返
	if s := before[f.inScope["allnull"]]; !strings.Contains(s, "|NULL|NULL|NULL|NULL|NULL|") {
		t.Fatalf("allnull 行的可空列应全为 NULL：%s", s)
	}
	if s := before[f.inScope["emptyuser"]]; !strings.Contains(s, "|=|NULL|") {
		t.Fatalf("emptyuser 行应是 username=''(=) 且 conn_tuple=NULL：%s", s)
	}
	if s := before[f.inScope["emptyconn"]]; !strings.Contains(s, "|NULL|=|") {
		t.Fatalf("emptyconn 行应是 username=NULL 且 conn_tuple=''(=)：%s", s)
	}
	if s := before[f.inScope["nanots"]]; !strings.Contains(s, ".123456") {
		t.Fatalf("nanots 行应保留微秒精度 .123456：%s", s)
	}
	if s := before[f.inScope["bigraw"]]; len(s) < 256<<10 {
		t.Fatalf("bigraw 行的 raw 文本应约 260 KiB，实际 %d 字节", len(s))
	}

	runID := p0VerifiedRun(t, ctx, db, day, day)
	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	inScope := f.inScopeIDs()
	for _, id := range inScope {
		if p0HotExists(t, ctx, db, id) {
			t.Fatalf("事件 %s 应已随 Swap 移出热表", id)
		}
	}
	for _, id := range inScope {
		inserted, err := Materialize(ctx, db, id)
		if err != nil {
			t.Fatalf("物化 %s: %v", id, err)
		}
		if !inserted {
			t.Fatalf("物化 %s 应返回 inserted=true", id)
		}
	}
	assertHotEquals(t, ctx, db, all, before)

	// 被钉住的行与类别外的行从未进冷块：物化返回 false、不覆盖热表内容
	for name, id := range map[string]uuid.UUID{"pinned": f.pinned, "foreign": f.foreign} {
		inserted, err := Materialize(ctx, db, id)
		if err != nil {
			t.Fatalf("物化 %s: %v", name, err)
		}
		if inserted {
			t.Fatalf("%s 行不在冷层，物化不应报告插入", name)
		}
	}
	// 冷层确实没有的事件：inserted=false 且不插行
	absent := uuid.New()
	inserted, err := Materialize(ctx, db, absent)
	if err != nil || inserted {
		t.Fatalf("不存在的事件应返回 (false, nil)，实际 (%v, %v)", inserted, err)
	}
	if p0HotExists(t, ctx, db, absent) {
		t.Fatal("不存在的事件不该被插入任何行")
	}
	// 重复物化（热表已有 + 冷层有）：幂等
	inserted, err = Materialize(ctx, db, f.inScope["bigraw"])
	if err != nil || inserted {
		t.Fatalf("重复物化应返回 (false, nil)，实际 (%v, %v)", inserted, err)
	}
	assertHotEquals(t, ctx, db, all, before)
}

// 2f（超大事件，已翻转，HEAD=本次改动）：raw 编码后超过 MaxEventBytes 的事件不进冷块，
// shadow 如实记 detail.oversized / oversized_ids。旧实现要求「冷块条数 == 待移出条数」，
// 差额整日拒绝。P3 起超大行不在本 run 的 locator → 不进删除集 D → 留热，Swap 照常移出
// 其余有冷副本的行；断言超大行留热、其余移出、无静默丢失（§P3 第 8 条的「执行时没有
// 可删事件则报告无需操作」由 p3_swap_guards 的 noop 用例覆盖）。
func TestP0OversizedEventStaysHotOnSwap(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)
	a := p0Event(t, ctx, client, day.Add(1*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(2*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
	big := p0Event(t, ctx, client, day.Add(3*time.Minute), 4001, "agent",
		`{"blob":"`+strings.Repeat("x", MaxEventBytes)+`"}`)

	runID := p0VerifiedRun(t, ctx, db, day, day)
	run, err := LoadRun(ctx, db, runID)
	if err != nil {
		t.Fatal(err)
	}
	var detail struct {
		Oversized    int64    `json:"oversized"`
		OversizedIDs []string `json:"oversized_ids"`
	}
	if err := json.Unmarshal(run.Detail, &detail); err != nil {
		t.Fatalf("解析 run detail: %v", err)
	}
	if detail.Oversized != 1 || len(detail.OversizedIDs) != 1 || detail.OversizedIDs[0] != big.String() {
		t.Fatalf("detail.oversized 应只记超大事件 %s，实际 %+v", big, detail)
	}

	p, err := Plan(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if p.Archived != 3 {
		t.Fatalf("超大事件也在归档口径里，Archived 应为 3，实际 %+v", p)
	}
	if cold := p0ColdDayCount(t, ctx, db, runID, day); cold != 2 {
		t.Fatalf("冷块里应只有 A/B 共 2 条，实际 %d", cold)
	}
	// P3 翻转：不再整日拒绝——超大行留热，其余照常移出
	got, err := Swap(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("P3：超大行留热、A/B 移出，Swap 应照常执行，实际 %v", err)
	}
	if got.Kept != 1 || got.Dropped != 2 {
		t.Fatalf("事务内实测应是 kept=1（超大行）/ dropped=2（A/B），实际 kept=%d dropped=%d", got.Kept, got.Dropped)
	}
	if !p0HotExists(t, ctx, db, big) {
		t.Fatal("P3：超大行没有冷副本，必须留在热表（无静默丢）")
	}
	for _, id := range []uuid.UUID{a, b} {
		if p0HotExists(t, ctx, db, id) {
			t.Fatalf("事件 %s 有冷副本，应已移出热表", id)
		}
		if _, found, err := Locate(ctx, db, id); err != nil || !found {
			t.Fatalf("事件 %s 的冷副本必须可定位：found=%v err=%v", id, found, err)
		}
	}
	if n := p0PartitionRows(t, ctx, db, day); n != 1 {
		t.Fatalf("切换后日分区应只剩超大行 1 行，实际 %d 行", n)
	}
	if p0RelExists(t, ctx, db, eventpart.DailyName(day)+"_rewrite") {
		t.Fatal("成功的切换不该留下暂存表")
	}
	// 逐日记录如实写差额：预检 note 解释了 3 − 2 = 1 行没有冷副本留热
	days := p3DayRecords(t, ctx, db, runID)
	rec, ok := days[day.Format(time.DateOnly)]
	if !ok || rec.Kept != 1 || rec.Dropped != 2 || !rec.RunDayVerified {
		t.Fatalf("detail.days.%s 应是 kept=1 dropped=2 run_day_verified=true，实际 %+v",
			day.Format(time.DateOnly), days[day.Format(time.DateOnly)])
	}
	if !strings.Contains(rec.Note, "没有冷副本") {
		t.Fatalf("预检发现的差额应写进 note 供运维解释，实际 %q", rec.Note)
	}
}

// 2g（retire 后 restore 的路由现状，T21/V12·C 项的现状版）：同一天依次
// swap(day) → Retire(day) → Restore(run, day)。退役走 eventpart.Retire（与 janitor 同一入口，
// cutoff=该日结束即只退役不晚于它的日分区）。现状记录：
//   - restore 不撤销退役：恢复行按当前分区路由落进该月归档分区 events_aYYYYMM，
//     而不是重建日分区；
//   - 被 pin 的锚点行随退役并进归档分区且逐字段不变；
//   - 这些恢复行没有 pin，之后仍可能被 janitor 到期再次清理。
func TestP0RestoreRoutingAfterRetireBaseline(t *testing.T) {
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 40)
	// P4 闸门夹具前提:min-age 归零 + 播种消费者持久进度(闸门语义在 p4_*.go 正面覆盖)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	p4SeedConsumed(t, ctx, db, day)

	pin := p0Event(t, ctx, client, day.Add(1*time.Minute), 4001, "agent", `{"mark":"pin","conn":{"dst":"10.0.0.9:22"}}`)
	p0Pin(t, ctx, client, day.Add(1*time.Minute), pin)
	a := p0Event(t, ctx, client, day.Add(2*time.Minute), 4001, "agent", `{"mark":"A","conn":{"dst":"10.0.0.1:443"}}`)
	b := p0Event(t, ctx, client, day.Add(3*time.Minute), 4001, "agent", `{"mark":"B","conn":{"dst":"10.0.0.2:443"}}`)
	ab := []uuid.UUID{a, b}
	before := hotSnapshot(t, ctx, db, []uuid.UUID{pin, a, b})

	runID := p0VerifiedRun(t, ctx, db, day, day)
	if _, err := Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if !p0HotExists(t, ctx, db, pin) || p0HotExists(t, ctx, db, a) || p0HotExists(t, ctx, db, b) {
		t.Fatal("切换后应只有被 pin 的行留在热表")
	}
	if got := routingOf(t, ctx, db, pin); got != eventpart.DailyName(day) {
		t.Fatalf("pin 行应在日分区 %s，实际 %s", eventpart.DailyName(day), got)
	}

	// 退役该日：cutoff 取该日结束，只有上界不晚于它的日分区会被退役。
	month := time.Date(day.Year(), day.Month(), 1, 0, 0, 0, 0, time.UTC)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+eventpart.ArchiveName(month))
	})
	retired, dropped, err := eventpart.Retire(ctx, db, day.AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if retired < 1 {
		t.Fatalf("至少应退役 %s 这一个日分区，实际 %d 个", day.Format(time.DateOnly), retired)
	}
	if dropped != 0 {
		t.Fatalf("swap 之后该分区只剩被 pin 的一行，退役应并进归档分区而不丢弃（dropped=%d）", dropped)
	}
	if p0RelExists(t, ctx, db, eventpart.DailyName(day)) {
		t.Fatal("退役后日分区不应再存在")
	}
	if got := routingOf(t, ctx, db, pin); got != eventpart.ArchiveName(month) {
		t.Fatalf("pin 行应随退役并进 %s，实际 %s", eventpart.ArchiveName(month), got)
	}
	assertHotRow(t, ctx, db, pin, before)

	n, err := Restore(ctx, db, runID, day)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if n != 2 {
		t.Fatalf("现状：退役后 Restore 仍应物化冷块里的 A/B 共 2 条，实际 %d", n)
	}
	for _, id := range ab {
		if got := routingOf(t, ctx, db, id); got != eventpart.ArchiveName(month) {
			t.Fatalf("现状：恢复行 %s 应按当前分区路由落进 %s（或 default），实际 %s",
				id, eventpart.ArchiveName(month), got)
		}
	}
	assertHotRow(t, ctx, db, a, before)
	assertHotRow(t, ctx, db, b, before)
	assertHotRow(t, ctx, db, pin, before)
	// 现状记录：restore 不重新创建与月归档重叠的日分区，也不重置热保留期；
	// 未 pin 的恢复行到期后会被 janitor 再次清理。
}

// sameMap 比较两个 string→string 快照是否完全一致。
func sameMap(a, b map[string]string) bool {
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
