//go:build integration

package eventpart_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/testdb"
)

func open(t *testing.T) (context.Context, *ent.Client, *sql.DB) {
	t.Helper()
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := ingest.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	// 上个测试留下的历史日分区与归档分区不能影响本测试的退役判断
	rows, err := db.QueryContext(ctx, `SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
 WHERE i.inhparent = 'events'::regclass AND c.relname <> 'events_default'`)
	if err != nil {
		t.Fatal(err)
	}
	var stale []string
	for rows.Next() {
		var name string
		rows.Scan(&name)
		stale = append(stale, name)
	}
	rows.Close()
	for _, name := range stale {
		if _, err := db.ExecContext(ctx, `DROP TABLE `+name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := eventpart.EnsureDays(ctx, db, eventpart.Parent, eventpart.Today(), eventpart.PremakeDays); err != nil {
		t.Fatal(err)
	}
	return ctx, client, db
}

func newEvent(t *testing.T, ctx context.Context, client *ent.Client, ts time.Time) *ent.Event {
	t.Helper()
	return client.Event.Create().SetTs(ts).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
}

func partitionOf(t *testing.T, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var name string
	if err := db.QueryRow(`SELECT tableoid::regclass::text FROM events WHERE id = $1`, id).Scan(&name); err != nil {
		return ""
	}
	return name
}

func exists(t *testing.T, db *sql.DB, query string, args ...any) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRow(`SELECT EXISTS(`+query+`)`, args...).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

// 新库直接是分区表：主键含 ts、没有任何外键指向 events、今天起的日分区已预建，异常时间戳落默认分区。
func TestFreshSchemaIsPartitioned(t *testing.T) {
	ctx, client, db := open(t)
	if ok, err := eventpart.Partitioned(ctx, db); err != nil || !ok {
		t.Fatalf("events 应为分区表: %v %v", ok, err)
	}
	var pk string
	if err := db.QueryRow(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'events'::regclass AND contype = 'p'`).Scan(&pk); err != nil || pk != "PRIMARY KEY (id, ts)" {
		t.Fatalf("主键应为 (id, ts): %q %v", pk, err)
	}
	if exists(t, db, `SELECT 1 FROM pg_constraint WHERE confrelid = 'events'::regclass`) {
		t.Fatal("分区表不应被任何外键引用")
	}
	today := eventpart.Today()
	for i := 0; i <= eventpart.PremakeDays; i++ {
		if !exists(t, db, `SELECT 1 FROM pg_class WHERE relname = $1`, eventpart.DailyName(today.AddDate(0, 0, i))) {
			t.Fatalf("缺预建分区 %s", eventpart.DailyName(today.AddDate(0, 0, i)))
		}
	}
	now := newEvent(t, ctx, client, time.Now())
	future := newEvent(t, ctx, client, today.AddDate(1, 0, 0))
	ancient := newEvent(t, ctx, client, time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC))
	if got := partitionOf(t, db, now.ID); got != eventpart.DailyName(today) {
		t.Fatalf("当天事件落在 %s", got)
	}
	for _, e := range []*ent.Event{future, ancient} {
		if got := partitionOf(t, db, e.ID); got != eventpart.DefaultName {
			t.Fatalf("没有日分区的事件应落默认分区，实际 %s", got)
		}
	}
	// 再跑一遍迁移：ent 不碰分区表，也不补回外键
	if err := eventpart.Migrate(ctx, client, db); err != nil {
		t.Fatalf("重复迁移失败: %v", err)
	}
	if exists(t, db, `SELECT 1 FROM pg_constraint WHERE confrelid = 'events'::regclass`) {
		t.Fatal("重复迁移不应补回指向 events 的外键")
	}
}

// 预建分区时把默认分区里属于该日的行搬进新分区；已存在的分区不重复建。
func TestEnsureDaysMovesDefaultRows(t *testing.T) {
	ctx, client, db := open(t)
	day := eventpart.Today().AddDate(0, 0, 30)
	e := newEvent(t, ctx, client, day.Add(5*time.Hour))
	if got := partitionOf(t, db, e.ID); got != eventpart.DefaultName {
		t.Fatalf("预建范围外的事件应先落默认分区，实际 %s", got)
	}
	if _, err := db.Exec(`INSERT INTO temporal_matches(rule_id,event_id) VALUES('m',$1)`, e.ID); err != nil {
		t.Fatal(err)
	}
	n, err := eventpart.EnsureDays(ctx, db, eventpart.Parent, day, 0)
	if err != nil || n != 1 {
		t.Fatalf("应新建 1 个分区: %d %v", n, err)
	}
	if got := partitionOf(t, db, e.ID); got != eventpart.DailyName(day) {
		t.Fatalf("默认分区的行应搬进新日分区，实际 %s", got)
	}
	if !exists(t, db, `SELECT 1 FROM temporal_matches WHERE event_id = $1`, e.ID) {
		t.Fatal("搬分区不是删除，派生状态不能被级联清掉")
	}
	if n, err := eventpart.EnsureDays(ctx, db, eventpart.Parent, day, 0); err != nil || n != 0 {
		t.Fatalf("已有分区不应重建: %d %v", n, err)
	}
	// 新分区继承父表的索引与触发器
	var idx, trg int
	db.QueryRow(`SELECT count(*) FROM pg_index WHERE indrelid = $1::regclass`, eventpart.DailyName(day)).Scan(&idx)
	db.QueryRow(`SELECT count(*) FROM pg_trigger WHERE tgrelid = $1::regclass AND tgname IN ('openxdr_events_release', 'openxdr_events_evidence')`, eventpart.DailyName(day)).Scan(&trg)
	if idx < 5 || trg != 2 {
		t.Fatalf("新分区应带齐索引与触发器: %d 个索引 %d 个触发器", idx, trg)
	}
}

// 退役：证据并进月归档分区，无引用的随分区删除，派生状态按原级联口径清理；
// 默认分区里落在归档范围的行一起并入；退役后迟到写入该范围的事件进归档分区而非报错。
func TestRetireKeepsEvidenceAndDropsTheRest(t *testing.T) {
	ctx, client, db := open(t)
	d10 := time.Date(2020, 1, 10, 0, 0, 0, 0, time.UTC)
	if n, err := eventpart.EnsureDays(ctx, db, eventpart.Parent, d10, 2); err != nil || n != 3 {
		t.Fatalf("建历史日分区: %d %v", n, err)
	}
	plain := newEvent(t, ctx, client, d10.Add(time.Hour))
	alerted := newEvent(t, ctx, client, d10.Add(2*time.Hour))
	evidence := newEvent(t, ctx, client, d10.AddDate(0, 0, 1).Add(time.Hour))
	anchor := newEvent(t, ctx, client, d10.AddDate(0, 0, 1).Add(2*time.Hour))
	unanchored := newEvent(t, ctx, client, d10.AddDate(0, 0, 1).Add(3*time.Hour))
	kept := newEvent(t, ctx, client, d10.AddDate(0, 0, 2).Add(time.Hour))
	stray := newEvent(t, ctx, client, d10.AddDate(0, 0, -5))
	if partitionOf(t, db, stray.ID) != eventpart.DefaultName {
		t.Fatal("没有日分区的历史事件应在默认分区")
	}
	for _, ev := range []*ent.Event{plain, alerted} {
		client.Event.UpdateOneID(ev.ID).SetClassUID(4001).SaveX(ctx)
		if _, err := db.ExecContext(ctx, `INSERT INTO assetmap_queue(event_id,event_ts) VALUES($1,$2)`, ev.ID, ev.Ts); err != nil {
			t.Fatal(err)
		}
	}
	alert := client.Alert.Create().SetTs(alerted.Ts).SetRuleID("r").SetSeverity(3).SetEventID(alerted.ID).SaveX(ctx)
	group := uuid.New()
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO temporal_rule_snapshots(revision,document) VALUES('v','{}') ON CONFLICT DO NOTHING`, nil},
		{`INSERT INTO temporal_matches(rule_id,event_id) VALUES('m',$1),('m',$2)`, []any{plain.ID, alerted.ID}},
		{`INSERT INTO temporal_detections(revision,rule_id,anchor_id,group_id,entity,evidence,alert_id) VALUES('v','seq',$1,$2,'asset','[]',$3)`, []any{anchor.ID, group, alert.ID}},
		{`INSERT INTO temporal_evidence(revision,rule_id,anchor_id,event_id) VALUES('v','seq',$1,$2)`, []any{anchor.ID, evidence.ID}},
		{`INSERT INTO temporal_detections(revision,rule_id,anchor_id,group_id,entity,evidence) VALUES('v','seq',$1,$2,'asset','[]')`, []any{unanchored.ID, group}},
	} {
		if _, err := db.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}

	retired, dropped, err := eventpart.Retire(ctx, db, d10.AddDate(0, 0, 2))
	if err != nil || retired != 2 || dropped != 2 {
		t.Fatalf("应退役 10、11 日两个分区并丢弃 2 条无引用事件: %d %d %v", retired, dropped, err)
	}
	archive := eventpart.ArchiveName(d10)
	for _, e := range []*ent.Event{alerted, evidence, anchor, stray} {
		if got := partitionOf(t, db, e.ID); got != archive {
			t.Fatalf("事件 %s 应在归档分区，实际 %q", e.ID, got)
		}
	}
	for _, e := range []*ent.Event{plain, unanchored} {
		if got := partitionOf(t, db, e.ID); got != "" {
			t.Fatalf("无引用事件应随分区删除，实际在 %q", got)
		}
	}
	if got := partitionOf(t, db, kept.ID); got != eventpart.DailyName(d10.AddDate(0, 0, 2)) {
		t.Fatalf("未到期分区不应退役: %q", got)
	}
	if exists(t, db, `SELECT 1 FROM assetmap_queue WHERE event_id=$1`, plain.ID) || !exists(t, db, `SELECT 1 FROM assetmap_queue WHERE event_id=$1`, alerted.ID) {
		t.Fatal("退役应清理被删除事件的图谱待办，并保留归档事件待办")
	}
	if exists(t, db, `SELECT 1 FROM temporal_matches WHERE event_id = $1`, plain.ID) || !exists(t, db, `SELECT 1 FROM temporal_matches WHERE event_id = $1`, alerted.ID) {
		t.Fatal("派生状态应只随被删事件清理")
	}
	if exists(t, db, `SELECT 1 FROM temporal_detections WHERE anchor_id = $1`, unanchored.ID) || !exists(t, db, `SELECT 1 FROM temporal_evidence WHERE event_id = $1`, evidence.ID) {
		t.Fatal("未出告警的时序锚点应清理，出了告警的证据链应保留")
	}
	var bound string
	db.QueryRow(`SELECT pg_get_expr(relpartbound, oid) FROM pg_class WHERE relname = $1`, archive).Scan(&bound)
	if bound != "FOR VALUES FROM ('2020-01-01 00:00:00+00') TO ('2020-01-12 00:00:00+00')" {
		t.Fatalf("归档分区范围不对: %s", bound)
	}

	// 迟到事件写进已退役的范围：进归档分区
	late := newEvent(t, ctx, client, d10.Add(3*time.Hour))
	if got := partitionOf(t, db, late.ID); got != archive {
		t.Fatalf("迟到事件应进归档分区，实际 %q", got)
	}
	// 再退役一天：归档分区原样并入，上界推进
	if retired, dropped, err := eventpart.Retire(ctx, db, d10.AddDate(0, 0, 3)); err != nil || retired != 1 || dropped != 1 {
		t.Fatalf("再退役 12 日: %d %d %v", retired, dropped, err)
	}
	for _, e := range []*ent.Event{alerted, evidence, anchor, stray, late} {
		if got := partitionOf(t, db, e.ID); got != archive {
			t.Fatalf("归档重建后事件 %s 丢失或位置不对: %q", e.ID, got)
		}
	}
	if retired, _, err := eventpart.Retire(ctx, db, d10.AddDate(0, 0, 3)); err != nil || retired != 0 {
		t.Fatalf("重复退役应无事可做: %d %v", retired, err)
	}
	oldest, ok, err := eventpart.OldestDaily(ctx, db)
	if err != nil || !ok || !oldest.Equal(eventpart.Today()) {
		t.Fatalf("最老日分区应为今天: %v %v %v", oldest, ok, err)
	}
}

// 替代外键的触发器：逐行删除事件时级联清派生状态，仍是时序证据的事件提交时拒绝删除；
// 同一语句里证据随锚点一起级联掉时允许（原外键 DEFERRABLE INITIALLY DEFERRED 的语义）。
func TestReleaseTriggersReplaceForeignKeys(t *testing.T) {
	ctx, client, db := open(t)
	now := time.Now()
	plain, anchor, evidence := newEvent(t, ctx, client, now), newEvent(t, ctx, client, now), newEvent(t, ctx, client, now)
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO temporal_rule_snapshots(revision,document) VALUES('v','{}') ON CONFLICT DO NOTHING`, nil},
		{`INSERT INTO temporal_matches(rule_id,event_id) VALUES('m',$1)`, []any{plain.ID}},
		{`INSERT INTO temporal_detections(revision,rule_id,anchor_id,group_id,entity,evidence) VALUES('v','seq',$1,$2,'asset','[]')`, []any{anchor.ID, uuid.New()}},
		{`INSERT INTO temporal_evidence(revision,rule_id,anchor_id,event_id) VALUES('v','seq',$1,$2)`, []any{anchor.ID, evidence.ID}},
	} {
		if _, err := db.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`DELETE FROM events WHERE id = $1`, plain.ID); err != nil {
		t.Fatal(err)
	}
	if exists(t, db, `SELECT 1 FROM temporal_matches WHERE event_id = $1`, plain.ID) {
		t.Fatal("删除事件应级联清理派生状态")
	}
	if _, err := db.Exec(`DELETE FROM events WHERE id = $1`, evidence.ID); err == nil {
		t.Fatal("仍是时序证据的事件不能删除")
	}
	if _, err := db.Exec(`DELETE FROM events WHERE id IN ($1, $2)`, evidence.ID, anchor.ID); err != nil {
		t.Fatalf("锚点与证据同一语句删除应通过: %v", err)
	}
	if exists(t, db, `SELECT 1 FROM temporal_evidence WHERE event_id = $1`, evidence.ID) {
		t.Fatal("证据应随锚点级联删除")
	}
}

// 父表上一直有读事务时，退役不排队等锁：等待期间别的写入照常进行，读一结束就拿到锁完成；
// 超过尝试时长明确报错，不留半截状态。
func TestRetireWaitsForParentLockWithoutQueueing(t *testing.T) {
	ctx, client, db := open(t)
	d10 := time.Date(2020, 1, 10, 0, 0, 0, 0, time.UTC)
	if _, err := eventpart.EnsureDays(ctx, db, eventpart.Parent, d10, 0); err != nil {
		t.Fatal(err)
	}
	old := newEvent(t, ctx, client, d10.Add(time.Hour))

	hold := func() *sql.Tx {
		reader, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.ExecContext(ctx, `SELECT count(*) FROM events`); err != nil {
			t.Fatal(err)
		}
		return reader
	}

	defer eventpart.SetParentLockWait(200 * time.Millisecond)()
	reader := hold()
	if _, _, err := eventpart.Retire(ctx, db, d10.AddDate(0, 0, 1)); err == nil {
		t.Fatal("父表一直被占用时退役应在尝试时长后报错")
	}
	_ = reader.Rollback()
	if !exists(t, db, `SELECT 1 FROM events WHERE id = $1`, old.ID) {
		t.Fatal("失败的退役不应删掉任何事件")
	}

	eventpart.SetParentLockWait(10 * time.Second)
	reader = hold()
	done := make(chan error, 1)
	go func() { _, _, err := eventpart.Retire(ctx, db, d10.AddDate(0, 0, 1)); done <- err }()
	time.Sleep(500 * time.Millisecond)
	start := time.Now()
	newEvent(t, ctx, client, time.Now())
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("退役等锁期间写入被堵了 %s", waited)
	}
	select {
	case err := <-done:
		t.Fatalf("读事务没结束，退役不应完成: %v", err)
	default:
	}
	_ = reader.Rollback()
	if err := <-done; err != nil {
		t.Fatalf("读事务结束后退役应完成: %v", err)
	}
	if exists(t, db, `SELECT 1 FROM events WHERE id = $1`, old.ID) {
		t.Fatal("无引用的过期事件应随分区退役删掉")
	}
}
