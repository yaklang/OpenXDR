//go:build integration

package eventpart_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/graphqueue"
)

type logWriter struct{ t *testing.T }

func (w logWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// legacySchema 把测试库的 events 换回迁移前的样子：ent 建的普通表、主键 id、
// 派生表与告警的外键都指向它，另有一个依赖它的视图（模拟 AI 组视图）。
func legacySchema(t *testing.T, ctx context.Context, client *ent.Client, db *sql.DB) {
	t.Helper()
	t.Cleanup(func() { restoreSchema(t, client, db) })
	stmts := []string{
		`CREATE EXTENSION IF NOT EXISTS pg_trgm`,
		`DROP TABLE events`,
		`CREATE TABLE events (id uuid NOT NULL, ts timestamptz NOT NULL, class_uid bigint NOT NULL, source varchar NOT NULL,
 process_guid uuid, parent_process_guid uuid, username varchar, conn_tuple varchar, raw jsonb NOT NULL, asset_id uuid,
 CONSTRAINT events_pkey PRIMARY KEY (id),
 CONSTRAINT events_assets_events FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL)`,
		`CREATE INDEX event_ts ON events (ts)`,
		`CREATE INDEX event_asset_id_ts ON events (asset_id, ts)`,
		`CREATE INDEX event_process_guid ON events (process_guid)`,
		`CREATE INDEX event_parent_process_guid ON events (parent_process_guid)`,
		`CREATE INDEX events_raw_trgm ON events USING gin ((raw::text) gin_trgm_ops)`,
		`ALTER TABLE alerts ADD CONSTRAINT alerts_events_alerts FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE SET NULL`,
		`ALTER TABLE temporal_evidence ADD CONSTRAINT temporal_evidence_event_id_fkey FOREIGN KEY (event_id) REFERENCES events(id) DEFERRABLE INITIALLY DEFERRED`,
		`CREATE SCHEMA IF NOT EXISTS migration_view_test`,
		`CREATE VIEW migration_view_test.events WITH (security_barrier) AS SELECT id, ts, raw FROM public.events WHERE class_uid = 1007`,
	}
	for _, d := range []struct{ table, column string }{
		{"temporal_matches", "event_id"}, {"temporal_candidates", "event_id"}, {"temporal_evaluation_gaps", "event_id"},
		{"temporal_detections", "anchor_id"}, {"identity_observations", "event_id"}, {"identity_local_snapshots", "event_id"},
	} {
		stmts = append(stmts, `ALTER TABLE `+d.table+` ADD CONSTRAINT `+d.table+`_`+d.column+`_fkey FOREIGN KEY (`+d.column+`) REFERENCES events(id) ON DELETE CASCADE`)
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%v\n%s", err, stmt)
		}
	}
	// 与生产老库一致：资产图谱队列给普通表挂了自己的删除触发器
	if err := graphqueue.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
}

// assetmapTrigger 返回挂着资产图谱队列删除触发器的表名（没有则为空）。
func assetmapTrigger(t *testing.T, db *sql.DB) string {
	t.Helper()
	var table string
	if err := db.QueryRow(`SELECT coalesce(string_agg(tgrelid::regclass::text, ','), '') FROM pg_trigger WHERE tgname = 'openxdr_assetmap_release'`).Scan(&table); err != nil {
		t.Fatal(err)
	}
	return table
}

// restoreSchema 不论测试停在哪一步，都把库恢复成 server 新建库的样子，免得影响后面的测试。
func restoreSchema(t *testing.T, client *ent.Client, db *sql.DB) {
	ctx := context.Background()
	for _, stmt := range []string{
		`DROP SCHEMA IF EXISTS migration_view_test CASCADE`,
		`DROP TABLE IF EXISTS events_next, events_old, event_partition_migration CASCADE`,
		`DROP FUNCTION IF EXISTS openxdr_events_mirror() CASCADE`,
		`DO $$ BEGIN IF (SELECT relkind FROM pg_class WHERE oid = to_regclass('events')) = 'r' THEN DROP TABLE events CASCADE; END IF; END $$`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Errorf("恢复测试库: %v", err)
		}
	}
	if err := eventpart.Migrate(ctx, client, db); err != nil {
		t.Errorf("恢复分区表: %v", err)
	}
}

func step(t *testing.T, m *eventpart.Migrator, ctx context.Context, name string) {
	t.Helper()
	if err := m.Run(ctx, name, true, ""); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func count(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%v\n%s", err, query)
	}
	return n
}

func viewTarget(t *testing.T, db *sql.DB) string {
	t.Helper()
	var target string
	if err := db.QueryRow(`SELECT DISTINCT d.refobjid::regclass::text FROM pg_depend d JOIN pg_rewrite r ON r.oid = d.objid
 WHERE r.ev_class = 'migration_view_test.events'::regclass AND d.refobjid <> r.ev_class AND d.refclassid = 'pg_class'::regclass`).Scan(&target); err != nil {
		t.Fatal(err)
	}
	return target
}

// 在线迁移全流程：前置检查与空间不足拒绝、未确认拒绝、回填中断续跑、镜像同步迁移期间的写入与删除、
// 核对发现并修复差异、切换后计数一致且外键去掉视图重绑、回滚恢复外键、再次切换并收尾，最后由退役接手。
func TestOnlineMigrationFullFlow(t *testing.T) {
	ctx, client, db := open(t)
	legacySchema(t, ctx, client, db)
	m := &eventpart.Migrator{DB: db, Out: logWriter{t}, RetentionDays: 30, Chunk: 6 * time.Hour, LockTimeout: 5 * time.Second,
		Free: func() (uint64, error) { return 1 << 40, nil }}

	asset := client.Asset.Create().SetHostname("m1").SaveX(ctx)
	today := eventpart.Today()
	mk := func(ts time.Time) uuid.UUID {
		id := uuid.New()
		if _, err := db.Exec(`INSERT INTO events (id, ts, class_uid, source, asset_id, raw) VALUES ($1, $2, 1007, 'agent', $3, '{"k":"v"}')`, id, ts, asset.ID); err != nil {
			t.Fatal(err)
		}
		return id
	}
	evidence := mk(today.AddDate(0, 0, -60).Add(time.Hour)) // 保留期外仍被告警引用的老证据
	client.Alert.Create().SetTs(today).SetRuleID("r").SetSeverity(3).SetAssetID(asset.ID).SetEventID(evidence).SaveX(ctx)
	var ids []uuid.UUID
	for d := -3; d <= 0; d++ {
		for h := 0; h < 24; h += 5 {
			ids = append(ids, mk(today.AddDate(0, 0, d).Add(time.Duration(h)*time.Hour)))
		}
	}
	future := mk(today.AddDate(0, 0, 40)) // 预建范围外，迁移后进默认分区
	if _, err := db.Exec(`INSERT INTO temporal_matches(rule_id, event_id) VALUES ('m', $1)`, ids[0]); err != nil {
		t.Fatal(err)
	}

	if err := m.Run(ctx, "prepare", false, ""); err == nil {
		t.Fatal("未加确认的改库步骤必须拒绝")
	}
	short := *m
	short.Free = func() (uint64, error) { return 1, nil }
	if err := short.Run(ctx, "prepare", true, ""); err == nil || !strings.Contains(err.Error(), "磁盘余量不足") {
		t.Fatalf("磁盘余量不足必须拒绝: %v", err)
	}
	noDisk := *m
	noDisk.Free = nil
	if err := noDisk.Run(ctx, "prepare", true, ""); err == nil {
		t.Fatal("读不到磁盘余量时必须拒绝")
	}
	step(t, m, ctx, "check")
	step(t, m, ctx, "prepare")
	if err := m.Run(ctx, "switch", true, ""); err == nil {
		t.Fatal("没回填核对就切换必须拒绝")
	}

	// 回填中途中断：游标落库，阶段不变
	interrupted, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	paused := *m
	paused.Pause = time.Second
	if err := paused.Run(interrupted, "copy", true, ""); err == nil {
		t.Fatal("超时中断应返回错误")
	}
	cancel()
	var cursor, from time.Time
	var phase string
	if err := db.QueryRow(`SELECT phase, cursor, copy_from FROM event_partition_migration`).Scan(&phase, &cursor, &from); err != nil || phase != "copying" || !cursor.After(from) {
		t.Fatalf("中断后应停在回填阶段且游标前进: %s %v %v %v", phase, from, cursor, err)
	}
	// 迁移期间的写入与删除由镜像触发器同步
	during := mk(today.Add(30 * time.Minute))
	if _, err := db.Exec(`DELETE FROM events WHERE id = $1`, ids[1]); err != nil {
		t.Fatal(err)
	}
	if count(t, db, `SELECT count(*) FROM events_next WHERE id = $1`, during) != 1 {
		t.Fatal("迁移期间的新写入应同步进新表")
	}
	step(t, m, ctx, "copy")
	step(t, m, ctx, "index")

	// 回填与删除竞争留下的残行：verify 必须发现，repair 修掉
	ghostDay := today.AddDate(0, 0, -2)
	if _, err := db.Exec(`INSERT INTO events_next (id, ts, class_uid, source, raw) VALUES ($1, $2, 1007, 'agent', '{}')`, uuid.New(), ghostDay.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := m.Run(ctx, "verify", false, ""); err == nil || !strings.Contains(err.Error(), "不一致") {
		t.Fatalf("残行必须被核对发现: %v", err)
	}
	if err := m.Run(ctx, "repair", true, ghostDay.Format("2006-01-02")); err != nil {
		t.Fatal(err)
	}
	step(t, m, ctx, "verify")

	total := count(t, db, `SELECT count(*) FROM events`)
	if got := assetmapTrigger(t, db); got != "events" {
		t.Fatalf("老表应挂着资产图谱队列触发器，实际 %q", got)
	}
	step(t, m, ctx, "switch")
	if ok, _ := eventpart.Partitioned(ctx, db); !ok {
		t.Fatal("切换后 events 应为分区表")
	}
	if got := assetmapTrigger(t, db); got != "events_old" {
		t.Fatalf("资产图谱队列触发器应随老表改名，实际 %q", got)
	}
	if got := count(t, db, `SELECT count(*) FROM events`); got != total {
		t.Fatalf("切换前后行数不一致: %d → %d", total, got)
	}
	if count(t, db, `SELECT count(*) FROM pg_constraint WHERE confrelid = 'events'::regclass`) != 0 {
		t.Fatal("切换后不应有外键指向分区表")
	}
	if got := viewTarget(t, db); got != "events" {
		t.Fatalf("视图应重绑到新表，实际依赖 %s", got)
	}
	var where string
	db.QueryRow(`SELECT tableoid::regclass::text FROM events WHERE id = $1`, evidence).Scan(&where)
	if where != eventpart.ArchiveName(today.AddDate(0, 0, -60)) {
		t.Fatalf("保留期外的证据应在月归档分区，实际 %s", where)
	}
	db.QueryRow(`SELECT tableoid::regclass::text FROM events WHERE id = $1`, future).Scan(&where)
	if where != eventpart.DefaultName {
		t.Fatalf("预建范围外的事件应在默认分区，实际 %s", where)
	}
	if count(t, db, `SELECT count(*) FROM pg_indexes WHERE tablename = 'events' AND indexname IN ('events_pkey','event_ts','event_asset_id_ts','event_process_guid','event_parent_process_guid','events_raw_trgm')`) != 6 {
		t.Fatal("切换后父表索引应恢复标准名字")
	}
	// 切换后的写入同步回老表，供回滚
	after := mk(today.Add(40 * time.Minute))
	if count(t, db, `SELECT count(*) FROM events_old WHERE id = $1`, after) != 1 {
		t.Fatal("切换后的写入应同步回 events_old")
	}
	step(t, m, ctx, "verify")

	step(t, m, ctx, "rollback")
	if ok, _ := eventpart.Partitioned(ctx, db); ok {
		t.Fatal("回滚后 events 应是老表")
	}
	if got := assetmapTrigger(t, db); got != "events" {
		t.Fatalf("回滚后资产图谱队列触发器应回到老表，实际 %q", got)
	}
	if got := count(t, db, `SELECT count(*) FROM pg_constraint WHERE confrelid = 'events'::regclass AND convalidated`); got != 8 {
		t.Fatalf("回滚应加回并校验 8 个外键，实际 %d", got)
	}
	if got := viewTarget(t, db); got != "events" || count(t, db, `SELECT count(*) FROM migration_view_test.events WHERE id = $1`, after) != 1 {
		t.Fatalf("回滚后视图应指回老表且能看到切换期间的写入: %s", got)
	}
	step(t, m, ctx, "verify")
	step(t, m, ctx, "switch")
	step(t, m, ctx, "finish")
	if count(t, db, `SELECT count(*) FROM pg_class WHERE relname IN ('events_old', 'events_next')`) != 0 ||
		count(t, db, `SELECT count(*) FROM pg_proc WHERE proname = 'openxdr_events_mirror'`) != 0 {
		t.Fatal("finish 应删掉老表与镜像函数")
	}
	if got := assetmapTrigger(t, db); got != "" {
		t.Fatalf("finish 后分区表不应再有资产图谱队列触发器（由 openxdr_events_release 接手），实际 %q", got)
	}
	if got := count(t, db, `SELECT count(*) FROM events`); got != total+1 {
		t.Fatalf("最终行数应为切换前加切换后写入的一条: %d", got)
	}
	// 迁移后的表交给 server 的退役：保留期外的日分区并入同月归档
	firstDaily := today.AddDate(0, 0, -30)
	if n, _, err := eventpart.Retire(ctx, db, firstDaily.AddDate(0, 0, 1)); err != nil || n != 1 {
		t.Fatalf("迁移后的表应能退役最老的日分区: %d %v", n, err)
	}
	if count(t, db, `SELECT count(*) FROM temporal_matches WHERE event_id = $1`, ids[0]) != 1 {
		t.Fatal("未删除事件的派生状态不能丢")
	}
	var raw json.RawMessage
	if err := db.QueryRow(`SELECT raw FROM events WHERE id = $1`, evidence).Scan(&raw); err != nil || string(raw) != `{"k": "v"}` {
		t.Fatalf("证据内容应原样保留: %s %v", raw, err)
	}
}
