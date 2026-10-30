// Package eventpart 维护按 ts 日分区的 events 表：建表、ent 自动迁移共存、
// 分区预建、保留期退役（删分区）与替代外键的删除级联。设计见 docs/event-partitioning.md。
package eventpart

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"slices"

	atlas "ariga.io/atlas/sql/schema"
	entschema "entgo.io/ent/dialect/sql/schema"

	"openxdr/server/ent"
)

// Parent 是分区父表名，分区与默认分区都挂在它下面。
const Parent = "events"

// Columns 与 ent 生成的 events 列一致（schema_test 守着），复制与搬运一律写明列名，不依赖列序。
const Columns = "id, ts, class_uid, source, process_guid, parent_process_guid, username, conn_tuple, raw, asset_id"

const columnDDL = `id uuid NOT NULL, ts timestamptz NOT NULL, class_uid bigint NOT NULL, source varchar NOT NULL,
 process_guid uuid, parent_process_guid uuid, username varchar, conn_tuple varchar, raw jsonb NOT NULL, asset_id uuid`

// indexes 与 ent schema 的事件索引同名同列；全文检索的 trgm 索引由 server 启动时另建（需要 pg_trgm）。
var indexes = []struct{ name, method string }{
	{"event_ts", "btree (ts)"},
	{"event_asset_id_ts", "btree (asset_id, ts)"},
	{"event_process_creation_guid", "btree (process_guid) WHERE class_uid = 1007 AND process_guid IS NOT NULL"},
	{"event_process_guid_ts", "btree (process_guid, ts) WHERE process_guid IS NOT NULL"},
	{"event_parent_process_guid", "btree (parent_process_guid)"},
	{"event_conn_tuple_ts", "btree (conn_tuple, ts) WHERE conn_tuple IS NOT NULL"},
}

// SchemaOption 让 ent 自动迁移看不到 events 及指向它的外键：分区表的主键必须含 ts，
// 交给 ent 按单列主键 diff 会直接报错（分区键不能删）或去补外键。比对前把它们从两边都拿掉，
// 老库上仍在的 alerts→events 外键也就不会被当成多余删掉。
var SchemaOption = entschema.WithDiffHook(func(next entschema.Differ) entschema.Differ {
	return entschema.DiffFunc(func(current, desired *atlas.Schema) ([]atlas.Change, error) {
		hideEvents(current)
		hideEvents(desired)
		return next.Diff(current, desired)
	})
})

func hideEvents(s *atlas.Schema) {
	s.Tables = slices.DeleteFunc(slices.Clone(s.Tables), func(t *atlas.Table) bool { return t.Name == Parent })
	for _, t := range s.Tables {
		t.ForeignKeys = slices.DeleteFunc(slices.Clone(t.ForeignKeys), func(fk *atlas.ForeignKey) bool {
			return fk.RefTable != nil && fk.RefTable.Name == Parent
		})
	}
}

// Migrate 是 ent 自动迁移加 events 建表：新库直接建成分区表；已有的普通 events
// （迁移前的老库）原样保留，由 cmd/eventpartition 在线迁移。调用方须持有 schema 锁。
func Migrate(ctx context.Context, client *ent.Client, db *sql.DB) error {
	if err := client.Schema.Create(ctx, SchemaOption); err != nil {
		return err
	}
	kind, err := relkind(ctx, db, Parent)
	if err != nil {
		return err
	}
	switch kind {
	case "":
		if err := createParent(ctx, db, Parent, true); err != nil {
			return fmt.Errorf("创建分区事件表: %w", err)
		}
	case "r":
		return nil
	}
	if err := EnsureReleaseTrigger(ctx, db, Parent); err != nil {
		return err
	}
	// 已有的分区表上预建可能一时等不到锁，不值得因此起不来：交给后台维护重试，期间新事件暂落默认分区
	if _, err := EnsureDays(ctx, db, Parent, Today(), PremakeDays); err != nil {
		if kind == "" {
			return err
		}
		slog.Warn("启动时预建事件分区失败，交给后台维护重试", "err", err)
	}
	return nil
}

// Partitioned 报告 events 是否已是分区表。迁移前的老库返回 false，各处按老路径运行。
func Partitioned(ctx context.Context, q querier) (bool, error) {
	kind, err := relkind(ctx, q, Parent)
	return kind == "p", err
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func relkind(ctx context.Context, q querier, table string) (string, error) {
	var kind sql.NullString
	err := q.QueryRowContext(ctx, `SELECT relkind::text FROM pg_class WHERE oid = to_regclass($1)`, table).Scan(&kind)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return kind.String, err
}

func createParent(ctx context.Context, db *sql.DB, name string, withIndexes bool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range parentDDL(name, "", withIndexes) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// parentDDL 是建分区父表与默认分区的语句。在线迁移的新表先不建二级索引：批量复制完再逐分区并发建；
// 主键约束名带上 suffix（events_pkey_next），避免与老表重名，切换时去掉。
func parentDDL(name, suffix string, withIndexes bool) []string {
	stmts := []string{
		fmt.Sprintf(`CREATE TABLE %s (%s,
 CONSTRAINT %s PRIMARY KEY (id, ts),
 CONSTRAINT events_assets_events FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL
) PARTITION BY RANGE (ts)`, name, columnDDL, "events_pkey"+suffix),
		fmt.Sprintf(`CREATE TABLE %s PARTITION OF %s DEFAULT`, DefaultName, name),
	}
	for _, idx := range indexes {
		if !withIndexes {
			break
		}
		stmts = append(stmts, fmt.Sprintf(`CREATE INDEX %s ON %s USING %s`, idx.name+suffix, name, idx.method))
	}
	return stmts
}

// movingRows 在搬运事件行（默认分区 → 新分区）的事务里打开：行只是换了分区，不是被删除，
// 级联、证据保护与迁移镜像触发器都要跳过。只用 SET LOCAL，事务结束即失效。
const movingRows = `SET LOCAL openxdr.moving_rows = 'on'`

const skipWhenMoving = ` IF current_setting('openxdr.moving_rows', true) = 'on' THEN RETURN NULL; END IF;
`

// releaseFunctions 代替原来指向 events(id) 的外键：分区表的唯一约束必须含 ts，单列外键建不起来。
// 逐行删除事件时，派生状态随之清掉（原 ON DELETE CASCADE）；仍是时序证据的事件在提交时拒绝删除
// （原 NO ACTION DEFERRABLE INITIALLY DEFERRED：同一语句先删锚点、级联掉证据的删除照常通过）。
// 删分区不触发它们，退役流程显式做同样的事。表不存在（测试库只建了一部分模块）就跳过。
const releaseFunctions = `CREATE OR REPLACE FUNCTION openxdr_events_release() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
` + skipWhenMoving + ` IF to_regclass('temporal_matches') IS NOT NULL THEN DELETE FROM temporal_matches WHERE event_id = OLD.id; END IF;
 IF to_regclass('temporal_candidates') IS NOT NULL THEN DELETE FROM temporal_candidates WHERE event_id = OLD.id; END IF;
 -- temporal_evaluation_gaps 不在这里删：它是诊断记录，按自身 created_at 的独立保留期
 -- 由 janitor 的 temporal.PruneGaps 清理（TEMPORAL_GAP_RETENTION_DAYS），与事件的生命
 -- 周期脱钩——swap/retire/逐行删除都不再连带删除尚未到期的诊断缺口。
 IF to_regclass('temporal_detections') IS NOT NULL THEN DELETE FROM temporal_detections WHERE anchor_id = OLD.id; END IF;
 IF to_regclass('identity_observations') IS NOT NULL THEN DELETE FROM identity_observations WHERE event_id = OLD.id; END IF;
 IF OLD.class_uid IN (4001,5001,5020) AND to_regclass('assetmap_queue') IS NOT NULL THEN DELETE FROM assetmap_queue WHERE event_id = OLD.id; END IF;
 IF to_regclass('identity_local_snapshots') IS NOT NULL THEN DELETE FROM identity_local_snapshots WHERE event_id = OLD.id; END IF;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION openxdr_events_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
` + skipWhenMoving + ` IF to_regclass('temporal_evidence') IS NOT NULL AND EXISTS (SELECT 1 FROM temporal_evidence WHERE event_id = OLD.id) THEN
  RAISE EXCEPTION USING ERRCODE = 'foreign_key_violation', MESSAGE = format('事件 %s 仍是时序命中证据，不能删除', OLD.id);
 END IF;
 RETURN NULL;
END $$`

// derived 是原先 ON DELETE CASCADE 指向 events 的派生表及其事件列；退役分区时按同一清单清理。
var derived = []struct{ table, column string }{
	{"temporal_matches", "event_id"},
	{"temporal_candidates", "event_id"},
	// temporal_evaluation_gaps 不在派生清理清单里：诊断记录按自身 created_at 的独立保留期
	// 由 temporal.PruneGaps 清理（TEMPORAL_GAP_RETENTION_DAYS），与事件是否仍在分区/热表
	// 脱钩（swap 移走、retire 差集、restore 后再清理都连带不到它）。资产删除的
	// ON DELETE CASCADE 是唯一例外，属资产生命周期。
	{"temporal_detections", "anchor_id"},
	{"identity_observations", "event_id"},
	{"identity_local_snapshots", "event_id"},
	{"assetmap_queue", "event_id"},
}

// PinnedIDs 是不随保留期删除的事件：告警、时序证据与已出告警的时序锚点（与 janitor 逐行清理同一口径）。
// 导出给冷归档（eventarchive）复用同一口径：被钉住的事件不删，也不进冷块。
const PinnedIDs = `SELECT event_id FROM alerts WHERE event_id IS NOT NULL
 UNION ALL SELECT event_id FROM temporal_evidence
 UNION ALL SELECT anchor_id FROM temporal_detections WHERE alert_id IS NOT NULL`

// EnsureReleaseTrigger 给分区事件表挂删除级联与证据保护触发器；行级触发器会自动克隆到现有与以后的分区。
func EnsureReleaseTrigger(ctx context.Context, db execer, table string) error {
	if _, err := db.ExecContext(ctx, releaseFunctions); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, fmt.Sprintf(`DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'openxdr_events_release' AND tgrelid = '%[1]s'::regclass) THEN
  CREATE TRIGGER openxdr_events_release AFTER DELETE ON %[1]s FOR EACH ROW EXECUTE FUNCTION openxdr_events_release();
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'openxdr_events_evidence' AND tgrelid = '%[1]s'::regclass) THEN
  CREATE CONSTRAINT TRIGGER openxdr_events_evidence AFTER DELETE ON %[1]s DEFERRABLE INITIALLY DEFERRED
   FOR EACH ROW EXECUTE FUNCTION openxdr_events_evidence();
 END IF;
END $$`, table))
	return err
}

// DropReleaseTrigger 是 EnsureReleaseTrigger 的反操作，迁移回滚时从分区表上摘掉。
func DropReleaseTrigger(ctx context.Context, db execer, table string) error {
	_, err := db.ExecContext(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS openxdr_events_release ON %[1]s;
DROP TRIGGER IF EXISTS openxdr_events_evidence ON %[1]s`, table))
	return err
}
