package eventpart

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// 在线迁移：老库的普通 events 表 → 分区表。分步执行，每步要么整步生效、要么可原地重跑：
//
//	check   只读：阶段、空间、预计耗时与前置条件
//	prepare 建 events_next（分区表，只带主键）与老表上的镜像触发器，此后老表的增删改同步进新表
//	copy    按时间段分批回填，游标落库，中断后从游标续跑
//	index   逐分区 CREATE INDEX CONCURRENTLY 再挂到父索引上，最后 ANALYZE
//	verify  只读核对：同一快照里逐日比对行数与 id 摘要
//	repair  按日补齐 verify 发现的差异（回填与删除竞争留下的残行）
//	switch  短暂排他锁内改名切换，去掉指向老表的外键、重绑视图、挂上反向镜像
//	rollback 切换后、finish 前可切回老表
//	finish  删掉老表与镜像，迁移结束
//	abort   切换前放弃迁移，删掉 events_next
const (
	NextName      = "events_next"
	OldName       = "events_old"
	stateTable    = "event_partition_migration"
	mirrorTrigger = "openxdr_events_mirror"
	lockKey       = "openxdr:event-partition-migration"
	// SpaceFactor 迁移需要的额外空间 = 老表（含索引与 TOAST）× 1.2：新表一份，再留两成给 WAL 与临时文件
	SpaceFactor = 1.2
)

const (
	phaseCopying  = "copying"
	phaseCopied   = "copied"
	phaseIndexed  = "indexed"
	phaseVerified = "verified"
	phaseSwitched = "switched"
	phaseFinished = "finished"
)

// mirrorFunction 把触发表上的增删改原样同步到 TG_ARGV[0]：切换前老表 → events_next，切换后新表 → events_old。
// 与写入同一事务，任一快照里两边一致。搬分区（movingRows）不是删除，跳过。
const mirrorFunction = `CREATE OR REPLACE FUNCTION openxdr_events_mirror() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
` + skipWhenMoving + ` IF TG_OP <> 'INSERT' THEN
  EXECUTE format('DELETE FROM %I WHERE id = $1 AND ts = $2', TG_ARGV[0]) USING OLD.id, OLD.ts;
 END IF;
 IF TG_OP <> 'DELETE' THEN
  EXECUTE format('INSERT INTO %I (` + Columns + `) SELECT ` + Columns + ` FROM (SELECT ($1).*) r ON CONFLICT DO NOTHING', TG_ARGV[0]) USING NEW;
 END IF;
 RETURN NULL;
END $$`

// Migrator 执行在线迁移的各步。Free 返回数据目录所在文件系统的剩余字节，为 nil 时需要空间的步骤拒绝执行。
type Migrator struct {
	DB            *sql.DB
	Out           io.Writer
	RetentionDays int
	Chunk         time.Duration
	Pause         time.Duration
	LockTimeout   time.Duration
	Free          func() (uint64, error)
}

type migrationState struct {
	Phase           string
	RetentionDays   int
	From, To, Cur   sql.NullTime
	Copied          int64
	VerifiedTrigger sql.NullInt64
	ForeignKeys     []foreignKey
}

type foreignKey struct {
	Table string `json:"table"`
	Name  string `json:"name"`
	Def   string `json:"def"`
}

// Run 执行一步。会改动库的步骤必须 confirm，否则拒绝（不做任何「演练」）。
func (m *Migrator) Run(ctx context.Context, step string, confirm bool, day string) error {
	steps := map[string]func(context.Context, *sql.Conn) error{
		"check": m.check, "verify": m.verify,
		"prepare": m.prepare, "copy": m.copy, "index": m.index, "repair": func(ctx context.Context, c *sql.Conn) error { return m.repair(ctx, c, day) },
		"switch": m.switchOver, "rollback": m.rollback, "finish": m.finish, "abort": m.abort,
	}
	fn, ok := steps[step]
	if !ok {
		return fmt.Errorf("未知步骤 %q", step)
	}
	if step != "check" && step != "verify" && !confirm {
		return fmt.Errorf("%s 会改动数据库，确认后加 -confirm 执行；先用 check 查看当前状态", step)
	}
	conn, err := m.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var locked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtext($1))`, lockKey).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return errors.New("另一个迁移进程正在运行")
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtext($1))`, lockKey)
	return fn(ctx, conn)
}

func (m *Migrator) printf(format string, args ...any) { fmt.Fprintf(m.Out, format+"\n", args...) }

func (m *Migrator) lockTimeout() string {
	if m.LockTimeout <= 0 {
		return "5s"
	}
	return fmt.Sprintf("%dms", m.LockTimeout.Milliseconds())
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func loadState(ctx context.Context, q queryer) (*migrationState, error) {
	if kind, err := relkind(ctx, q, stateTable); err != nil || kind == "" {
		return nil, err
	}
	var s migrationState
	var fks []byte
	err := q.QueryRowContext(ctx, `SELECT phase, retention_days, copy_from, copy_to, cursor, copied, verified_trigger, foreign_keys
 FROM `+stateTable+` WHERE id = 1`).Scan(&s.Phase, &s.RetentionDays, &s.From, &s.To, &s.Cur, &s.Copied, &s.VerifiedTrigger, &fks)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(fks) > 0 {
		if err := json.Unmarshal(fks, &s.ForeignKeys); err != nil {
			return nil, err
		}
	}
	return &s, nil
}

func setPhase(ctx context.Context, q queryer, phase string) error {
	_, err := q.ExecContext(ctx, `UPDATE `+stateTable+` SET phase = $1, updated_at = now() WHERE id = 1`, phase)
	return err
}

func requirePhase(s *migrationState, phases ...string) error {
	if s == nil {
		return fmt.Errorf("还没有 prepare，当前不在迁移中")
	}
	for _, p := range phases {
		if s.Phase == p {
			return nil
		}
	}
	return fmt.Errorf("当前阶段是 %s，这一步需要阶段 %s", s.Phase, strings.Join(phases, " / "))
}

func tableSize(ctx context.Context, q queryer, table string) (int64, error) {
	var size sql.NullInt64
	// 分区表本身不占空间，要把分区加起来
	err := q.QueryRowContext(ctx, `SELECT sum(pg_total_relation_size(c.oid)) FROM pg_class c
 WHERE c.oid = to_regclass($1) OR c.oid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = to_regclass($1))`, table).Scan(&size)
	return size.Int64, err
}

// spaceNeeded 返回迁移还需要的空间与当前剩余空间；剩余不足就拒绝。
func (m *Migrator) ensureSpace(ctx context.Context, q queryer) error {
	if m.Free == nil {
		return errors.New("必须用 -pgdata 指向数据库数据目录（在数据库主机或容器内运行），否则无法确认磁盘余量")
	}
	need, free, err := m.space(ctx, q)
	if err != nil {
		return err
	}
	if free < need {
		return fmt.Errorf("磁盘余量不足：还需要约 %s，剩余 %s。迁移期间新旧两份数据并存，先扩容再继续", human(need), human(free))
	}
	return nil
}

func (m *Migrator) space(ctx context.Context, q queryer) (need, free uint64, err error) {
	oldName := Parent
	if kind, err := relkind(ctx, q, OldName); err != nil {
		return 0, 0, err
	} else if kind != "" {
		oldName = OldName
	}
	old, err := tableSize(ctx, q, oldName)
	if err != nil {
		return 0, 0, err
	}
	next, err := tableSize(ctx, q, NextName)
	if err != nil {
		return 0, 0, err
	}
	want := uint64(float64(old) * SpaceFactor)
	if uint64(next) < want {
		need = want - uint64(next)
	}
	if m.Free != nil {
		if free, err = m.Free(); err != nil {
			return 0, 0, err
		}
	}
	return need, free, nil
}

func human(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// check 只读：当前阶段、空间与预计耗时、前置条件。不满足前置条件时返回错误（退出码非零）。
func (m *Migrator) check(ctx context.Context, c *sql.Conn) error {
	s, err := loadState(ctx, c)
	if err != nil {
		return err
	}
	kind, err := relkind(ctx, c, Parent)
	if err != nil {
		return err
	}
	phase := "未开始"
	if s != nil {
		phase = s.Phase
	}
	m.printf("阶段：%s；events 是%s", phase, map[string]string{"r": "普通表", "p": "分区表", "": "不存在"}[kind])
	if s != nil && s.From.Valid {
		m.printf("回填：%s → %s，游标 %s，已复制 %d 行", s.From.Time.UTC().Format(time.RFC3339), s.To.Time.UTC().Format(time.RFC3339), s.Cur.Time.UTC().Format(time.RFC3339), s.Copied)
	}
	var heap, total, rows int64
	src := Parent
	if kind == "p" {
		src = OldName
	}
	if k, _ := relkind(ctx, c, src); k == "r" {
		if err := c.QueryRowContext(ctx, `SELECT pg_table_size(to_regclass($1)), pg_total_relation_size(to_regclass($1)), GREATEST(reltuples, 0)::bigint
 FROM pg_class WHERE oid = to_regclass($1)`, src).Scan(&heap, &total, &rows); err != nil {
			return err
		}
		m.printf("老表 %s：约 %d 行，数据 %s，含索引 %s", src, rows, human(uint64(heap)), human(uint64(total)))
		// 经验速率（生产虚拟盘 + 同步复制下保守取值），copy 运行时按实测速率给出剩余时间
		m.printf("预计：copy %s–%s（按 30–80 MB/s）；index 每个二级索引各扫一遍新表，btree %s–%s/个，trgm GIN 约为其 3–5 倍；verify 两表各扫一遍 %s–%s",
			dur(heap, 80), dur(heap, 30), dur(heap, 150), dur(heap, 50), dur(2*heap, 200), dur(2*heap, 60))
	}
	need, free, err := m.space(ctx, c)
	if err != nil {
		return err
	}
	if m.Free == nil {
		m.printf("空间：迁移还需约 %s；未给 -pgdata，无法读取剩余空间（主备两台都要有这么多余量）", human(need))
	} else {
		m.printf("空间：迁移还需约 %s，本机剩余 %s（主备两台都要有这么多余量）", human(need), human(free))
	}
	if s == nil {
		if err := preflight(ctx, c); err != nil {
			return err
		}
		if m.Free != nil && free < need {
			return fmt.Errorf("磁盘余量不足：还需要约 %s，剩余 %s", human(need), human(free))
		}
		m.printf("前置条件满足，可以 prepare")
	}
	return nil
}

func dur(bytes int64, mbps float64) string {
	d := time.Duration(float64(bytes) / (mbps * 1024 * 1024) * float64(time.Second))
	return d.Round(time.Minute).String()
}

// preflight 核对老表能原样迁移：普通表、列与 ent 一致、没有不含 ts 的唯一索引、没有物化视图或发布依赖它。
func preflight(ctx context.Context, q queryer) error {
	var version int
	if err := q.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&version); err != nil {
		return err
	}
	if version < 130000 {
		return fmt.Errorf("需要 PostgreSQL 13 及以上（分区表上的行级与约束触发器），当前 %d", version)
	}
	if kind, err := relkind(ctx, q, Parent); err != nil || kind != "r" {
		return fmt.Errorf("events 不是普通表（relkind=%q），不需要或不能迁移: %v", kind, err)
	}
	for _, name := range []string{NextName, OldName} {
		if kind, err := relkind(ctx, q, name); err != nil || kind != "" {
			return fmt.Errorf("%s 已存在，先查明来历再继续: %v", name, err)
		}
	}
	var cols string
	if err := q.QueryRowContext(ctx, `SELECT string_agg(attname || ' ' || format_type(atttypid, atttypmod) || CASE WHEN attnotnull THEN ' not null' ELSE '' END, ', ' ORDER BY attname)
 FROM pg_attribute WHERE attrelid = 'events'::regclass AND attnum > 0 AND NOT attisdropped`).Scan(&cols); err != nil {
		return err
	}
	const want = "asset_id uuid, class_uid bigint not null, conn_tuple character varying, id uuid not null, parent_process_guid uuid, process_guid uuid, raw jsonb not null, source character varying not null, ts timestamp with time zone not null, username character varying"
	if cols != want {
		return fmt.Errorf("events 列与预期不一致，拒绝迁移：%s", cols)
	}
	defs, err := oldIndexes(ctx, q, Parent)
	if err != nil {
		return err
	}
	for _, d := range defs {
		if _, err := indexMethod(d.def); err != nil {
			return err
		}
		if len(d.name)+len("_next") > 63 || len(d.name)+len("_old") > 63 {
			return fmt.Errorf("索引名 %s 太长，加后缀会被截断", d.name)
		}
	}
	// openxdr_assetmap_release 是资产图谱队列只给普通表挂的删除触发器（graphqueue.EnsureSchema）：
	// 切换时随老表改名成 events_old、回滚时随它回来；分区表上同样的清理由 openxdr_events_release
	// 与分区退役接手（见 schema.go 的 assetmap_queue），不需要迁移搬它。
	var blockers string
	if err := q.QueryRowContext(ctx, `SELECT coalesce(string_agg(x, ', '), '') FROM (
 SELECT 'materialized view ' || v.oid::regclass AS x FROM pg_depend d JOIN pg_rewrite r ON r.oid = d.objid JOIN pg_class v ON v.oid = r.ev_class
  WHERE d.classid = 'pg_rewrite'::regclass AND d.refobjid = 'events'::regclass AND v.relkind = 'm'
 UNION ALL SELECT 'publication ' || p.pubname FROM pg_publication_rel pr JOIN pg_publication p ON p.oid = pr.prpubid WHERE pr.prrelid = 'events'::regclass
 UNION ALL SELECT 'policy ' || polname FROM pg_policy WHERE polrelid = 'events'::regclass
 UNION ALL SELECT 'trigger ' || tgname FROM pg_trigger WHERE tgrelid = 'events'::regclass AND NOT tgisinternal
  AND tgname <> 'openxdr_assetmap_release') t`).Scan(&blockers); err != nil {
		return err
	}
	if blockers != "" {
		return fmt.Errorf("events 上有迁移不会处理的依赖，拒绝迁移：%s", blockers)
	}
	return nil
}

type indexDef struct{ name, def string }

// oldIndexes 是普通 events 表上主键以外的索引；新表照这些建，名字加 _next 后缀，切换时去掉。
func oldIndexes(ctx context.Context, q queryer, table string) ([]indexDef, error) {
	rows, err := q.QueryContext(ctx, `SELECT c.relname, pg_get_indexdef(i.indexrelid) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
 WHERE i.indrelid = to_regclass($1) AND NOT i.indisprimary ORDER BY c.relname`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []indexDef
	for rows.Next() {
		var d indexDef
		if err := rows.Scan(&d.name, &d.def); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// prepare 一个事务内建好状态表、events_next（主键、外键、默认分区、归档与日分区）和老表上的镜像触发器。
func (m *Migrator) prepare(ctx context.Context, c *sql.Conn) error {
	if s, err := loadState(ctx, c); err != nil {
		return err
	} else if s != nil {
		return fmt.Errorf("迁移已在进行（阶段 %s）", s.Phase)
	}
	if err := preflight(ctx, c); err != nil {
		return err
	}
	if err := m.ensureSpace(ctx, c); err != nil {
		return err
	}
	if m.RetentionDays < 0 {
		return errors.New("保留天数不能为负")
	}
	tx, err := c.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var minTs sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT min(ts) FROM events`).Scan(&minTs); err != nil {
		return err
	}
	stmts := []string{
		`SET LOCAL lock_timeout = '` + m.lockTimeout() + `'`,
		`CREATE TABLE IF NOT EXISTS ` + stateTable + ` (id int PRIMARY KEY CHECK (id = 1), phase text NOT NULL,
 retention_days int NOT NULL, copy_from timestamptz, copy_to timestamptz, cursor timestamptz, copied bigint NOT NULL DEFAULT 0,
 verified_trigger oid, foreign_keys jsonb, updated_at timestamptz NOT NULL DEFAULT now())`,
		fmt.Sprintf(`INSERT INTO %s (id, phase, retention_days) VALUES (1, '%s', %d)`, stateTable, phaseCopying, m.RetentionDays),
	}
	stmts = append(stmts, parentDDL(NextName, "_next", false)...)
	stmts = append(stmts, nextPartitions(minTs, m.RetentionDays, time.Now())...)
	stmts = append(stmts, mirrorFunction,
		fmt.Sprintf(`CREATE TRIGGER %s AFTER INSERT OR UPDATE OR DELETE ON events FOR EACH ROW EXECUTE FUNCTION openxdr_events_mirror('%s')`, mirrorTrigger, NextName))
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%w\n%s", err, stmt)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.printf("已建 events_next 与镜像触发器：此后 events 的写入同步进新表。下一步 copy")
	return nil
}

// nextPartitions 是新表的初始分区：保留期以外的老证据按月进归档分区，保留期内到今天之后 PremakeDays 天按日。
func nextPartitions(minTs sql.NullTime, retentionDays int, now time.Time) []string {
	firstDaily := dayStart(now).AddDate(0, 0, -retentionDays)
	var stmts []string
	if minTs.Valid && minTs.Time.Before(firstDaily) {
		for month := monthStart(minTs.Time); month.Before(firstDaily); month = month.AddDate(0, 1, 0) {
			hi := month.AddDate(0, 1, 0)
			if hi.After(firstDaily) {
				hi = firstDaily
			}
			stmts = append(stmts, fmt.Sprintf(`CREATE TABLE %s PARTITION OF %s FOR VALUES FROM (%s) TO (%s)`, ArchiveName(month), NextName, literal(month), literal(hi)))
		}
	}
	for day := firstDaily; !day.After(dayStart(now).AddDate(0, 0, PremakeDays)); day = day.AddDate(0, 0, 1) {
		stmts = append(stmts, fmt.Sprintf(`CREATE TABLE %s PARTITION OF %s FOR VALUES FROM (%s) TO (%s)`, DailyName(day), NextName, literal(day), literal(day.AddDate(0, 0, 1))))
	}
	return stmts
}

// copy 按 Chunk 时间段回填，每段一个事务并推进游标；中断后从游标续跑，重复复制由主键去重。
func (m *Migrator) copy(ctx context.Context, c *sql.Conn) error {
	s, err := loadState(ctx, c)
	if err != nil {
		return err
	}
	if err := requirePhase(s, phaseCopying); err != nil {
		return err
	}
	if err := m.ensureSpace(ctx, c); err != nil {
		return err
	}
	if _, err := EnsureDays(ctx, m.DB, NextName, Today(), PremakeDays); err != nil {
		return err
	}
	if !s.From.Valid {
		// 镜像触发器已生效，此刻的 min/max 覆盖了所有需要回填的行；之后写入的由触发器同步
		var lo, hi sql.NullTime
		if err := c.QueryRowContext(ctx, `SELECT min(ts), max(ts) FROM events`).Scan(&lo, &hi); err != nil {
			return err
		}
		if !lo.Valid {
			m.printf("events 为空，无需回填")
			return setPhase(ctx, c, phaseCopied)
		}
		s.From = sql.NullTime{Time: lo.Time.Truncate(time.Hour), Valid: true}
		s.To = sql.NullTime{Time: hi.Time.Add(time.Microsecond), Valid: true}
		s.Cur = s.From
		if _, err := c.ExecContext(ctx, `UPDATE `+stateTable+` SET copy_from = $1, copy_to = $2, cursor = $1 WHERE id = 1`, s.From.Time, s.To.Time); err != nil {
			return err
		}
	}
	chunk := m.Chunk
	if chunk <= 0 {
		chunk = time.Hour
	}
	var estimate int64
	c.QueryRowContext(ctx, `SELECT GREATEST(reltuples, 0)::bigint FROM pg_class WHERE oid = 'events'::regclass`).Scan(&estimate)
	started, copiedNow, lastReport := time.Now(), int64(0), time.Now()
	cur := s.Cur.Time
	for cur.Before(s.To.Time) {
		if err := ctx.Err(); err != nil {
			m.printf("已中断，游标停在 %s，重跑 copy 续传", cur.UTC().Format(time.RFC3339))
			return err
		}
		next := cur.Add(chunk)
		if next.After(s.To.Time) {
			next = s.To.Time
		}
		n, err := m.copyChunk(ctx, c, cur, next)
		if err != nil {
			return err
		}
		copiedNow += n
		cur = next
		if n == 0 {
			// 老证据稀疏，空段直接跳到下一条记录所在的小时
			var gap sql.NullTime
			if err := c.QueryRowContext(ctx, `SELECT min(ts) FROM events WHERE ts >= $1`, cur).Scan(&gap); err != nil {
				return err
			}
			jump := s.To.Time
			if gap.Valid && gap.Time.Before(jump) {
				jump = gap.Time.Truncate(time.Hour)
			}
			if jump.After(cur) {
				if _, err := c.ExecContext(ctx, `UPDATE `+stateTable+` SET cursor = $1 WHERE id = 1`, jump); err != nil {
					return err
				}
				cur = jump
			}
		}
		if time.Since(lastReport) > 10*time.Second || !cur.Before(s.To.Time) {
			lastReport = time.Now()
			rate := float64(copiedNow) / time.Since(started).Seconds()
			eta := "未知"
			if left := estimate - s.Copied - copiedNow; rate > 0 && left > 0 {
				eta = (time.Duration(float64(left)/rate) * time.Second).Round(time.Second).String()
			}
			m.printf("游标 %s，本次已复制 %d 行，%.0f 行/秒，预计剩余 %s", cur.UTC().Format(time.RFC3339), copiedNow, rate, eta)
		}
		if m.Pause > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(m.Pause):
			}
		}
	}
	if err := setPhase(ctx, c, phaseCopied); err != nil {
		return err
	}
	m.printf("回填完成。下一步 index")
	return nil
}

func (m *Migrator) copyChunk(ctx context.Context, c *sql.Conn, from, to time.Time) (int64, error) {
	tx, err := c.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM events WHERE ts >= $1 AND ts < $2 ON CONFLICT DO NOTHING`, NextName, Columns, Columns), from, to)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `UPDATE `+stateTable+` SET cursor = $1, copied = copied + $2, updated_at = now() WHERE id = 1`, to, n); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// index 照老表的二级索引在新表上逐分区并发建索引并挂到父索引；中途失败留下的无效索引重跑时删掉重建。
func (m *Migrator) index(ctx context.Context, c *sql.Conn) error {
	s, err := loadState(ctx, c)
	if err != nil {
		return err
	}
	if err := requirePhase(s, phaseCopied); err != nil {
		return err
	}
	if err := m.ensureSpace(ctx, c); err != nil {
		return err
	}
	defs, err := oldIndexes(ctx, c, Parent)
	if err != nil {
		return err
	}
	parts, err := partitionNames(ctx, c, NextName)
	if err != nil {
		return err
	}
	for _, d := range defs {
		method, err := indexMethod(d.def)
		if err != nil {
			return err
		}
		parent := d.name + "_next"
		if _, err := c.ExecContext(ctx, fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON ONLY %s USING %s`, parent, NextName, method)); err != nil {
			return err
		}
		for _, part := range parts {
			child := truncateName(part + "_" + strings.TrimPrefix(d.name, "event_"))
			if err := m.buildChild(ctx, c, parent, child, part, method); err != nil {
				return fmt.Errorf("%s 上建 %s: %w", part, d.name, err)
			}
		}
		var valid bool
		if err := c.QueryRowContext(ctx, `SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)`, parent).Scan(&valid); err != nil || !valid {
			return fmt.Errorf("父索引 %s 仍无效（有分区没挂上）: %v", parent, err)
		}
		m.printf("索引 %s 完成", d.name)
	}
	if _, err := c.ExecContext(ctx, `ANALYZE `+NextName); err != nil {
		return err
	}
	if err := setPhase(ctx, c, phaseIndexed); err != nil {
		return err
	}
	m.printf("索引与统计信息就绪。下一步 verify")
	return nil
}

func (m *Migrator) buildChild(ctx context.Context, c *sql.Conn, parent, child, part, method string) error {
	var valid, attached sql.NullBool
	err := c.QueryRowContext(ctx, `SELECT i.indisvalid, EXISTS(SELECT 1 FROM pg_inherits h WHERE h.inhrelid = i.indexrelid AND h.inhparent = to_regclass($2))
 FROM pg_index i WHERE i.indexrelid = to_regclass($1)`, child, parent).Scan(&valid, &attached)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if attached.Bool {
		return nil
	}
	if valid.Valid && !valid.Bool {
		if _, err := c.ExecContext(ctx, `DROP INDEX CONCURRENTLY `+child); err != nil {
			return err
		}
		valid.Valid = false
	}
	if !valid.Valid {
		m.printf("  %s ...", child)
		if _, err := c.ExecContext(ctx, fmt.Sprintf(`CREATE INDEX CONCURRENTLY %s ON %s USING %s`, child, part, method)); err != nil {
			return err
		}
	}
	_, err = c.ExecContext(ctx, fmt.Sprintf(`ALTER INDEX %s ATTACH PARTITION %s`, parent, child))
	return err
}

func truncateName(name string) string {
	if len(name) > 63 {
		return name[:63]
	}
	return name
}

func partitionNames(ctx context.Context, q queryer, parent string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = to_regclass($1) ORDER BY 1`, parent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

type daySum struct {
	Count int64
	Hash  string
}

// dailySums 逐日（UTC）统计行数与 id 摘要；since 非零时只统计该时间之后。
func dailySums(ctx context.Context, tx *sql.Tx, table string, since time.Time) (map[string]daySum, error) {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD'), count(*), sum(hashtextextended(id::text, 0))::text
 FROM %s WHERE ts >= $1 GROUP BY 1`, table), since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]daySum{}
	for rows.Next() {
		var day string
		var s daySum
		if err := rows.Scan(&day, &s.Count, &s.Hash); err != nil {
			return nil, err
		}
		out[day] = s
	}
	return out, rows.Err()
}

// compare 在同一个只读快照里逐日比对两表，返回不一致的日子。
func compare(ctx context.Context, c *sql.Conn, a, b string, since time.Time) (mismatch []string, days int, rows int64, err error) {
	tx, err := c.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	left, err := dailySums(ctx, tx, a, since)
	if err != nil {
		return nil, 0, 0, err
	}
	right, err := dailySums(ctx, tx, b, since)
	if err != nil {
		return nil, 0, 0, err
	}
	for day, l := range left {
		rows += l.Count
		if right[day] != l {
			mismatch = append(mismatch, day)
		}
	}
	for day := range right {
		if _, ok := left[day]; !ok {
			mismatch = append(mismatch, day)
		}
	}
	sort.Strings(mismatch)
	return mismatch, len(left), rows, nil
}

// verify 只读核对新旧两表。切换前全量比对，通过后才允许 switch；切换后只比对仍在日分区里的日子
// （过期日分区退役时整体删除，不经镜像同步，老表在那些日子多出数据是预期的）。
func (m *Migrator) verify(ctx context.Context, c *sql.Conn) error {
	s, err := loadState(ctx, c)
	if err != nil {
		return err
	}
	if err := requirePhase(s, phaseCopied, phaseIndexed, phaseVerified, phaseSwitched); err != nil {
		return err
	}
	a, b, since := Parent, NextName, time.Time{}
	if s.Phase == phaseSwitched {
		a, b = OldName, Parent
		set, err := listPartitions(ctx, c, Parent)
		if err != nil {
			return err
		}
		if len(set.daily) > 0 {
			since = set.daily[0]
		}
	}
	// 镜像触发器始终挂在当前叫 events 的表上：切换前是老表，切换后是新表
	trigger, err := mirrorOID(ctx, c, Parent)
	if err != nil {
		return err
	}
	if trigger == 0 {
		return errors.New("events 上没有启用的镜像触发器，两表不再同步，不能据此核对")
	}
	started := time.Now()
	mismatch, days, rows, err := compare(ctx, c, a, b, since)
	if err != nil {
		return err
	}
	m.printf("核对 %s 与 %s：%d 天、%d 行，耗时 %s", a, b, days, rows, time.Since(started).Round(time.Second))
	if len(mismatch) > 0 {
		m.printf("不一致的日子：%s", strings.Join(mismatch, " "))
		if s.Phase != phaseSwitched {
			m.printf("用 repair -confirm 补齐（可加 -day 只修一天），再重新 verify")
		}
		return fmt.Errorf("%d 天不一致", len(mismatch))
	}
	if s.Phase == phaseIndexed || s.Phase == phaseVerified {
		if _, err := c.ExecContext(ctx, `UPDATE `+stateTable+` SET phase = $1, verified_trigger = $2, updated_at = now() WHERE id = 1`, phaseVerified, trigger); err != nil {
			return err
		}
		m.printf("一致。下一步 switch")
		return nil
	}
	m.printf("一致")
	return nil
}

// mirrorOID 返回表上启用中的镜像触发器 OID，没有则为 0。switch 用它确认核对之后镜像一直在。
func mirrorOID(ctx context.Context, q queryer, table string) (int64, error) {
	var oid sql.NullInt64
	err := q.QueryRowContext(ctx, `SELECT oid::bigint FROM pg_trigger WHERE tgrelid = to_regclass($1) AND tgname = $2 AND tgenabled <> 'D'`, table, mirrorTrigger).Scan(&oid)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return oid.Int64, err
}

// repair 按日补齐：删掉新表里老表没有的行，补上老表有而新表缺的行。之后必须重新 verify。
func (m *Migrator) repair(ctx context.Context, c *sql.Conn, only string) error {
	s, err := loadState(ctx, c)
	if err != nil {
		return err
	}
	if err := requirePhase(s, phaseCopied, phaseIndexed, phaseVerified); err != nil {
		return err
	}
	days := []string{only}
	if only == "" {
		if days, _, _, err = compare(ctx, c, Parent, NextName, time.Time{}); err != nil {
			return err
		}
	}
	for _, day := range days {
		lo, err := time.Parse("2006-01-02", day)
		if err != nil {
			return fmt.Errorf("日期 %q 格式应为 YYYY-MM-DD", day)
		}
		hi := lo.AddDate(0, 0, 1)
		tx, err := c.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		del, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s n WHERE n.ts >= $1 AND n.ts < $2
 AND NOT EXISTS (SELECT 1 FROM events o WHERE o.id = n.id AND o.ts = n.ts)`, NextName), lo, hi)
		if err != nil {
			tx.Rollback()
			return err
		}
		ins, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM events WHERE ts >= $1 AND ts < $2 ON CONFLICT DO NOTHING`, NextName, Columns, Columns), lo, hi)
		if err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		d, _ := del.RowsAffected()
		i, _ := ins.RowsAffected()
		m.printf("%s：删除新表多出的 %d 行，补上缺的 %d 行", day, d, i)
	}
	if s.Phase == phaseVerified {
		if err := setPhase(ctx, c, phaseIndexed); err != nil {
			return err
		}
	}
	m.printf("修完后重新 verify")
	return nil
}

type viewDef struct{ name, def, options string }

// dependentViews 取依赖该表的视图定义。视图按 OID 绑定表，改名后仍指向老表，切换时要按原定义重建一遍。
func dependentViews(ctx context.Context, tx *sql.Tx, table string) ([]viewDef, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT v.oid::regclass::text, pg_get_viewdef(v.oid), coalesce(array_to_string(v.reloptions, ', '), ''), v.relkind::text
 FROM pg_depend d JOIN pg_rewrite r ON r.oid = d.objid JOIN pg_class v ON v.oid = r.ev_class
 WHERE d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_class'::regclass AND d.refobjid = to_regclass($1) AND v.oid <> d.refobjid`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []viewDef
	for rows.Next() {
		var v viewDef
		var kind string
		if err := rows.Scan(&v.name, &v.def, &v.options, &kind); err != nil {
			return nil, err
		}
		if kind != "v" {
			return nil, fmt.Errorf("%s 不是普通视图，迁移不会处理", v.name)
		}
		v.def = strings.TrimSuffix(strings.TrimSpace(v.def), ";")
		out = append(out, v)
	}
	return out, rows.Err()
}

func rebindViews(ctx context.Context, tx *sql.Tx, views []viewDef) error {
	for _, v := range views {
		with := ""
		if v.options != "" {
			with = " WITH (" + v.options + ")"
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE OR REPLACE VIEW %s%s AS %s`, v.name, with, v.def)); err != nil {
			return fmt.Errorf("重建视图 %s: %w", v.name, err)
		}
	}
	return nil
}

// renameIndexes 给表的全部索引改名；主键走 RENAME CONSTRAINT 让约束与索引同名。
func renameIndexes(ctx context.Context, tx *sql.Tx, table string, rename func(string) string) error {
	rows, err := tx.QueryContext(ctx, `SELECT c.relname, i.indisprimary FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE i.indrelid = to_regclass($1)`, table)
	if err != nil {
		return err
	}
	type idx struct {
		name    string
		primary bool
	}
	var all []idx
	for rows.Next() {
		var x idx
		if err := rows.Scan(&x.name, &x.primary); err != nil {
			rows.Close()
			return err
		}
		all = append(all, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, x := range all {
		to := rename(x.name)
		if to == x.name {
			continue
		}
		stmt := fmt.Sprintf(`ALTER INDEX %s RENAME TO %s`, x.name, to)
		if x.primary {
			stmt = fmt.Sprintf(`ALTER TABLE %s RENAME CONSTRAINT %s TO %s`, table, x.name, to)
		}
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func addSuffix(suffix string) func(string) string {
	return func(name string) string { return name + suffix }
}

func trimSuffix(suffix string) func(string) string {
	return func(name string) string { return strings.TrimSuffix(name, suffix) }
}

// switchOver 在一个事务里完成切换：拿到两表排他锁后核对最近一小时行数，去掉指向老表的外键，
// 两表改名、索引改名，重建依赖视图，挂上删除级联触发器与反向镜像（新表 → events_old，供回滚）。
// 停写窗口就是这个事务：只有目录操作与一小时数据的计数，锁等不到 LockTimeout 就整体放弃，可直接重跑。
func (m *Migrator) switchOver(ctx context.Context, c *sql.Conn) error {
	s, err := loadState(ctx, c)
	if err != nil {
		return err
	}
	if err := requirePhase(s, phaseVerified); err != nil {
		return err
	}
	oid, err := mirrorOID(ctx, c, Parent)
	if err != nil {
		return err
	}
	if oid == 0 || !s.VerifiedTrigger.Valid || oid != s.VerifiedTrigger.Int64 {
		return errors.New("镜像触发器在 verify 之后被改动或停用，两表可能已不同步：重新 repair / verify")
	}
	if _, err := EnsureDays(ctx, m.DB, NextName, Today(), PremakeDays); err != nil {
		return err
	}
	started := time.Now()
	tx, err := c.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range []string{
		`SET LOCAL lock_timeout = '` + m.lockTimeout() + `'`,
		`LOCK TABLE events IN ACCESS EXCLUSIVE MODE`,
		`LOCK TABLE ` + NextName + ` IN ACCESS EXCLUSIVE MODE`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("拿锁失败（有长查询或长事务占着 events），稍后重跑 switch: %w", err)
		}
	}
	var oldCount, newCount int64
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM events WHERE ts >= now() - interval '1 hour'),
 (SELECT count(*) FROM `+NextName+` WHERE ts >= now() - interval '1 hour')`).Scan(&oldCount, &newCount); err != nil {
		return err
	}
	if oldCount != newCount {
		return fmt.Errorf("最近一小时行数不一致（老表 %d，新表 %d），放弃切换", oldCount, newCount)
	}
	views, err := dependentViews(ctx, tx, Parent)
	if err != nil {
		return err
	}
	fks, err := referencingKeys(ctx, tx, Parent)
	if err != nil {
		return err
	}
	for _, fk := range fks {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s DROP CONSTRAINT %s`, fk.Table, fk.Name)); err != nil {
			return err
		}
	}
	saved, _ := json.Marshal(fks)
	for _, stmt := range []string{
		`DROP TRIGGER ` + mirrorTrigger + ` ON events`,
		`ALTER TABLE events RENAME TO ` + OldName,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if err := renameIndexes(ctx, tx, OldName, addSuffix("_old")); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE `+NextName+` RENAME TO events`); err != nil {
		return err
	}
	if err := renameIndexes(ctx, tx, Parent, trimSuffix("_next")); err != nil {
		return err
	}
	if err := rebindViews(ctx, tx, views); err != nil {
		return err
	}
	if err := EnsureReleaseTrigger(ctx, tx, Parent); err != nil {
		return err
	}
	for _, stmt := range []string{
		fmt.Sprintf(`CREATE TRIGGER %s AFTER INSERT OR UPDATE OR DELETE ON events FOR EACH ROW EXECUTE FUNCTION openxdr_events_mirror('%s')`, mirrorTrigger, OldName),
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE `+stateTable+` SET phase = $1, foreign_keys = $2, updated_at = now() WHERE id = 1`, phaseSwitched, saved); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.printf("已切换，排他锁持有 %s。去掉外键 %d 个，重绑视图 %d 个；新表写入同步回 events_old 以备回滚。", time.Since(started).Round(time.Millisecond), len(fks), len(views))
	m.printf("server 下一轮维护自动接手分区预建与退役；观察无误后 finish，有问题 rollback")
	return nil
}

func referencingKeys(ctx context.Context, tx *sql.Tx, table string) ([]foreignKey, error) {
	rows, err := tx.QueryContext(ctx, `SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid) FROM pg_constraint
 WHERE confrelid = to_regclass($1) AND contype = 'f' ORDER BY 1, 2`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []foreignKey
	for rows.Next() {
		var fk foreignKey
		if err := rows.Scan(&fk.Table, &fk.Name, &fk.Def); err != nil {
			return nil, err
		}
		out = append(out, fk)
	}
	return out, rows.Err()
}

// rollback 切回老表：改名还原、外键以 NOT VALID 加回（事务外再逐个 VALIDATE，不长时间锁表）、视图重绑、
// 镜像改回老表 → events_next。阶段回到 indexed：再次 switch 前要重新 verify（退役删掉的日子会显示差异，repair 补回）。
func (m *Migrator) rollback(ctx context.Context, c *sql.Conn) error {
	s, err := loadState(ctx, c)
	if err != nil {
		return err
	}
	if err := requirePhase(s, phaseSwitched); err != nil {
		return err
	}
	tx, err := c.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range []string{
		`SET LOCAL lock_timeout = '` + m.lockTimeout() + `'`,
		`LOCK TABLE events IN ACCESS EXCLUSIVE MODE`,
		`LOCK TABLE ` + OldName + ` IN ACCESS EXCLUSIVE MODE`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("拿锁失败，稍后重跑 rollback: %w", err)
		}
	}
	views, err := dependentViews(ctx, tx, Parent)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DROP TRIGGER `+mirrorTrigger+` ON events`); err != nil {
		return err
	}
	if err := DropReleaseTrigger(ctx, tx, Parent); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE events RENAME TO `+NextName); err != nil {
		return err
	}
	if err := renameIndexes(ctx, tx, NextName, addSuffix("_next")); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE `+OldName+` RENAME TO events`); err != nil {
		return err
	}
	if err := renameIndexes(ctx, tx, Parent, trimSuffix("_old")); err != nil {
		return err
	}
	for _, fk := range s.ForeignKeys {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD CONSTRAINT %s %s NOT VALID`, fk.Table, fk.Name, fk.Def)); err != nil {
			return err
		}
	}
	if err := rebindViews(ctx, tx, views); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE TRIGGER %s AFTER INSERT OR UPDATE OR DELETE ON events FOR EACH ROW EXECUTE FUNCTION openxdr_events_mirror('%s')`, mirrorTrigger, NextName)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE `+stateTable+` SET phase = $1, verified_trigger = NULL, updated_at = now() WHERE id = 1`, phaseIndexed); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, fk := range s.ForeignKeys {
		if _, err := c.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s VALIDATE CONSTRAINT %s`, fk.Table, fk.Name)); err != nil {
			return fmt.Errorf("外键 %s 已加回但校验失败: %w", fk.Name, err)
		}
	}
	m.printf("已切回老表，外键 %d 个已加回并校验。可 abort 放弃，或 verify → repair → switch 再来", len(s.ForeignKeys))
	return nil
}

// finish 删掉老表与镜像，迁移不可再回滚。
func (m *Migrator) finish(ctx context.Context, c *sql.Conn) error {
	s, err := loadState(ctx, c)
	if err != nil {
		return err
	}
	if err := requirePhase(s, phaseSwitched); err != nil {
		return err
	}
	size, err := tableSize(ctx, c, OldName)
	if err != nil {
		return err
	}
	tx, err := c.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range []string{
		`SET LOCAL lock_timeout = '` + m.lockTimeout() + `'`,
		`DROP TRIGGER ` + mirrorTrigger + ` ON events`,
		`DROP TABLE ` + OldName,
		`DROP FUNCTION openxdr_events_mirror()`,
		fmt.Sprintf(`UPDATE %s SET phase = '%s', updated_at = now() WHERE id = 1`, stateTable, phaseFinished),
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.printf("迁移完成，删除 events_old 释放约 %s", human(uint64(size)))
	return nil
}

// abort 切换前放弃迁移：摘掉镜像、删掉 events_next 与迁移状态，老表原样不动。
func (m *Migrator) abort(ctx context.Context, c *sql.Conn) error {
	s, err := loadState(ctx, c)
	if err != nil {
		return err
	}
	if err := requirePhase(s, phaseCopying, phaseCopied, phaseIndexed, phaseVerified); err != nil {
		return err
	}
	tx, err := c.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range []string{
		`SET LOCAL lock_timeout = '` + m.lockTimeout() + `'`,
		`DROP TRIGGER IF EXISTS ` + mirrorTrigger + ` ON events`,
		`DROP TABLE IF EXISTS ` + NextName,
		`DROP FUNCTION IF EXISTS openxdr_events_mirror()`,
		`DROP TABLE ` + stateTable,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.printf("已放弃迁移，events 保持原样")
	return nil
}
