package eventpart

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	// DefaultName 兜底分区：没有对应日分区的时间戳（未来、远古、停机期间缺建的日子）落这里，不丢数据。
	DefaultName = "events_default"
	// PremakeDays 提前建好今天之后的天数；server 停机超过这么久，新事件暂落默认分区，恢复后预建时搬回日分区。
	PremakeDays = 7
	// LockTimeout 限定分区 DDL 等锁的时长：等不到就放弃重试，不让排队的排他锁把读写全堵住。
	LockTimeout = "3s"
)

// Today 返回 UTC 当天零点。分区边界一律按 UTC 日。
func Today() time.Time { return dayStart(time.Now()) }

func dayStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func monthStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// DailyName 是 [day, day+1) 日分区的表名。
func DailyName(day time.Time) string { return "events_p" + day.UTC().Format("20060102") }

// ArchiveName 是某月归档分区的表名：只装该月已过保留期、仍被引用的证据事件，下界是月初，上界随退役推进。
func ArchiveName(month time.Time) string { return "events_a" + month.UTC().Format("200601") }

func literal(t time.Time) string { return "'" + t.UTC().Format(time.RFC3339) + "'" }

type partitionSet struct {
	daily    []time.Time // 已排序的日分区下界
	archives map[string]bool
	byName   map[string]bool
	defName  string
}

func listPartitions(ctx context.Context, q interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}, parent string) (partitionSet, error) {
	set := partitionSet{archives: map[string]bool{}, byName: map[string]bool{}}
	rows, err := q.QueryContext(ctx, `SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
 WHERE i.inhparent = to_regclass($1)`, parent)
	if err != nil {
		return set, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return set, err
		}
		set.byName[name] = true
		switch {
		case strings.HasPrefix(name, "events_p") && len(name) == len("events_p20060102"):
			if day, err := time.Parse("20060102", strings.TrimPrefix(name, "events_p")); err == nil {
				set.daily = append(set.daily, day)
			}
		case strings.HasPrefix(name, "events_a") && len(name) == len("events_a200601"):
			set.archives[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		return set, err
	}
	sort.Slice(set.daily, func(i, j int) bool { return set.daily[i].Before(set.daily[j]) })
	var def sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT NULLIF(partdefid, 0)::regclass::text FROM pg_partitioned_table WHERE partrelid = to_regclass($1)`, parent).Scan(&def); err != nil && err != sql.ErrNoRows {
		return set, err
	}
	set.defName = def.String
	return set, nil
}

// EnsureDays 确保 [from, from+days] 每天都有日分区，返回新建个数。
// 用「建独立表 → 搬走默认分区里该日的行 → ATTACH」而不是 CREATE TABLE ... PARTITION OF：
// ATTACH 只对父表加 SHARE UPDATE EXCLUSIVE，不阻塞写入；默认分区里已有该日的行时直接建分区会失败。
func EnsureDays(ctx context.Context, db *sql.DB, parent string, from time.Time, days int) (int, error) {
	set, err := listPartitions(ctx, db, parent)
	if err != nil {
		return 0, err
	}
	created := 0
	for i := 0; i <= days; i++ {
		day := dayStart(from).AddDate(0, 0, i)
		if set.byName[DailyName(day)] {
			continue
		}
		if err := attachDay(ctx, db, parent, set.defName, day); err != nil {
			return created, fmt.Errorf("预建分区 %s: %w", DailyName(day), err)
		}
		created++
	}
	return created, nil
}

func attachDay(ctx context.Context, db *sql.DB, parent, def string, day time.Time) error {
	name, lo, hi := DailyName(day), literal(day), literal(day.AddDate(0, 0, 1))
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmts := []string{
		`SET LOCAL lock_timeout = '` + LockTimeout + `'`,
		fmt.Sprintf(`CREATE TABLE %s (LIKE %s INCLUDING DEFAULTS)`, name, parent),
	}
	if def != "" {
		// 先锁默认分区再 ATTACH：写入方是先父表后叶子，ATTACH 对父表的锁与写入不冲突，不会成环
		stmts = append(stmts,
			fmt.Sprintf(`LOCK TABLE %s IN SHARE ROW EXCLUSIVE MODE`, def),
			movingRows,
			fmt.Sprintf(`WITH moved AS (DELETE FROM %s WHERE ts >= %s AND ts < %s RETURNING %s)
 INSERT INTO %s (%s) SELECT %s FROM moved`, def, lo, hi, Columns, name, Columns, Columns))
	}
	stmts = append(stmts, fmt.Sprintf(`ALTER TABLE %s ATTACH PARTITION %s FOR VALUES FROM (%s) TO (%s)`, parent, name, lo, hi))
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// OldestDaily 返回最老日分区的下界；更早的时间只剩归档分区与默认分区。没有日分区时 ok 为 false。
func OldestDaily(ctx context.Context, db *sql.DB) (time.Time, bool, error) {
	set, err := listPartitions(ctx, db, Parent)
	if err != nil || len(set.daily) == 0 {
		return time.Time{}, false, err
	}
	return set.daily[0], true, nil
}

// Retire 把上界不晚于 cutoff 的日分区逐个退役，返回退役个数与丢弃的事件数。
// 退役 = 被引用的证据事件并进当月归档分区，其余随分区整体删除；派生状态按原级联口径显式清理。
func Retire(ctx context.Context, db *sql.DB, cutoff time.Time) (int, int64, error) {
	set, err := listPartitions(ctx, db, Parent)
	if err != nil {
		return 0, 0, err
	}
	retired, dropped := 0, int64(0)
	for _, day := range set.daily {
		if day.AddDate(0, 0, 1).After(cutoff) {
			break
		}
		n, err := retireDay(ctx, db, set, day)
		if err != nil {
			return retired, dropped, fmt.Errorf("退役分区 %s: %w", DailyName(day), err)
		}
		set.archives[ArchiveName(monthStart(day))] = true
		retired++
		dropped += n
	}
	return retired, dropped, nil
}

// retireDay 在一个事务里重建当月归档分区：旧归档 + 本日证据 + 默认分区里落在该范围的行，
// 再 DETACH 旧归档与日分区、ATTACH 新归档。复制都在对父表加排他锁之前做完，
// 父表排他锁只覆盖 DETACH / DROP / ATTACH 的目录操作与小表校验。
//
// 日分区先加 SHARE 锁：读照常，迟到写入该日的事务等待，保证复制出的证据集合在删除前不再变化。
// 时序证据只会引用最近 24 小时窗口 + 迟到余量内的事件，调用方用 RetireGuard 保证退役的日子早于它。
func retireDay(ctx context.Context, db *sql.DB, set partitionSet, day time.Time) (int64, error) {
	month := monthStart(day)
	daily, archive := DailyName(day), ArchiveName(month)
	staging := archive + "_next"
	lo, hi := literal(month), literal(day.AddDate(0, 0, 1))
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(stmt string) (sql.Result, error) { return tx.ExecContext(ctx, stmt) }
	for _, stmt := range []string{
		`SET LOCAL lock_timeout = '` + LockTimeout + `'`,
		fmt.Sprintf(`LOCK TABLE %s IN SHARE MODE`, daily),
		fmt.Sprintf(`CREATE TABLE %s (LIKE %s INCLUDING DEFAULTS)`, staging, Parent),
		fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM %s WHERE id IN (%s)`, staging, Columns, Columns, daily, PinnedIDs),
	} {
		if _, err := exec(stmt); err != nil {
			return 0, err
		}
	}
	var total, kept int64
	if err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT (SELECT count(*) FROM %s), (SELECT count(*) FROM %s)`, daily, staging)).Scan(&total, &kept); err != nil {
		return 0, err
	}
	for _, d := range derived {
		if _, err := exec(fmt.Sprintf(`DELETE FROM %s WHERE %s IN (SELECT id FROM %s EXCEPT SELECT id FROM %s)`, d.table, d.column, daily, staging)); err != nil {
			return 0, err
		}
	}
	if set.defName != "" {
		for _, stmt := range []string{
			fmt.Sprintf(`LOCK TABLE %s IN SHARE ROW EXCLUSIVE MODE`, set.defName),
			movingRows,
			fmt.Sprintf(`WITH moved AS (DELETE FROM %s WHERE ts >= %s AND ts < %s RETURNING %s)
 INSERT INTO %s (%s) SELECT %s FROM moved`, set.defName, lo, hi, Columns, staging, Columns, Columns),
		} {
			if _, err := exec(stmt); err != nil {
				return 0, err
			}
		}
	}
	hasArchive := set.byName[archive] || set.archives[archive]
	if hasArchive {
		for _, stmt := range []string{
			fmt.Sprintf(`LOCK TABLE %s IN SHARE MODE`, archive),
			fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM %s`, staging, Columns, Columns, archive),
		} {
			if _, err := exec(stmt); err != nil {
				return 0, err
			}
		}
	}
	if err := cloneIndexes(ctx, tx, Parent, staging); err != nil {
		return 0, err
	}
	stmts := []string{fmt.Sprintf(`ALTER TABLE %s DETACH PARTITION %s`, Parent, daily)}
	if hasArchive {
		stmts = append(stmts, fmt.Sprintf(`ALTER TABLE %s DETACH PARTITION %s`, Parent, archive), `DROP TABLE `+archive)
	}
	stmts = append(stmts,
		`DROP TABLE `+daily,
		fmt.Sprintf(`ALTER TABLE %s RENAME TO %s`, staging, archive),
		fmt.Sprintf(`ALTER TABLE %s ATTACH PARTITION %s FOR VALUES FROM (%s) TO (%s)`, Parent, archive, lo, hi))
	for _, stmt := range stmts {
		if _, err := exec(stmt); err != nil {
			return 0, err
		}
	}
	return total - kept, tx.Commit()
}

// cloneIndexes 在独立表上按父表的分区索引建好同构索引，ATTACH 时直接挂上而不是在排他锁里现建。
func cloneIndexes(ctx context.Context, tx *sql.Tx, parent, table string) error {
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD PRIMARY KEY (id, ts)`, table)); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT pg_get_indexdef(indexrelid) FROM pg_index WHERE indrelid = to_regclass($1) AND NOT indisprimary`, parent)
	if err != nil {
		return err
	}
	var defs []string
	for rows.Next() {
		var def string
		if err := rows.Scan(&def); err != nil {
			rows.Close()
			return err
		}
		defs = append(defs, def)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, def := range defs {
		method, err := indexMethod(def)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`CREATE INDEX ON %s USING %s`, table, method)); err != nil {
			return err
		}
	}
	return nil
}

// indexMethod 取 pg_get_indexdef 输出里 USING 之后的部分（访问方法、列/表达式与可能的 WHERE）。
func indexMethod(def string) (string, error) {
	_, method, ok := strings.Cut(def, " USING ")
	if !ok || strings.HasPrefix(def, "CREATE UNIQUE") {
		return "", fmt.Errorf("不支持的索引定义: %s", def)
	}
	return method, nil
}
