package eventpart

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// rewriteSuffix 是暂存表的后缀：日分区 events_pYYYYMMDD 重建时先写成
// events_pYYYYMMDD_rewrite，核对完再改名接上父表。
const rewriteSuffix = "_rewrite"

// lifecycleLockPrefix 是同日生命周期 advisory 锁的 key 前缀（冷归档 R1/R2）：
// 事件归属的 UTC 日是「引用写入者」（alerts / temporal_evidence / 已出告警的时序锚点，
// 事务级共享锁）与「破坏性操作」（swap / restore / retire / 到期清理，排他锁）的共同
// 协调对象。key 的唯一权威定义在本包（eventarchive 不能反向 import 本包会成环，
// 它的 lifecycle.go 经 LifecycleLockKey 取同一 key）；多日操作一律按 UTC 日升序取锁。
const lifecycleLockPrefix = "openxdr:lifecycle:"

// LifecycleLockKey 返回某 UTC 日的生命周期锁 key（YYYY-MM-DD，UTC）。
func LifecycleLockKey(day time.Time) string {
	return lifecycleLockPrefix + dayStart(day).Format("2006-01-02")
}

// lockExecer 是生命周期锁的最小执行接口：*sql.DB、*sql.Tx 与 ent 的事务都满足，
// 引用写入者（ingest / temporal）与清理方（janitor）在自己的事务里直接取锁。
type lockExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// lifecycleLockDays 把一批时间戳归一成去重、升序的 UTC 日（锁 key 的时间粒度）。
func lifecycleLockDays(ts ...time.Time) []time.Time {
	days := make([]time.Time, 0, len(ts))
	for _, t := range ts {
		d := dayStart(t)
		if !slices.Contains(days, d) {
			days = append(days, d)
		}
	}
	slices.SortFunc(days, func(a, b time.Time) int { return a.Compare(b) })
	return days
}

// lifecycleLock 是升序批量取锁的公共实现：modeSQL 是 pg_advisory_xact_lock[_shared]，
// 一条语句按 unnest 的升序逐日求值。升序求值保证与排他方的逐日升序互相不成环
// （共享/共享本就不冲突，排序只为与排他方交叉时无死锁）。
func lifecycleLock(ctx context.Context, q lockExecer, modeSQL string, ts ...time.Time) error {
	days := lifecycleLockDays(ts...)
	if len(days) == 0 {
		return nil
	}
	keys := make([]string, len(days))
	for i, d := range days {
		keys[i] = LifecycleLockKey(d)
	}
	if _, err := q.ExecContext(ctx,
		`SELECT `+modeSQL+`(hashtext(k)) FROM (SELECT unnest($1::text[]) AS k ORDER BY k) AS days`,
		keys); err != nil {
		return fmt.Errorf("取同日生命周期锁（%s，%d 日，%s..%s）: %w", modeSQL, len(days),
			days[0].Format("2006-01-02"), days[len(days)-1].Format("2006-01-02"), err)
	}
	return nil
}

// LifecycleLockShared 在引用写入事务内取这些时间戳归属日的共享生命周期锁（R1）。
// 事务级：提交/回滚自动释放；共享/共享并存，并发检测事务互不阻塞；同事务重复取同一日
// 立即成功（lock manager 认出本会话已持该模式，不会排到排他等待者后面）。
// 调用方随后必须锁内重读引用目标的热行。
func LifecycleLockShared(ctx context.Context, q lockExecer, ts ...time.Time) error {
	return lifecycleLock(ctx, q, "pg_advisory_xact_lock_shared", ts...)
}

// LifecycleLockExclusive 在破坏性清理事务内取这些时间戳归属日的排他生命周期锁（R1/R2）。
// 事务级、阻塞等待——调用方应先 SET LOCAL lock_timeout 防呆，等不到就失败重试。
// 供 retire / janitor 的到期清理等不走 rewriteDayTx 的路径使用；swap 的重写事务在
// rewriteDayTx 内自取同一 key。
func LifecycleLockExclusive(ctx context.Context, q lockExecer, ts ...time.Time) error {
	return lifecycleLock(ctx, q, "pg_advisory_xact_lock", ts...)
}

// ErrNothingToRewrite 表示事务内核对后没有任何要删除的行（保留口径覆盖了整个分区）：
// 事务已回滚、分区没有重建，调用方应按「无需操作」报告，不当成失败重试。
var ErrNothingToRewrite = errors.New("该分区没有可删的行，无需重建")

// RewriteInfo 描述一次重写的对象。eventpart 不知道调用方要校验什么，
// 只把表名交给注入点（冷归档用它拼集合校验与逐日记账的 SQL）。
type RewriteInfo struct {
	Day     time.Time // UTC 日（分区下界）
	Daily   string    // 日分区表名 events_pYYYYMMDD
	Staging string    // 暂存表名 events_pYYYYMMDD_rewrite（保留行已复制进去）
}

// 重写事务里测试注入点的阶段值（RewriteHooks.Observe 的 stage 参数）。
const (
	// RewriteAfterCopy 保留行已复制进暂存表、集合校验（Verify）之前。
	RewriteAfterCopy = "after_copy"
	// RewriteAfterIndexes 索引克隆完成、分区替换 DDL 之前。
	RewriteAfterIndexes = "after_indexes"
	// RewriteBeforeReplace 分区替换（DETACH/DROP/RENAME/ATTACH）之前、终检之前。
	RewriteBeforeReplace = "before_replace"
	// RewriteAfterRecord 逐日记账（Record）完成、COMMIT 之前。
	RewriteAfterRecord = "after_record"
)

// RewriteHooks 是 RewriteDayGuarded 的注入点，字段全部可空；eventpart 不感知调用方
// （冷归档）的表结构与口径，校验与记账内容由调用方以闭包注入。
type RewriteHooks struct {
	// Verify 在锁内、删除前执行「删除依据」的集合校验：不一致返回错误即整体回滚，
	// 原分区一行不动。在复制后（初检）与分区替换前（终检）各跑一次：终检把并发 pin
	// 一类的竞态窗口压缩到 [终检, commit]。
	Verify func(ctx context.Context, tx *sql.Tx, info RewriteInfo) error
	// Record 在分区替换完成、提交之前执行：与切换同一事务记账，杜绝
	// 「分区已切成功、成功记录单独写失败」的窗口。kept/dropped 是事务内实测数。
	Record func(ctx context.Context, tx *sql.Tx, info RewriteInfo, kept, dropped int64) error
	// DerivedSkip 在派生状态清理阶段逐表询问：返回 true 表示本次重写跳过该表的清理。
	// 派生清理删除的是「事件列 ∈ 本分区−暂存表」的行（事件随分区消失后不再可关联的派生行）；
	// 冷归档用它把 swap 与 retire 的清理口径分开——同一张派生表，retire 随保留期删是既有策略，
	// swap 顺带删则可能销毁尚未证明允许销毁的诊断记录（V09）。nil = derived 清单里的表全部
	// 照旧清理（retire 与裸 RewriteDay 的行为不变）。eventpart 不感知各表语义，只转发表名。
	DerivedSkip func(table string) bool
	// Observe 只用于测试：在固定阶段回调，返回错误即在该位置注入失败让事务回滚。
	// 生产恒为 nil，零行为差异。
	Observe func(ctx context.Context, tx *sql.Tx, info RewriteInfo, stage string) error
}

// RewriteDay 把一个日分区重建成只保留 keepSelect 选出的行，返回保留数与删除数。
//
// keepSelect 必须是「SELECT id FROM ...」形式的**只读**查询，由调用方给出保留口径
// （冷归档用它表达「被钉住的 + 不属于本 run 口径的」）。选中的行留在日分区里，
// 其余行随旧分区一起消失——这是全项目唯一会丢数据的分区操作，所以每一步都照 retireDay 的口径：
//
//  1. 只认独立日分区：该日的行还在默认分区（events_default）时直接报错，要求先 EnsureDays，
//     绝不自己去默认分区搬行；
//  2. 事务里先对日分区加 SHARE 锁：读照常，写入该日的迟到事件等待，复制期间行集不再变化；
//  3. 建暂存表 (LIKE parent INCLUDING DEFAULTS) → INSERT 保留行 → cloneIndexes
//     （与 retire 共用同一份索引克隆，ATTACH 时直接挂上，不在排他锁里现建索引）；
//  4. 独立数一遍 keepSelect 的行数，与暂存表实际行数不符即中止：keepSelect 指到别的表、
//     别的日分区或已被搬走的行时，这里会立刻露出来。删掉的若是整分区，那是事故不是本意；
//  5. 派生状态按 retire 的同一份清单清理（删分区不触发逐行级联触发器，必须显式做）；
//     RewriteHooks.DerivedSkip 非 nil 时按其决定逐表跳过（swap 与 retire 的清理口径可以不同）；
//  6. DETACH → DROP → RENAME → ATTACH 全在同一事务里：PostgreSQL 的 DDL 是事务性的，
//     任何一步失败都整体回滚，原分区及其索引、触发器原样保留。
//
// 不用 TRUNCATE，也不 DELETE FROM events：逐行删除会触发证据保护与级联触发器，
// 代价和语义都不是这里要的。失败一律返回错误，不吞。
//
// 冷归档的 swap 走 RewriteDayGuarded（同一份事务序列，外加锁内集合校验、同事务记账与
// advisory 并发闸门）；本函数保持原语义，供需要「裸重建」的调用方使用。
func RewriteDay(ctx context.Context, db *sql.DB, day time.Time, keepSelect string) (kept, dropped int64, err error) {
	return rewriteDayTx(ctx, db, day, keepSelect, RewriteHooks{}, false)
}

// RewriteDayGuarded 是带删除依据校验的分区重写：事务序列与 RewriteDay 相同（见上），
// 由调用方经 RewriteHooks 注入锁内校验、同事务记账与测试观察点，并且：
//
//   - 同一分区的重写一次只允许一个：事务内先取 advisory try 锁（不等待），第二个并发
//     操作立即明确拒绝，而不是靠后面的 DDL 锁超时兜底；retire 不取这把锁，与它的
//     串行化由分区 DDL 锁顺序保证；
//   - 事务内还取同日生命周期排他锁（LifecycleLockKey，在 try 锁之后、任何表锁与数据
//     访问之前）：与引用写入者的事务级共享锁互斥，把「终检后、DETACH 前新增引用」的
//     竞态从 verify 收窄的窗口改为锁上排队（R1）；restore / retire / 到期清理取同一
//     key，多日操作按 UTC 日升序（R2）；
//   - Verify 在复制后（初检）与分区替换前（终检）各跑一次：SHARE 锁挡得住该日 events
//     的写入，挡不住引用表（alerts 等）的并发 INSERT，复制之后新到的引用只能靠事务内
//     重读发现；
//   - 事务内核对后没有可删行（保留口径覆盖整个分区）时回滚并返回 ErrNothingToRewrite，
//     不做无谓的重建 DDL；
//   - Record 与分区替换同一事务提交，不存在「分区已切成功、成功记录单独写失败」的窗口。
//
// 失败一律返回 (0, 0, err)；提交失败同样整体回滚，计数不能当成已生效。
func RewriteDayGuarded(ctx context.Context, db *sql.DB, day time.Time, keepSelect string, hooks RewriteHooks) (kept, dropped int64, err error) {
	return rewriteDayTx(ctx, db, day, keepSelect, hooks, true)
}

func rewriteDayTx(ctx context.Context, db *sql.DB, day time.Time, keepSelect string, hooks RewriteHooks, guarded bool) (kept, dropped int64, err error) {
	keep, err := checkKeepSelect(ctx, db, keepSelect)
	if err != nil {
		return 0, 0, err
	}
	d := dayStart(day)
	daily := DailyName(d)
	set, err := listPartitions(ctx, db, Parent)
	if err != nil {
		return 0, 0, err
	}
	if !set.byName[daily] {
		return 0, 0, fmt.Errorf("%s 没有独立日分区 %s：该日的行在默认分区里，"+
			"先跑 EnsureDays 建好日分区再重写（本函数不碰默认分区）", d.Format(time.DateOnly), daily)
	}
	staging := daily + rewriteSuffix
	lo, hi := literal(d), literal(d.AddDate(0, 0, 1))
	info := RewriteInfo{Day: d, Daily: daily, Staging: staging}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(stmt string) (sql.Result, error) { return tx.ExecContext(ctx, stmt) }
	for _, stmt := range []string{`SET LOCAL lock_timeout = '` + LockTimeout + `'`} {
		if _, err := exec(stmt); err != nil {
			return 0, 0, err
		}
	}
	if guarded {
		// 并发闸门：同一日分区的重写一次一个。try 锁不等待，第二个操作立刻得到明确的
		// 拒绝，而不是在后面的 DDL 锁上排队等超时。事务结束自动释放。
		// 注意它先于生命周期锁取：并发第二个 swap 必须立即被 try 锁拒绝，而不是先在
		// 生命周期锁上排队（P3 的 T04a 固定了这个语义）。
		var locked bool
		if err := tx.QueryRowContext(ctx,
			`SELECT pg_try_advisory_xact_lock(hashtext('openxdr:eventpart:rewrite:'||$1))`,
			d.Format(time.DateOnly)).Scan(&locked); err != nil {
			return 0, 0, err
		}
		if !locked {
			return 0, 0, fmt.Errorf("另一个操作正在重写日分区 %s（advisory 锁被占用），拒绝并发执行", daily)
		}
		// 同日生命周期排他锁（R1/R2）：在本事务读写该日任何数据、以及任何表锁之前取得。
		// 引用写入者（告警/时序证据/已出告警锚点）持事务级共享锁建引用，与这里的排他互斥：
		// 终检之后、DETACH 之前到达的引用不再只靠 verify 收窄窗口，而是在锁上排队，等本
		// 事务提交后按「锁内重读热行 → 缺失则物化回热表」补链（eventarchive R1 路径）。
		// 阻塞等待（受上面的 lock_timeout 约束）：等的是当日并发检测事务提交，属正常串行。
		if _, err := tx.ExecContext(ctx,
			`SELECT pg_advisory_xact_lock(hashtext($1))`, LifecycleLockKey(d)); err != nil {
			return 0, 0, fmt.Errorf("取 %s 的同日生命周期排他锁: %w", d.Format(time.DateOnly), err)
		}
	}
	for _, stmt := range []string{
		fmt.Sprintf(`LOCK TABLE %s IN SHARE MODE`, daily),
		fmt.Sprintf(`CREATE TABLE %s (LIKE %s INCLUDING DEFAULTS)`, staging, Parent),
	} {
		if _, err := exec(stmt); err != nil {
			return 0, 0, err
		}
	}
	var total int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM `+daily).Scan(&total); err != nil {
		return 0, 0, fmt.Errorf("统计 %s 行数: %w", daily, err)
	}
	// 保留集自己数一遍，再与实际写进暂存表的行数比：两者不符说明 keepSelect 与这个日分区
	// 不是同一批行，此刻中止还能保住原分区
	var selected int64
	if err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT count(DISTINCT id) FROM (%s) AS keep_ids`, keep)).
		Scan(&selected); err != nil {
		return 0, 0, fmt.Errorf("执行保留口径: %w", err)
	}
	if _, err := exec(fmt.Sprintf(`INSERT INTO %s (%s) SELECT %s FROM %s WHERE id IN (%s)`,
		staging, Columns, Columns, daily, keep)); err != nil {
		return 0, 0, err
	}
	var keptRows int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM `+staging).Scan(&keptRows); err != nil {
		return 0, 0, fmt.Errorf("统计暂存表 %s 行数: %w", staging, err)
	}
	if keptRows != selected {
		return 0, 0, fmt.Errorf("保留计数不符：keepSelect 选出 %d 条，%s 里只有 %d 条（共 %d 条），"+
			"中止，原分区未改动", selected, daily, keptRows, total)
	}
	if keptRows > total {
		return 0, 0, fmt.Errorf("保留 %d 条超过 %s 的 %d 条，中止，原分区未改动", keptRows, daily, total)
	}
	observe := func(stage string) error {
		if hooks.Observe == nil {
			return nil
		}
		return hooks.Observe(ctx, tx, info, stage)
	}
	if guarded {
		if err := observe(RewriteAfterCopy); err != nil {
			return 0, 0, err
		}
		// 初检：锁内、删除前，用事务内重读的数据核对删除依据（保留集与冷副本覆盖）。
		if hooks.Verify != nil {
			if err := hooks.Verify(ctx, tx, info); err != nil {
				return 0, 0, err
			}
		}
		if keptRows == total {
			// 没有可删的行：回滚（defer），分区不重建，明确报告无需操作。
			return keptRows, 0, ErrNothingToRewrite
		}
	}
	for _, dv := range derived {
		if hooks.DerivedSkip != nil && hooks.DerivedSkip(dv.table) {
			continue
		}
		stmt := fmt.Sprintf(`DELETE FROM %s WHERE %s IN (SELECT id FROM %s EXCEPT SELECT id FROM %s)`,
			dv.table, dv.column, daily, staging)
		if _, err := exec(stmt); err != nil {
			return 0, 0, fmt.Errorf("清理派生状态 %s: %w", dv.table, err)
		}
	}
	if err := cloneIndexes(ctx, tx, Parent, staging); err != nil {
		return 0, 0, err
	}
	if guarded {
		if err := observe(RewriteAfterIndexes); err != nil {
			return 0, 0, err
		}
		if err := observe(RewriteBeforeReplace); err != nil {
			return 0, 0, err
		}
		// 终检：分区替换前把同一份集合校验再跑一遍，把并发引用（pin）的竞态窗口
		// 压缩到 [终检, commit]；终检之后到达的引用最多指向删除集（已有冷副本）里的行。
		if hooks.Verify != nil {
			if err := hooks.Verify(ctx, tx, info); err != nil {
				return 0, 0, err
			}
		}
	}
	for _, stmt := range []string{
		fmt.Sprintf(`ALTER TABLE %s DETACH PARTITION %s`, Parent, daily),
		`DROP TABLE ` + daily,
		fmt.Sprintf(`ALTER TABLE %s RENAME TO %s`, staging, daily),
		fmt.Sprintf(`ALTER TABLE %s ATTACH PARTITION %s FOR VALUES FROM (%s) TO (%s)`, Parent, daily, lo, hi),
	} {
		if _, err := exec(stmt); err != nil {
			return 0, 0, err
		}
	}
	if guarded && hooks.Record != nil {
		// 逐日记账与分区替换同一事务：记账失败连分区替换一起回滚。
		if err := hooks.Record(ctx, tx, info, keptRows, total-keptRows); err != nil {
			return 0, 0, err
		}
	}
	if guarded {
		if err := observe(RewriteAfterRecord); err != nil {
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		// 提交失败即整体回滚：原分区完好，计数不能当成已生效
		return 0, 0, err
	}
	return keptRows, total - keptRows, nil
}

// checkKeepSelect 校验 keepSelect 是单条只读查询并返回去掉首尾空白后的语句。
//
// 前缀与分号只是第一道闸门（挡住拼进第二条语句）；只读性由只读事务里的试执行兜底：
// 任何写数据的语句在 READ ONLY 事务里都会被 PostgreSQL 拒绝，包括
// `WITH x AS (INSERT ... RETURNING id) SELECT id FROM x` 这种形如 SELECT 的写法。
// 用 LIMIT 1 只取一行，验证的是「能不能执行」而不是结果有多少。
func checkKeepSelect(ctx context.Context, db *sql.DB, keepSelect string) (string, error) {
	keep := strings.TrimSpace(keepSelect)
	if keep == "" {
		return "", errors.New("keepSelect 不能为空")
	}
	if !startsWithKeyword(keep, "select") {
		return "", fmt.Errorf("keepSelect 必须是以 SELECT 开头的只读查询，实际是 %q", firstLine(keep))
	}
	if strings.Contains(keep, ";") {
		return "", errors.New("keepSelect 只能是一条语句（不允许分号）")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT id FROM (%s) AS keep_ids LIMIT 1`, keep))
	if err != nil {
		return "", fmt.Errorf("keepSelect 不可执行或不是只读查询: %w", err)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("keepSelect 不可执行或不是只读查询: %w", err)
	}
	return keep, nil
}

// startsWithKeyword 报告 s 是否以关键字 keyword 开头（大小写不敏感，后面必须跟空白）。
func startsWithKeyword(s, keyword string) bool {
	if len(s) < len(keyword) || !strings.EqualFold(s[:len(keyword)], keyword) {
		return false
	}
	return len(s) == len(keyword) || s[len(keyword)] == ' ' || s[len(keyword)] == '\n' ||
		s[len(keyword)] == '\t' || s[len(keyword)] == '\r'
}

// firstLine 截出错信息里要展示的部分：keepSelect 可能很长，报错只带第一行前 80 字节。
func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	const max = 80
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
