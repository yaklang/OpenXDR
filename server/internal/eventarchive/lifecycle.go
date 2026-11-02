package eventarchive

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"openxdr/server/internal/eventpart"
)

// 同日生命周期 advisory 锁（R1/R2，COLD_ARCHIVE_EVOLUTION.SCRATCH.md §P3 的两节最小修复）。
//
// key = hashtext(eventpart.LifecycleLockKey(day))，即 'openxdr:lifecycle:' || <UTC 日>。
// PostgreSQL 16 起 advisory 锁分共享 / 排他两种模式，事务级入口在 eventpart
// （LifecycleLockShared / LifecycleLockExclusive——temporal、ingest、janitor 都要用，
// 它们不能反向依赖本包：本包的切换闸门 guard.go 反过来 import temporal）：
//
//   - 引用写入者（alerts.event_id / temporal_evidence.event_id / 已出告警的
//     temporal_detections 锚点）：pg_advisory_xact_lock_shared，事务级——提交或回滚自动
//     释放；共享/共享并存，多个并发检测事务照常建引用；同事务重复取同一日立即成功。
//   - 破坏性操作（swap 的重写事务在 eventpart.rewriteDayTx 内 / retire / janitor 到期
//     清理）：pg_advisory_xact_lock，事务级排他——等当日全部引用事务提交后才动手。
//   - Restore 是多块多事务：本文件 DayLockGuard 在专用连接上持会话级排他 pg_advisory_lock，
//     从枚举块到最后一块提交 + 完成记录全程持有，显式 unlock 后关闭连接，绝不把仍持
//     锁的连接归还连接池；连接中断锁随会话消失，后续块不得继续。
//
// 多日操作（ingest 的时序窗口、retire、sweep）一律按 UTC 日升序取锁。升序是全局约定：
// 排他方逐日升序、共享方也升序（单条语句内 unnest + ORDER BY 逐日求值），两类等待者
// 不可能互相持对方想要的更早日子，不会成环。
//
// 这把锁不替代 swap 已有的 per 分区 rewrite try 锁（防同分区并发重写）与 LOCK TABLE
// SHARE（挡该日 events 写入）；它补的是引用表（alerts / temporal_*）不碰 events 分区、
// 表锁挡不住的那条竞态链。

// DayLockGuard 是 Restore 持有的会话级同日排他锁：专用连接 + 显式释放（R2）。
// Restore 按块多事务提交，没有哪个事务能覆盖整次操作，所以在专用连接上持会话级锁，
// 从枚举块到最后一块提交 + 完成记录全程互斥同日的 swap / retire / 到期清理。
type DayLockGuard struct {
	conn *sql.Conn
	day  time.Time
}

// LockDaySessionExclusive 在专用连接上取该日的会话级排他生命周期锁。
// 连接来自 db.Conn，只归属本次 Restore：绝不归还连接池（Release 先显式 unlock 再 Close）。
// 阻塞等待是预期行为（等的是当日正在进行的 swap / 引用事务，操作者可用 Ctrl-C 取消）。
func LockDaySessionExclusive(ctx context.Context, db *sql.DB, day time.Time) (*DayLockGuard, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("开生命周期锁专用连接: %w", err)
	}
	d := dayStart(day)
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtext($1))`,
		eventpart.LifecycleLockKey(d)); err != nil {
		// 没拿到锁（等待超时/取消/连接故障）：直接丢弃连接，不留持有半把锁的会话在池外。
		_ = conn.Close()
		return nil, fmt.Errorf("取 %s 的会话级生命周期排他锁: %w", d.Format("2006-01-02"), err)
	}
	return &DayLockGuard{conn: conn, day: d}, nil
}

// Alive 确认锁连接仍在。会话锁随连接消失而释放：专用连接断开后锁已不在手上，
// 后续块不得在无保护状态下继续，Restore 在每块前调用本方法。
func (g *DayLockGuard) Alive(ctx context.Context) error {
	if g == nil || g.conn == nil {
		return fmt.Errorf("%s 的生命周期锁连接已关闭，不得继续后续块", g.day.Format("2006-01-02"))
	}
	if _, err := g.conn.ExecContext(ctx, `SELECT 1`); err != nil {
		return fmt.Errorf("%s 的生命周期锁连接不可用（会话锁已随连接消失，结果待核对，不得继续后续块）: %w",
			g.day.Format("2006-01-02"), err)
	}
	return nil
}

// Release 显式解锁并关闭专用连接。顺序固定：先 unlock 再 close——close 把连接归还池时
// 它已不持有任何会话锁。unlock 没执行成功（连接半死）时不能归还连接，直接终结后端
// 会话让锁随连接消失，坏连接由连接池按故障丢弃。
func (g *DayLockGuard) Release() {
	if g == nil || g.conn == nil {
		return
	}
	if _, err := g.conn.ExecContext(context.Background(),
		`SELECT pg_advisory_unlock(hashtext($1))`, eventpart.LifecycleLockKey(g.day)); err != nil {
		kctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = g.conn.ExecContext(kctx, `SELECT pg_terminate_backend(pg_backend_pid())`)
		cancel()
	}
	_ = g.conn.Close()
	g.conn = nil
}
