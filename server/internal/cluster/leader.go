// Package cluster 提供基于 PostgreSQL advisory lock 的单活后台任务租约。
package cluster

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

// WithLock 串行执行短事务型集群操作，例如 schema 迁移和管理员初始化。
func WithLock(ctx context.Context, db *sql.DB, name string, fn func() error) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, "openxdr:"+name); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, "openxdr:"+name)
	}()
	return fn()
}

// RunLeader 在集群中只让一个实例运行同名后台循环。锁绑定独占数据库连接；
// 连接失效时立即取消任务，其他节点随后接管。
func RunLeader(ctx context.Context, db *sql.DB, name string, run func(context.Context)) {
	for ctx.Err() == nil {
		conn, err := db.Conn(ctx)
		if err != nil {
			retry(ctx, name, err)
			continue
		}
		var acquired bool
		err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, "openxdr:"+name).Scan(&acquired)
		if err != nil || !acquired {
			_ = conn.Close()
			if err != nil {
				retry(ctx, name, err)
			} else {
				wait(ctx, 5*time.Second)
			}
			continue
		}

		slog.Info("取得集群任务租约", "task", name)
		workerCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); run(workerCtx) }()
		ticker := time.NewTicker(5 * time.Second)
		alive := true
		for alive {
			select {
			case <-ctx.Done():
				alive = false
			case <-done:
				alive = false
			case <-ticker.C:
				if err := conn.PingContext(workerCtx); err != nil {
					slog.Warn("集群任务租约连接失效", "task", name, "err", err)
					alive = false
				}
			}
		}
		ticker.Stop()
		cancel()
		<-done
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, "openxdr:"+name)
		_ = conn.Close()
		wait(ctx, time.Second)
	}
}

func retry(ctx context.Context, name string, err error) {
	slog.Warn("获取集群任务租约失败", "task", name, "err", err)
	wait(ctx, 5*time.Second)
}

func wait(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
