package cluster

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// 集群包的纯逻辑单测不带 integration tag：租约抢锁依赖真实 Postgres
// （见 leader_integration_test.go），wait 是带 ctx 的通用等待原语，先锤炼它。

func TestWaitCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		wait(ctx, time.Second)
		close(done)
	}()
	// 等 goroutine 进入 wait 的 select 后再取消，确保走的是 ctx 分支
	time.Sleep(5 * time.Millisecond)
	cancel()
	<-done
	if d := time.Since(start); d >= time.Second {
		t.Errorf("ctx 取消后 wait 应立即返回，实际等了 %v", d)
	}
}

func TestWaitHonorsDuration(t *testing.T) {
	start := time.Now()
	wait(context.Background(), 20*time.Millisecond)
	if d := time.Since(start); d < 15*time.Millisecond {
		t.Errorf("wait 未到时长不应提前返回，实际只等了 %v", d)
	}
}

// blockingUnlockDriver 模拟数据库网络半开：加锁成功，但 pg_advisory_unlock 一直阻塞直到 ctx 超时。
type blockingUnlockDriver struct {
	unlockTimedOut atomic.Bool
}

func (d *blockingUnlockDriver) Open(string) (driver.Conn, error) {
	return &blockingUnlockConn{drv: d}, nil
}

type blockingUnlockConn struct{ drv *blockingUnlockDriver }

func (c *blockingUnlockConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *blockingUnlockConn) Close() error                        { return nil }
func (c *blockingUnlockConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }
func (c *blockingUnlockConn) Ping(context.Context) error          { return nil }

func (c *blockingUnlockConn) ExecContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "pg_advisory_unlock") {
		<-ctx.Done()
		c.drv.unlockTimedOut.Store(true)
		return nil, ctx.Err()
	}
	return driver.RowsAffected(1), nil
}

func (c *blockingUnlockConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "pg_try_advisory_lock") {
		return &boolRows{val: true}, nil
	}
	return &boolRows{val: false}, nil
}

type boolRows struct {
	val  bool
	done bool
}

func (r *boolRows) Columns() []string { return []string{"ok"} }
func (r *boolRows) Close() error      { return nil }
func (r *boolRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.val
	return nil
}

func TestUnlockTimesOutOnHalfOpenConnection(t *testing.T) {
	orig := unlockTimeout
	unlockTimeout = 50 * time.Millisecond
	t.Cleanup(func() { unlockTimeout = orig })

	drv := &blockingUnlockDriver{}
	db := sql.OpenDB(&funcConnector{drv: drv})
	t.Cleanup(func() { _ = db.Close() })

	// 1. WithLock 解锁遇到网络半开必须在超时内返回
	start := time.Now()
	if err := WithLock(context.Background(), db, "halfopen-lock", func() error { return nil }); err != nil {
		t.Fatalf("WithLock 业务成功不应报错: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("WithLock 解锁未按超时退出，耗时 %v", d)
	}
	if !drv.unlockTimedOut.Load() {
		t.Fatal("WithLock 未走带超时的解锁路径")
	}

	// 2. RunLeader 收到取消信号后解锁遇到网络半开也必须在超时内退出
	drv.unlockTimedOut.Store(false)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunLeader(ctx, db, "halfopen-leader", func(wctx context.Context) {
			close(started)
			<-wctx.Done()
		})
	}()
	<-started
	start = time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunLeader 解锁阻塞超过 1 秒，未按超时退出")
	}
	if !drv.unlockTimedOut.Load() {
		t.Fatal("RunLeader 未走带超时的解锁路径")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("RunLeader 退出过慢: %v", d)
	}
}

type funcConnector struct{ drv driver.Driver }

func (c *funcConnector) Connect(context.Context) (driver.Conn, error) { return c.drv.Open("") }
func (c *funcConnector) Driver() driver.Driver                        { return c.drv }
