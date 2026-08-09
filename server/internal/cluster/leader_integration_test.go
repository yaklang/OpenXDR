//go:build integration

package cluster

import (
	"context"
	"database/sql"
	"os"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// openDB 连接测试库。advisory lock 依赖真实 Postgres，且只用到锁不碰业务表。
func openDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("INTEGRATION_DATABASE_URL")
	if dsn == "" {
		t.Skip("INTEGRATION_DATABASE_URL 未设置，跳过集成测试")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestRunLeaderSingleActive 验证 advisory lock 的单活语义：
// 同名任务并发运行时只有一个是 leader；首节点退出后另一节点接管，全程不出现双活。
func TestRunLeaderSingleActive(t *testing.T) {
	db := openDB(t)

	var active, peak atomic.Int32
	// run 返回时往外收一次计数；这里用闭包包装外层 run，保持 run 签名与 RunLeader 一致。
	run := func(ctx context.Context) {
		n := active.Add(1)
		for {
			cur := peak.Load()
			if n <= cur || peak.CompareAndSwap(cur, n) {
				break
			}
		}
		defer active.Add(-1)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}

	// 节点 A 先起，等它拿到锁。
	ctxA, cancelA := context.WithCancel(context.Background())
	doneA := make(chan struct{})
	go func() { defer close(doneA); RunLeader(ctxA, db, "test-single-active", run) }()
	time.Sleep(300 * time.Millisecond)

	// 节点 B 竞争同一任务，应当一直拿不到锁而排队。
	ctxB, cancelB := context.WithCancel(context.Background())
	doneB := make(chan struct{})
	go func() { defer close(doneB); RunLeader(ctxB, db, "test-single-active", run) }()

	// A 独占运行一段时间，全程不应出现并发。
	time.Sleep(500 * time.Millisecond)
	if p := peak.Load(); p != 1 {
		t.Fatalf("A 运行阶段期望单活（峰值 1），实际并发峰值 %d", p)
	}

	// A 退出，B 应接管；虽因轮询间隔有等待，最终仍只有一个在跑。
	cancelA()
	<-doneA

	deadline := time.Now().Add(7 * time.Second) // B 竞争失败时最多等 5s 重试
	for time.Now().Before(deadline) {
		if active.Load() == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// 短暂稳定后确认仍是单活且 B 已接管。
	time.Sleep(300 * time.Millisecond)
	if active.Load() != 1 {
		t.Fatalf("B 接管后期望 1 个 leader，实际 %d", active.Load())
	}
	if p := peak.Load(); p != 1 {
		t.Fatalf("全程期望单活（峰值 1），实际并发峰值 %d", p)
	}

	// 收尾：B 退出并释放锁。
	cancelB()
	<-doneB
}
