package cluster

import (
	"context"
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
