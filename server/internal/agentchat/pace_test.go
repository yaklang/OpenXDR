package agentchat

import (
	"context"
	"testing"
	"time"
)

// step 一条消息：角色与相对上一条的间隔
type step struct {
	role string
	gap  time.Duration
}

func replay(steps []step) *pace {
	at := time.Unix(0, 0)
	p := newPace(at)
	for _, s := range steps {
		at = at.Add(s.gap)
		p.mark(s.role, at)
	}
	return p
}

func TestWrapUpLead(t *testing.T) {
	const timeout = 30 * time.Minute
	for _, c := range []struct {
		name  string
		steps []step
		turn  time.Duration
		lead  time.Duration
	}{
		// 前几天的推理端：单轮 5–17 秒，3×17+60 不到 3 分钟，沿用原来的下限
		{"快模型", []step{{"user", 0}, {"assistant", 5 * time.Second}, {"toolResult", time.Second}, {"assistant", 17 * time.Second},
			{"toolResult", 2 * time.Second}, {"assistant", 9 * time.Second}}, 17 * time.Second, 3 * time.Minute},
		// 2026-10-21 的推理端：单轮平均 98 秒、最长 229 秒，提前 3×229+60 = 747 秒收尾
		{"慢模型", []step{{"user", 0}, {"assistant", 98 * time.Second}, {"toolResult", time.Second}, {"assistant", 229 * time.Second},
			{"toolResult", time.Second}, {"assistant", 95 * time.Second}}, 229 * time.Second, 747 * time.Second},
		// 一条命令等审批 10 分钟：落在 assistant 与工具结果之间，不算模型耗时
		{"长工具调用", []step{{"user", 0}, {"assistant", 10 * time.Second}, {"toolResult", 10 * time.Minute}, {"toolResult", time.Second},
			{"assistant", 12 * time.Second}}, 12 * time.Second, 3 * time.Minute},
		// 只看最近 5 轮：早先的一次慢轮滑出窗口后不再拖累
		{"窗口滑出", []step{{"assistant", 200 * time.Second}, {"assistant", 10 * time.Second}, {"assistant", 10 * time.Second},
			{"assistant", 10 * time.Second}, {"assistant", 10 * time.Second}, {"assistant", 20 * time.Second}}, 20 * time.Second, 3 * time.Minute},
		// 极慢时也给调查留一半时间
		{"封顶", []step{{"assistant", 10 * time.Minute}}, 10 * time.Minute, 15 * time.Minute},
		{"还没有样本", nil, 0, 3 * time.Minute},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := replay(c.steps)
			if got := p.turn(); got != c.turn {
				t.Errorf("单轮耗时应为 %v，得到 %v", c.turn, got)
			}
			if got := wrapUpLead(timeout, p.turn()); got != c.lead {
				t.Errorf("收尾提前量应为 %v，得到 %v", c.lead, got)
			}
		})
	}
	// 运行期限很短时固定余量也封顶在一半
	if got := wrapUpLead(10*time.Second, 0); got != 5*time.Second {
		t.Errorf("短期限封顶一半：%v", got)
	}
}

// watch 每记一轮重算：这一轮变慢、提前量超过剩余时间，立即触发，不等原来的时刻
func TestPaceWatchRearms(t *testing.T) {
	const timeout = 10 * time.Minute
	start := time.Now()
	p := newPace(start)
	// 没有样本时提前量 3 分钟：原定 2 秒后触发
	deadline := start.Add(3*time.Minute + 2*time.Second)
	fired := make(chan time.Time, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.watch(ctx, deadline, timeout, func() { fired <- time.Now() })
	time.Sleep(100 * time.Millisecond)
	select {
	case <-fired:
		t.Fatal("不应过早触发")
	default:
	}
	// 一轮用了 50 秒：提前量 3×50+60 = 210 秒，已超过剩余
	p.mark("assistant", start.Add(50*time.Second))
	select {
	case at := <-fired:
		if at.Sub(start) > time.Second {
			t.Errorf("应立即触发，实际在 %v 后", at.Sub(start))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("没有触发")
	}
}

func TestInvestigateBudgetCapsShortDeadline(t *testing.T) {
	s := &Service{} // 默认 timeout = 4h

	// 30 分钟任务（如 ops-followup）：预算应按 ctx 剩余期限算，收尾提前量封顶在 15m 而非 2h
	ctx30, cancel30 := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel30()
	_, budget := s.investigateBudget(ctx30)
	if budget > 30*time.Minute || budget < 29*time.Minute {
		t.Fatalf("30m 任务的收尾预算应约为 30m，实际=%v", budget)
	}
	if lead := wrapUpLead(budget, 15*time.Minute); lead > 15*time.Minute || lead < 14*time.Minute {
		t.Fatalf("30m 任务的收尾提前量应封顶在一半(~15m)，实际=%v", lead)
	}

	// 长于默认超时的 ctx 仍受 s.timeout() 封顶
	ctxLong, cancelLong := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancelLong()
	if _, got := s.investigateBudget(ctxLong); got != s.timeout() {
		t.Fatalf("超长 ctx 应封顶到 s.timeout()=%v，实际=%v", s.timeout(), got)
	}

	// 无 deadline 时回落到 s.timeout()
	if _, got := s.investigateBudget(context.Background()); got != s.timeout() {
		t.Fatalf("无 deadline 应使用 s.timeout()=%v，实际=%v", s.timeout(), got)
	}
}
