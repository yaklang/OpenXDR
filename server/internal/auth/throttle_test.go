package auth

import (
	"testing"
	"time"
)

func TestThrottleBackoff(t *testing.T) {
	th := &throttle{failures: map[string]*failEntry{}}
	now := time.Now()

	// 免费额度内不拦
	for i := 0; i < throttleAfter-1; i++ {
		th.Fail("1.2.3.4", now)
	}
	if th.Blocked("1.2.3.4", now) {
		t.Fatal("未超阈值不该被拦")
	}

	// 达到阈值进入退避
	th.Fail("1.2.3.4", now)
	if !th.Blocked("1.2.3.4", now) {
		t.Fatal("超阈值应被拦")
	}
	// 别的来源不受影响
	if th.Blocked("5.6.7.8", now) {
		t.Fatal("其他来源不该被拦")
	}
	// 退避期过了自动放行
	if th.Blocked("1.2.3.4", now.Add(throttleBase+time.Second)) {
		t.Fatal("退避期过后应放行")
	}

	// 继续失败退避翻倍
	th.Fail("1.2.3.4", now)
	if th.Blocked("1.2.3.4", now.Add(throttleBase+time.Second)) != true {
		t.Fatal("再次失败退避应翻倍到 60s")
	}

	// 成功清零
	th.Clear("1.2.3.4")
	if th.Blocked("1.2.3.4", now) {
		t.Fatal("清零后不该被拦")
	}
}

func TestThrottlePrune(t *testing.T) {
	th := &throttle{failures: map[string]*failEntry{}}
	now := time.Now()
	th.failures["expired"] = &failEntry{count: 10, until: now.Add(-time.Minute)}
	th.failures["active"] = &failEntry{count: 10, until: now.Add(time.Hour)}
	th.mu.Lock()
	th.prune(now)
	th.mu.Unlock()
	if _, ok := th.failures["expired"]; ok {
		t.Error("过期条目应被清掉")
	}
	if _, ok := th.failures["active"]; !ok {
		t.Error("活跃条目不该被清")
	}
}
