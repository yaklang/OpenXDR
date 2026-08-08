package auth

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// 登录失败限速：同一来源反复失败后指数退避。
// 状态在内存里，重启即清零——爆破防护要的是把速率压下来，不是永久封禁。
const (
	// 免费失败次数，超过开始退避。手滑输错几次不该被锁
	throttleAfter = 5
	throttleBase  = 30 * time.Second
	// 退避封顶：30s << 7 ≈ 64 分钟
	throttleMaxShift = 7
	// map 兜底上限，防御伪造源地址撑爆内存
	throttleMaxKeys = 10000
)

type failEntry struct {
	count int
	until time.Time
}

type throttle struct {
	mu       sync.Mutex
	failures map[string]*failEntry
}

var loginThrottle = &throttle{failures: map[string]*failEntry{}}

// Blocked 当前是否处于退避期。
func (t *throttle) Blocked(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.failures[key]
	return e != nil && now.Before(e.until)
}

// Fail 记一次失败。超过免费次数后，每多错一次退避时间翻倍。
func (t *throttle) Fail(key string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.failures) >= throttleMaxKeys {
		t.prune(now)
	}
	e := t.failures[key]
	if e == nil {
		e = &failEntry{}
		t.failures[key] = e
	}
	e.count++
	if e.count >= throttleAfter {
		shift := min(e.count-throttleAfter, throttleMaxShift)
		e.until = now.Add(throttleBase << shift)
	}
}

// Clear 登录成功即清零，正常用户不背历史包袱。
func (t *throttle) Clear(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, key)
}

// prune 清掉退避期已过的条目。调用方持锁。
func (t *throttle) prune(now time.Time) {
	for k, e := range t.failures {
		if now.After(e.until) {
			delete(t.failures, k)
		}
	}
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
