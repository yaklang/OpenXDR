package grpcsvc

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHasHostedLXC(t *testing.T) {
	raw := json.RawMessage(`[
		{"runtime":"docker","uid":"abc","name":"gateway","addrs":["172.17.0.2"]},
		{"runtime":"lxc","uid":"203","name":"gateway","addrs":["10.1.1.100"]},
		{"runtime":"lxc","uid":"204","name":"dns","addrs":["10.1.1.20"]}
	]`)
	if !hasHostedLXC(raw, "gateway") {
		t.Fatal("已登记的 LXC 应返回 true")
	}
	if !hasHostedLXC(raw, "dns") {
		t.Fatal("已登记的另一个 LXC 应返回 true")
	}
	if hasHostedLXC(raw, "other") {
		t.Fatal("未登记的名称应返回 false")
	}
	if hasHostedLXC(json.RawMessage(`[{"runtime":"docker","uid":"1","name":"gateway","addrs":["172.17.0.2"]}]`), "gateway") {
		t.Fatal("仅有 docker 同名容器时不应视为 LXC")
	}
	if hasHostedLXC(nil, "gateway") || hasHostedLXC(json.RawMessage(`not-json`), "gateway") || hasHostedLXC(raw, "") {
		t.Fatal("空清单、损坏 JSON 或空名称应返回 false")
	}
}

func TestSameGroup(t *testing.T) {
	g1, g2 := uuid.New(), uuid.New()
	g1Copy := g1
	if !sameGroup(nil, nil) {
		t.Fatal("双方均未分组应视为同组")
	}
	if !sameGroup(&g1, &g1Copy) {
		t.Fatal("同组 UUID 应返回 true")
	}
	if sameGroup(&g1, &g2) || sameGroup(&g1, nil) || sameGroup(nil, &g2) {
		t.Fatal("不同组或一方未分组应返回 false")
	}
}

func TestGuestCacheCapAndEviction(t *testing.T) {
	c := &guestCache{cap: 16}
	host := uuid.New()
	base := time.Now()

	// 写入超过上限的随机名称：缓存大小绝不能超过上限
	for i := 0; i < 64; i++ {
		id := uuid.New()
		k := guestKey{hostID: host, name: fmt.Sprintf("ct-%d", i)}
		c.put(k, guestEntry{id: &id, os: "linux", at: base.Add(time.Duration(i) * time.Millisecond)}, base.Add(time.Duration(i)*time.Millisecond))
		if len(c.m) > 16 {
			t.Fatalf("缓存条目数 %d 超过上限 16", len(c.m))
		}
	}
	// 最新写入的条目应仍保留
	latest := guestKey{hostID: host, name: "ct-63"}
	if _, ok := c.get(latest, base.Add(100*time.Millisecond)); !ok {
		t.Fatal("最新写入的条目不应被淘汰")
	}
	// 超过 TTL 后应视为未命中，并在新写入时优先清理过期条目
	afterTTL := base.Add(guestTTL + time.Second)
	if _, ok := c.get(latest, afterTTL); ok {
		t.Fatal("过期条目不应命中")
	}
	freshKey := guestKey{hostID: host, name: "fresh"}
	freshID := uuid.New()
	c.put(freshKey, guestEntry{id: &freshID, os: "linux", at: afterTTL}, afterTTL)
	if len(c.m) != 1 {
		t.Fatalf("满容触发清理后，已过期的旧条目应全部清除，剩余 %d", len(c.m))
	}
}

func TestGuestCacheConcurrentAccess(t *testing.T) {
	c := &guestCache{cap: 64}
	host := uuid.New()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				now := time.Now()
				k := guestKey{hostID: host, name: fmt.Sprintf("w%d-%d", worker, i%40)}
				id := uuid.New()
				c.put(k, guestEntry{id: &id, os: "linux", at: now}, now)
				_, _ = c.get(k, now)
			}
		}(g)
	}
	wg.Wait()
	if len(c.m) > 64 {
		t.Fatalf("并发写入后缓存超过上限：%d", len(c.m))
	}
}
