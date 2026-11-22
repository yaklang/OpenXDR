package grpcsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/asset"
)

// LXC 里的进程由宿主机 agent 按 cgroup 采到（容器里自己的 agent 常常加载不了 eBPF，只能轮询），
// 事件却挂在宿主机名下：研判看到的是「pve1 上的容器」，处置等级、关联都错位。
// 仅当上报宿主机在设备清单的 containers 中登记了该 LXC 名称、且宿主机与目标资产同组且均未下线时，
// 才将事件归到目标资产，原宿主机记在 observed_by 里。
// 只认 LXC：Docker 容器不是资产，QEMU 进程本来就属于宿主机。

const (
	guestTTL      = time.Minute
	maxGuestCache = 4096
)

type guestKey struct {
	hostID uuid.UUID
	name   string
}

type guestEntry struct {
	id *uuid.UUID
	os string
	at time.Time
}

type guestCache struct {
	mu  sync.RWMutex
	m   map[guestKey]guestEntry
	cap int // 零值按 maxGuestCache 处理，方便单测覆盖上限
}

func (c *guestCache) limit() int {
	if c.cap > 0 {
		return c.cap
	}
	return maxGuestCache
}

func (c *guestCache) get(k guestKey, now time.Time) (guestEntry, bool) {
	c.mu.RLock()
	e, ok := c.m[k]
	c.mu.RUnlock()
	if !ok || now.Sub(e.at) >= guestTTL {
		return guestEntry{}, false
	}
	return e, true
}

func (c *guestCache) put(k guestKey, e guestEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[guestKey]guestEntry{}
	}
	if _, exists := c.m[k]; !exists && len(c.m) >= c.limit() {
		// 先清理所有已过期条目；若仍满则按时间淘汰最旧的一批，防伪造随机名撑爆内存
		for key, val := range c.m {
			if now.Sub(val.at) >= guestTTL {
				delete(c.m, key)
			}
		}
		if len(c.m) >= c.limit() {
			type item struct {
				k  guestKey
				at time.Time
			}
			items := make([]item, 0, len(c.m))
			for key, val := range c.m {
				items = append(items, item{k: key, at: val.at})
			}
			slices.SortFunc(items, func(a, b item) int { return a.at.Compare(b.at) })
			evict := max(1, len(c.m)-c.limit()*3/4)
			for i := 0; i < evict && i < len(items); i++ {
				delete(c.m, items[i].k)
			}
		}
	}
	c.m[k] = e
}

// lxcGuest 事件来自哪个 LXC（没有返回空）
func lxcGuest(rawMap map[string]any) string {
	c, _ := rawMap["container"].(map[string]any)
	if c == nil || c["runtime"] != "lxc" {
		return ""
	}
	name, _ := c["name"].(string)
	return name
}

// hasHostedLXC 检查宿主机上报的容器清单是否登记了指定名称的 LXC 容器。
func hasHostedLXC(containers json.RawMessage, name string) bool {
	if len(containers) == 0 || name == "" {
		return false
	}
	var list []struct {
		Runtime string `json:"runtime"`
		Name    string `json:"name"`
	}
	if json.Unmarshal(containers, &list) != nil {
		return false
	}
	for _, h := range list {
		if h.Runtime == "lxc" && h.Name == name {
			return true
		}
	}
	return false
}

// sameGroup 两台资产所属组是否一致（均未分组或同属一个组）。
func sameGroup(a, b *uuid.UUID) bool {
	if a == nil && b == nil {
		return true
	}
	return a != nil && b != nil && *a == *b
}

// guestAsset 校验并查找宿主机所托管 LXC 对应的目标资产，查不到或归属不合法返回 nil；结果缓存一分钟。
func (s *Server) guestAsset(ctx context.Context, hostID uuid.UUID, name string) (*uuid.UUID, string) {
	now := time.Now()
	key := guestKey{hostID: hostID, name: name}
	if e, ok := s.guests.get(key, now); ok {
		return e.id, e.os
	}

	// 查库全程在锁外执行，避免慢查询阻塞其他上报流
	e := guestEntry{at: now}
	if host, err := s.DB.Asset.Get(ctx, hostID); err == nil && host.RetiredAt == nil && hasHostedLXC(host.Containers, name) {
		if a, err := s.DB.Asset.Query().Where(asset.HostnameEQ(name), asset.RetiredAtIsNil()).Only(ctx); err == nil && sameGroup(host.GroupID, a.GroupID) {
			e.id = &a.ID
			if a.Os != nil {
				e.os = *a.Os
			}
		}
	}
	s.guests.put(key, e, time.Now())
	return e.id, e.os
}

// attribute 事件该挂在哪台资产上：LXC 里的归到那台 LXC，raw 里补上观测它的宿主机
func (st *agentStream) attribute(raw json.RawMessage, rawMap map[string]any) (*uuid.UUID, string, json.RawMessage) {
	name := lxcGuest(rawMap)
	if name == "" || st.assetID == nil {
		return st.assetID, st.assetOS, raw
	}
	id, os := st.s.guestAsset(st.ctx, *st.assetID, name)
	if id == nil || *id == *st.assetID {
		return st.assetID, st.assetOS, raw
	}
	// 原样保留事件正文，只在对象开头插一个字段：经 map 重新编码会把大整数变成浮点数
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) < 2 || trimmed[0] != '{' {
		return st.assetID, st.assetOS, raw
	}
	sep := ","
	if rest := bytes.TrimLeft(trimmed[1:], " \t\r\n"); len(rest) > 0 && rest[0] == '}' {
		sep = ""
	}
	out := append([]byte(`{"observed_by":{"asset_id":"`+st.assetID.String()+`"}`+sep), trimmed[1:]...)
	return id, os, out
}
