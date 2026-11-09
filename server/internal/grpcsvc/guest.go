package grpcsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/asset"
)

// LXC 里的进程由宿主机 agent 按 cgroup 采到（容器里自己的 agent 常常加载不了 eBPF，只能轮询），
// 事件却挂在宿主机名下：研判看到的是「pve1 上的容器」，处置等级、关联都错位。
// 纳管资产里有一台主机名与这个 LXC 完全一致、没下线的，事件就归到它，原宿主机记在 observed_by 里。
// 只认 LXC：Docker 容器不是资产，QEMU 进程本来就属于宿主机

const guestTTL = time.Minute

type guestEntry struct {
	id *uuid.UUID
	os string
	at time.Time
}

type guestCache struct {
	mu sync.Mutex
	m  map[string]guestEntry
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

// guestAsset LXC 名字对应的资产，查不到返回 nil；结果缓存一分钟
func (s *Server) guestAsset(ctx context.Context, name string) (*uuid.UUID, string) {
	s.guests.mu.Lock()
	defer s.guests.mu.Unlock()
	if e, ok := s.guests.m[name]; ok && time.Since(e.at) < guestTTL {
		return e.id, e.os
	}
	e := guestEntry{at: time.Now()}
	if a, err := s.DB.Asset.Query().Where(asset.HostnameEQ(name), asset.RetiredAtIsNil()).Only(ctx); err == nil {
		e.id = &a.ID
		if a.Os != nil {
			e.os = *a.Os
		}
	}
	if s.guests.m == nil {
		s.guests.m = map[string]guestEntry{}
	}
	s.guests.m[name] = e
	return e.id, e.os
}

// attribute 事件该挂在哪台资产上：LXC 里的归到那台 LXC，raw 里补上观测它的宿主机
func (st *agentStream) attribute(raw json.RawMessage, rawMap map[string]any) (*uuid.UUID, string, json.RawMessage) {
	name := lxcGuest(rawMap)
	if name == "" || st.assetID == nil {
		return st.assetID, st.assetOS, raw
	}
	id, os := st.s.guestAsset(st.ctx, name)
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
