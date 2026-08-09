// Package suppress 误报抑制：把分析师的判断反馈回检测链路。
//
// 三条接入路径（agent / sensor / syslog）在建告警前都要问一次这里。
// 匹配走内存索引，不为每条事件查库；命中计数攒批回写，界面上能看到
// 一条抑制规则到底压掉了多少东西——抑制绝不能是静默的。
package suppress

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

type entry struct {
	id      uuid.UUID
	assetID *uuid.UUID // nil = 对所有资产生效
	expires *time.Time
}

type Store struct {
	db       *ent.Client
	reload   time.Duration
	mu       sync.RWMutex
	byRule   map[string][]entry
	counters map[uuid.UUID]*counter
}

type counter struct {
	hits int
	last time.Time
}

func New(db *ent.Client, reload time.Duration) *Store {
	return &Store{
		db:       db,
		reload:   reload,
		byRule:   map[string][]entry{},
		counters: map[uuid.UUID]*counter{},
	}
}

// Run 周期性重载抑制规则并回写命中计数。
func (s *Store) Run(ctx context.Context) {
	s.Reload(ctx)
	ticker := time.NewTicker(s.reload)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// ctx 已取消，回写要用不带取消的副本，否则关停时丢计数
			s.flush(context.WithoutCancel(ctx))
			return
		case <-ticker.C:
			s.flush(ctx)
			s.Reload(ctx)
		}
	}
}

// Reload 从库里重建索引。新建或撤销抑制规则后立即生效不必等下个周期。
func (s *Store) Reload(ctx context.Context) {
	rows, err := s.db.Suppression.Query().All(ctx)
	if err != nil {
		slog.Error("加载抑制规则失败", "err", err)
		return
	}
	index := make(map[string][]entry, len(rows))
	for _, r := range rows {
		index[r.RuleID] = append(index[r.RuleID], entry{
			id:      r.ID,
			assetID: r.AssetID,
			expires: r.ExpiresAt,
		})
	}
	s.mu.Lock()
	s.byRule = index
	s.mu.Unlock()
}

// Suppressed 判断某条规则在某资产上是否被抑制。命中时累加计数。
func (s *Store) Suppressed(ruleID string, assetID *uuid.UUID, now time.Time) bool {
	s.mu.RLock()
	entries := s.byRule[ruleID]
	s.mu.RUnlock()
	if id := matchRule(entries, assetID, now); id != nil {
		s.hit(*id, now)
		return true
	}
	return false
}

// matchRule 返回 entries 里第一条对给定资产/时间有效的抑制规则 id；
// 过期或资产不匹配的条目跳过，全部不成立则返回 nil。
func matchRule(entries []entry, assetID *uuid.UUID, now time.Time) *uuid.UUID {
	for i := range entries {
		e := &entries[i]
		if e.expires != nil && now.After(*e.expires) {
			continue
		}
		// 抑制规则限定了资产时，只对该资产生效
		if e.assetID != nil && (assetID == nil || *e.assetID != *assetID) {
			continue
		}
		return &e.id
	}
	return nil
}

func (s *Store) hit(id uuid.UUID, now time.Time) {
	s.mu.Lock()
	c, ok := s.counters[id]
	if !ok {
		c = &counter{}
		s.counters[id] = c
	}
	c.hits++
	c.last = now
	s.mu.Unlock()
}

func (s *Store) flush(ctx context.Context) {
	s.mu.Lock()
	pending := s.counters
	s.counters = map[uuid.UUID]*counter{}
	s.mu.Unlock()

	for id, c := range pending {
		if c.hits == 0 {
			continue
		}
		if err := s.db.Suppression.UpdateOneID(id).
			AddMatchedCount(c.hits).
			SetLastMatchedAt(c.last).
			Exec(ctx); err != nil {
			slog.Warn("回写抑制命中数失败", "suppression", id, "err", err)
		}
	}
}
