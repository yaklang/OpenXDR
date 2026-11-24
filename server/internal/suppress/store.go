// Package suppress 误报抑制：把分析师判断与内置已知良性链统一收进检测前闸门。
//
// 三条接入路径（agent / sensor / syslog）与 UEBA 在建告警前都要问一次这里。
// 匹配走内存索引，不为普通事件查库（仅命中检测规则且生效抑制含多跳 ancestor.* 条件时才按需回溯一次进程血缘）；
// 命中计数攒批回写，界面上能看到每条抑制规则到底压掉了多少东西——抑制绝不能是静默的。
package suppress

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/suppression"
	"openxdr/server/internal/sigma"
)

type entry struct {
	id       uuid.UUID
	assetID  *uuid.UUID // nil = 对所有资产生效
	expires  *time.Time
	builtin  bool
	wildcard bool
	compiled compiledSet
}

type Store struct {
	db         *ent.Client
	reload     time.Duration
	mu         sync.RWMutex
	rules      sigma.Catalog
	ruleByID   map[string]*sigma.Rule
	byRule     map[string][]entry
	wildcards  []entry
	hasLineage bool
	counters   map[uuid.UUID]*counter
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

// SetRules 注入规则目录视图，供内置良性链在加载与匹配时校验级别与高危类别闸门
func (s *Store) SetRules(rules sigma.Catalog) {
	s.mu.Lock()
	s.rules = rules
	s.ruleByID = snapshotRules(rules)
	s.mu.Unlock()
}

func snapshotRules(rules sigma.Catalog) map[string]*sigma.Rule {
	if rules == nil {
		return nil
	}
	list := rules.Rules()
	m := make(map[string]*sigma.Rule, len(list))
	for _, r := range list {
		m[r.ID] = r
	}
	return m
}

// NeedsLineage 当前是否有生效的抑制规则引用了多跳祖先条件（ancestor.*）
func (s *Store) NeedsLineage() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hasLineage
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
			s.Flush(context.WithoutCancel(ctx))
			return
		case <-ticker.C:
			s.Flush(ctx)
			s.Reload(ctx)
		}
	}
}

// Reload 从库里重建索引。新建、启停或撤销抑制规则后立即生效不必等下个周期。
func (s *Store) Reload(ctx context.Context) {
	// 只有生效的进索引：disabled（管理员停用）、proposed（待批准）、rejected（被拒）一律不生效
	rows, err := s.db.Suppression.Query().Where(suppression.StatusEQ("active")).All(ctx)
	if err != nil {
		slog.Error("加载抑制规则失败", "err", err)
		return
	}

	s.mu.RLock()
	cat := s.rules
	s.mu.RUnlock()
	ruleMap := snapshotRules(cat)

	index := make(map[string][]entry, len(rows))
	var wildcards []entry
	hasLineage := false
	for _, r := range rows {
		comp := compileConditions(r.Conditions)
		if comp.ancestor {
			hasLineage = true
		}
		isBuiltin := r.CreatedBy == CreatedByBuiltin
		e := entry{
			id:       r.ID,
			assetID:  r.AssetID,
			expires:  r.ExpiresAt,
			builtin:  isBuiltin,
			wildcard: r.RuleID == WildcardRule,
			compiled: comp,
		}
		if e.wildcard {
			// 通配规则仅允许仓库内置良性链使用，且必须有严密条件约束
			if isBuiltin && len(r.Conditions) >= 2 {
				wildcards = append(wildcards, e)
			}
			continue
		}
		for _, rid := range SplitRuleIDs(r.RuleID) {
			index[rid] = append(index[rid], e)
		}
	}
	s.mu.Lock()
	s.ruleByID = ruleMap
	s.byRule = index
	s.wildcards = wildcards
	s.hasLineage = hasLineage
	s.mu.Unlock()
}

// Suppressed 判断某条规则在某资产上的这次命中是否被抑制（仅用事件自身与内嵌父进程）。命中时累加计数。
func (s *Store) Suppressed(ruleID string, assetID *uuid.UUID, raw map[string]any, now time.Time) bool {
	return s.SuppressedWithLineage(ruleID, assetID, raw, nil, now)
}

// SuppressedWithLineage 带多跳进程血缘判断命中是否被抑制；命中时累加计数。
func (s *Store) SuppressedWithLineage(ruleID string, assetID *uuid.UUID, raw map[string]any, lineage []map[string]any, now time.Time) bool {
	if id := s.CoveringWithLineage(ruleID, assetID, raw, lineage, now); id != nil {
		s.hit(*id, now)
		return true
	}
	return false
}

// Covering 与 Suppressed 同一口径，只查不计数：回头核对历史命中用，不算新压掉的次数
func (s *Store) Covering(ruleID string, assetID *uuid.UUID, raw map[string]any, now time.Time) *uuid.UUID {
	return s.CoveringWithLineage(ruleID, assetID, raw, nil, now)
}

// CoveringWithLineage 带多跳进程血缘核对抑制覆盖，只查不计数
func (s *Store) CoveringWithLineage(ruleID string, assetID *uuid.UUID, raw map[string]any, lineage []map[string]any, now time.Time) *uuid.UUID {
	s.mu.RLock()
	entries := s.byRule[ruleID]
	wildcards := s.wildcards
	ruleMap := s.ruleByID
	s.mu.RUnlock()

	if id := matchRule(entries, ruleID, ruleMap, true, assetID, raw, lineage, now); id != nil {
		return id
	}
	return matchRule(wildcards, ruleID, ruleMap, false, assetID, raw, lineage, now)
}

// matchRule 返回 entries 里第一条对给定资产/时间/血缘有效的抑制规则 id；
// 内置良性链额外受 BuiltinAllowedRule 低危与高危类别硬闸门约束。
func matchRule(entries []entry, ruleID string, ruleMap map[string]*sigma.Rule, explicit bool, assetID *uuid.UUID, raw map[string]any, lineage []map[string]any, now time.Time) *uuid.UUID {
	checkedGate := false
	gateAllowed := false
	for i := range entries {
		e := &entries[i]
		if e.expires != nil && now.After(*e.expires) {
			continue
		}
		if e.assetID != nil && (assetID == nil || *e.assetID != *assetID) {
			continue
		}
		if e.builtin {
			if !checkedGate {
				checkedGate = true
				gateAllowed = builtinAllowedInMap(ruleID, ruleMap, explicit)
			}
			if !gateAllowed {
				continue
			}
		}
		if !e.compiled.matches(raw, lineage) {
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
	if now.After(c.last) {
		c.last = now
	}
	s.mu.Unlock()
}

// Flush 立即把内存累计的抑制命中计数回写数据库
func (s *Store) Flush(ctx context.Context) {
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
