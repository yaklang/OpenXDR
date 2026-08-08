// Package intel 威胁情报碰撞：事件里的 IP / 域名 / 文件哈希撞上 IOC 库即产生告警。
//
// 与 suppress 同一套模式：内存索引 + 周期 reload，热路径不查库；
// 命中计数攒批回写，界面上看得见每条情报撞上了多少事件。
// 提取不枚举字段路径，而是按键名递归收集——agent / sensor / syslog
// 三路事件结构各异，键名约定（ip、hostname、sha256……）却是统一的。
package intel

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/sigma"
)

// Detections 规则命中与情报命中并成同一序列，三条接入路径共用抑制、去重与建告警逻辑。
func Detections(rules []*sigma.Rule, iocs []Hit) []Hit {
	hits := make([]Hit, 0, len(rules)+len(iocs))
	for _, r := range rules {
		hits = append(hits, Hit{RuleID: r.ID, Severity: r.Severity})
	}
	return append(hits, iocs...)
}

// Hit 一次 IOC 命中。RuleID 形如 intel:ip:1.2.3.4，
// 与规则告警共用去重、抑制、关联链路，无需特殊处理。
type Hit struct {
	RuleID   string
	Severity int16
}

type entry struct {
	id       uuid.UUID
	severity int16
	expires  *time.Time
}

type Store struct {
	db       *ent.Client
	reload   time.Duration
	mu       sync.RWMutex
	byKey    map[string]entry // kind + ":" + value
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
		byKey:    map[string]entry{},
		counters: map[uuid.UUID]*counter{},
	}
}

// Run 周期性重载情报库并回写命中计数。
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

// Reload 从库里重建索引。导入或删除情报后立即生效不必等下个周期。
func (s *Store) Reload(ctx context.Context) {
	rows, err := s.db.Intel.Query().All(ctx)
	if err != nil {
		slog.Error("加载威胁情报失败", "err", err)
		return
	}
	index := make(map[string]entry, len(rows))
	for _, r := range rows {
		index[string(r.Kind)+":"+strings.ToLower(r.Value)] = entry{
			id:       r.ID,
			severity: r.Severity,
			expires:  r.ExpiresAt,
		}
	}
	s.mu.Lock()
	s.byKey = index
	s.mu.Unlock()
}

// Match 把事件体里的候选值与情报库碰撞。同一事件里重复出现的值只算一次命中。
func (s *Store) Match(raw map[string]any, now time.Time) []Hit {
	s.mu.RLock()
	empty := len(s.byKey) == 0
	s.mu.RUnlock()
	if empty {
		return nil
	}

	c := collector{}
	c.walk("", raw)

	var hits []Hit
	seen := map[string]bool{}
	try := func(kind, value string) {
		key := kind + ":" + value
		if seen[key] {
			return
		}
		seen[key] = true
		s.mu.RLock()
		e, ok := s.byKey[key]
		s.mu.RUnlock()
		if !ok || (e.expires != nil && now.After(*e.expires)) {
			return
		}
		s.hit(e.id, now)
		hits = append(hits, Hit{RuleID: "intel:" + key, Severity: e.severity})
	}

	for _, v := range c.ips {
		try("ip", v)
	}
	for _, v := range c.domains {
		// 情报常给根域，事件里是子域：evil.com 要能撞上 a.b.evil.com
		for d := v; d != ""; {
			try("domain", d)
			i := strings.IndexByte(d, '.')
			if i < 0 {
				break
			}
			d = d[i+1:]
		}
	}
	for _, v := range c.hashes {
		try("hash", v)
	}
	return hits
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
		if err := s.db.Intel.UpdateOneID(id).
			AddMatchedCount(c.hits).
			SetLastMatchedAt(c.last).
			Exec(ctx); err != nil {
			slog.Warn("回写情报命中数失败", "intel", id, "err", err)
		}
	}
}

// collector 递归收集事件体里可与情报碰撞的值，按键名分类。
type collector struct {
	ips     []string
	domains []string
	hashes  []string
}

func (c *collector) walk(key string, v any) {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			c.walk(k, child)
		}
	case []any:
		for _, child := range val {
			c.walk(key, child)
		}
	case string:
		if val == "" {
			return
		}
		switch key {
		case "ip":
			c.ips = append(c.ips, val)
		case "hostname", "sni":
			c.domains = append(c.domains, strings.ToLower(strings.TrimSuffix(val, ".")))
		case "sha256", "sha1", "md5", "hashes", "hash", "ja3_hash":
			c.hashes = append(c.hashes, strings.ToLower(val))
		}
	}
}
