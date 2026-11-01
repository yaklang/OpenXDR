package ingest

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// 冷归档重传判重（阶段 C 接线）。
//
// 分区被 `eventarchive swap` 切走之后，这条事件在 events 里已经没有行，
// `INSERT ... ON CONFLICT DO NOTHING` 看不到它：迟到或重传的老事件会被当成新事件重新入库、
// 重新检测、重复告警。本文件给接入路径补上「冷层里有这条事件」的判断。
//
// 两个约束决定了实现形态：
//   - ingest 不 import eventarchive：这里只定义最小接口，适配器在 main.go；
//   - 接入峰值约 3000 条/秒，不能逐条扫 event_archive_chunks 的元数据：归档只覆盖较老的
//     日子，事件时间晚于「归档中最晚的 last_ts」就不可能在冷块里，这个边界缓存 60 秒。

// ArchiveDedup 判断一条事件是否已经不在热表、但存在于冷归档里。
// 只在「事件时间不晚于归档边界」时被调用，实现可以假设这是罕见路径。
type ArchiveDedup interface {
	// Archived 返回 true 表示该事件已归档（不应再入库、不应重新检测）。
	Archived(ctx context.Context, id uuid.UUID) (bool, error)
	// ArchiveBoundary 返回归档中最晚的事件时间；ok=false 表示归档为空或不可用。
	ArchiveBoundary(ctx context.Context) (last time.Time, ok bool, err error)
}

// DefaultArchiveBoundaryTTL 是归档边界的缓存时间。归档按天/按批构建（shadow），
// 边界不需要秒级精度；60 秒是「每条事件都不查库」与「切换后多久按新边界判重」的折中。
const DefaultArchiveBoundaryTTL = 60 * time.Second

// CachedArchive 给 ArchiveBoundary 加 TTL 缓存，Archived 直接转发。
//
// 缓存放 ingest 侧而不是 eventarchive：边界是接入热路径的准入判断（只有这里有 3000 条/秒
// 与「老事件」语义），而 eventarchive 的读函数保持无状态、语义不变——一份会过期的边界
// 不能被冷读、覆盖度统计或证据物化复用，那些调用方需要当下的真实边界。
//
// 查询失败同样缓存到过期：冷层故障时每条事件都去查一次库会放大故障，失败由调用方按
// 「没有归档」fail-open（见 Processor.archivedBefore）。
// 调用方自己的 ctx 结束（取消/超时）不写缓存，那不是冷层故障，下一次调用应重新查。
type CachedArchive struct {
	Source ArchiveDedup
	TTL    time.Duration    // 0 用 DefaultArchiveBoundaryTTL
	Now    func() time.Time // nil 用 time.Now；测试注入假时钟

	mu      sync.Mutex
	last    time.Time
	ok      bool
	err     error
	expires time.Time
	filled  bool
}

// NewCachedArchive 用默认 60 秒 TTL 包装一个归档读取实现。
func NewCachedArchive(src ArchiveDedup) *CachedArchive {
	return &CachedArchive{Source: src, TTL: DefaultArchiveBoundaryTTL}
}

// ArchiveBoundary 命中缓存就直接返回（不碰数据库），未命中或过期才查 Source。
// 不在持锁期间查库：一次慢查询不该把整条接入路径堵住；并发未命中最多多发几次同样的查询。
func (c *CachedArchive) ArchiveBoundary(ctx context.Context) (time.Time, bool, error) {
	c.mu.Lock()
	if c.filled && c.now().Before(c.expires) {
		last, ok, err := c.last, c.ok, c.err
		c.mu.Unlock()
		return last, ok, err
	}
	c.mu.Unlock()

	last, ok, err := c.Source.ArchiveBoundary(ctx)
	if ctx.Err() != nil {
		return last, ok, err
	}
	c.mu.Lock()
	c.last, c.ok, c.err = last, ok, err
	c.expires = c.now().Add(c.ttl())
	c.filled = true
	c.mu.Unlock()
	return last, ok, err
}

// Archived 不做缓存：单条事件在不在冷块里正是接入路径要判定的结果，缓存它会让重传在
// TTL 内继续被当成新事件（或把新事件误判成已归档），两者都比多一次查询代价大。
func (c *CachedArchive) Archived(ctx context.Context, id uuid.UUID) (bool, error) {
	return c.Source.Archived(ctx, id)
}

func (c *CachedArchive) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return DefaultArchiveBoundaryTTL
}

func (c *CachedArchive) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// archivedBefore 判断这条事件是否已经在冷归档里（分区被切走后的重放）。
//
// 时间闸门先跑：归档只覆盖较老的日子，事件时间晚于归档边界就不可能落在冷块里，
// 这时连一次 Archived 都不发。边界本身走 CachedArchive 的 60 秒缓存，逐条查库不可接受。
//
// 失败策略是 fail-open：拿不准（块损坏、索引覆盖不完整、库不可用、边界读不到）就按
// 「不在归档里」继续入库与检测。把「无法确认」当成「已归档」会永久丢掉一条真实事件；
// 重复入库最多产生一条重复告警，能被告警侧去重窗口吸收，而丢事件不可恢复。
// 每次 fail-open 都计数，日志按「同一原因每分钟一条」限流。
func (p *Processor) archivedBefore(ctx context.Context, e Envelope) bool {
	if p.Archive == nil {
		return false
	}
	last, ok, err := p.Archive.ArchiveBoundary(ctx)
	if err != nil {
		p.archiveFailOpen("boundary", e.ID, err)
		return false
	}
	if !ok || e.Timestamp.After(last) {
		return false
	}
	archived, err := p.Archive.Archived(ctx, e.ID)
	if err != nil {
		p.archiveFailOpen("lookup", e.ID, err)
		return false
	}
	return archived
}

// archiveFailOpenMetrics 是可选的指标扩展（与 Metrics 里的 TemporalSkipped 同一模式：
// 不扩大必选接口，别的实现不用改）。
type archiveFailOpenMetrics interface {
	ArchiveFailOpen(stage string)
}

// archiveFailOpen 记一次「拿不准就照常入库」：计数每次都要加（运维要看频率），
// 日志按原因限流（冷层整体故障时每事件一条会把有用的日志淹掉）。
func (p *Processor) archiveFailOpen(stage string, id uuid.UUID, err error) {
	if archiveWarn.allow(stage+"|"+err.Error(), time.Now()) {
		slog.Warn("冷归档判重失败，按未归档继续入库（fail-open）",
			"stage", stage, "event", id, "err", err)
	}
	if m, ok := p.Metrics.(archiveFailOpenMetrics); ok {
		m.ArchiveFailOpen(stage)
	}
}

const (
	// archiveWarnEvery 是同一原因的最短日志间隔。
	archiveWarnEvery = time.Minute
	// archiveWarnReasons 是限流器记住的原因数上限。块损坏时原因里带块 id，会随块数增长，
	// 限流器自己不能成为泄漏点。
	archiveWarnReasons = 32
)

// archiveWarn 是进程级的限流器：每节点每分钟每个原因最多一条。
var archiveWarn = &reasonLimiter{seen: map[string]time.Time{}, every: archiveWarnEvery}

// reasonLimiter 按原因限流日志：同一原因在 every 内只放行第一次。
type reasonLimiter struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	every time.Duration
}

// allow 报告这次是否应当记录 reason。键的数量有上限：满了先清过期项，仍然满就丢掉最旧的
// 一条——代价是最旧那个原因可能提前再记一条，不会无限增长。
func (l *reasonLimiter) allow(reason string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[string]time.Time{}
	}
	if last, ok := l.seen[reason]; ok && now.Sub(last) < l.every {
		return false
	}
	if _, ok := l.seen[reason]; !ok && len(l.seen) >= archiveWarnReasons {
		l.evict(now)
	}
	l.seen[reason] = now
	return true
}

func (l *reasonLimiter) evict(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for key, at := range l.seen {
		if now.Sub(at) >= l.every {
			delete(l.seen, key)
			continue
		}
		if oldestKey == "" || at.Before(oldest) {
			oldestKey, oldest = key, at
		}
	}
	if len(l.seen) >= archiveWarnReasons && oldestKey != "" {
		delete(l.seen, oldestKey)
	}
}
