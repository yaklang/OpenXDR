package ingest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeArchive 是 ArchiveDedup 的假实现：可编排边界、按 ID 的结论与错误，并数调用次数。
// 次数是本任务最关键的断言——「近期事件一次 Archived 都不发」靠它证明。
type fakeArchive struct {
	mu   sync.Mutex
	last time.Time
	ok   bool

	boundaryErr error
	archived    map[uuid.UUID]bool
	archivedErr error

	boundaryCalls int
	archivedCalls int
}

func (f *fakeArchive) Archived(_ context.Context, id uuid.UUID) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.archivedCalls++
	if f.archivedErr != nil {
		return false, f.archivedErr
	}
	return f.archived[id], nil
}

func (f *fakeArchive) ArchiveBoundary(ctx context.Context) (time.Time, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.boundaryCalls++
	if err := ctx.Err(); err != nil {
		return time.Time{}, false, err
	}
	if f.boundaryErr != nil {
		return time.Time{}, false, f.boundaryErr
	}
	return f.last, f.ok, nil
}

func (f *fakeArchive) counts() (boundary, archived int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.boundaryCalls, f.archivedCalls
}

// fakeMetrics 实现 Metrics，记下 fail-open 的阶段计数与最近一次 Processed 的结论。
type fakeMetrics struct {
	mu        sync.Mutex
	failOpen  map[string]int
	processed []processedCall
}

// processedCall 是一次 Process 结束时的指标：duplicate 为 true 表示 store 判为重复（stored=false）。
type processedCall struct {
	source    string
	duplicate bool
	alerts    int
}

func (m *fakeMetrics) Processed(source string, duplicate bool, alerts int, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.processed = append(m.processed, processedCall{source: source, duplicate: duplicate, alerts: alerts})
}

func (m *fakeMetrics) Failed(string) {}
func (m *fakeMetrics) ArchiveFailOpen(stage string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failOpen == nil {
		m.failOpen = map[string]int{}
	}
	m.failOpen[stage]++
}

func (m *fakeMetrics) count(stage string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.failOpen[stage]
}

func (m *fakeMetrics) lastProcessed() (processedCall, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.processed) == 0 {
		return processedCall{}, false
	}
	return m.processed[len(m.processed)-1], true
}

func oldEnvelope(boundary time.Time) Envelope {
	return Envelope{
		Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: "asset-a",
		Timestamp: boundary.Add(-time.Hour), ClassUID: 1007, Source: "agent",
	}
}

// 时间闸门：事件时间晚于归档边界时只在缓存里看一眼边界，Archived 一次都不发。
func TestArchivedBeforeSkipsRecentEvents(t *testing.T) {
	boundary := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	fake := &fakeArchive{last: boundary, ok: true, archived: map[uuid.UUID]bool{}}
	p := &Processor{Archive: fake}
	recent := oldEnvelope(boundary)
	recent.Timestamp = boundary.Add(time.Minute)

	if p.archivedBefore(context.Background(), recent) {
		t.Fatal("近期事件不可能在冷块里，闸门必须直接放行")
	}
	if boundaryCalls, archivedCalls := fake.counts(); archivedCalls != 0 || boundaryCalls != 1 {
		t.Fatalf("近期事件只该查一次边界、不该发 Archived，实际 boundary=%d archived=%d", boundaryCalls, archivedCalls)
	}

	// 边界本身（<=）在闸门内：这是「归档里最晚的那条」的判定，差一纳秒都不能算近期。
	edge := oldEnvelope(boundary)
	edge.Timestamp = boundary
	fake.archived[edge.ID] = true
	if !p.archivedBefore(context.Background(), edge) {
		t.Fatal("时间恰好等于归档边界的事件仍可能被归档，应当查冷层")
	}
	if _, archivedCalls := fake.counts(); archivedCalls != 1 {
		t.Fatalf("边界上的事件应发一次 Archived，实际 %d", archivedCalls)
	}
}

// 归档为空（ok=false）时闸门直接放行，不发 Archived。
func TestArchivedBeforeEmptyArchive(t *testing.T) {
	fake := &fakeArchive{ok: false}
	p := &Processor{Archive: fake, Metrics: &fakeMetrics{}}
	if p.archivedBefore(context.Background(), oldEnvelope(time.Now())) {
		t.Fatal("空归档不可能有这条事件")
	}
	if _, archivedCalls := fake.counts(); archivedCalls != 0 {
		t.Fatalf("空归档不该发 Archived，实际 %d", archivedCalls)
	}
}

// 归档命中的旧事件返回 true（调用方据此当成重复：不入库、不检测）。
func TestArchivedBeforeFindsArchivedEvent(t *testing.T) {
	boundary := time.Now().Add(-24 * time.Hour).UTC()
	e := oldEnvelope(boundary)
	fake := &fakeArchive{last: boundary, ok: true, archived: map[uuid.UUID]bool{e.ID: true}}
	p := &Processor{Archive: fake}
	if !p.archivedBefore(context.Background(), e) {
		t.Fatal("冷层有这条事件时必须判为已归档")
	}
}

// 归档里没有的旧事件：查过冷层、结论是「没有」，照常入库（由调用方继续）。
func TestArchivedBeforeUnknownOldEvent(t *testing.T) {
	boundary := time.Now().Add(-24 * time.Hour).UTC()
	e := oldEnvelope(boundary)
	fake := &fakeArchive{last: boundary, ok: true, archived: map[uuid.UUID]bool{}}
	p := &Processor{Archive: fake}
	if p.archivedBefore(context.Background(), e) {
		t.Fatal("冷层没有这条事件时不能判为已归档")
	}
	if _, archivedCalls := fake.counts(); archivedCalls != 1 {
		t.Fatalf("旧事件应查一次冷层，实际 %d", archivedCalls)
	}
}

// fail-open：Archived 报错（块损坏、ErrChunkBudget、库不可用）时按未归档继续，计数加一。
func TestArchivedBeforeLookupErrorFailsOpen(t *testing.T) {
	boundary := time.Now().Add(-24 * time.Hour).UTC()
	e := oldEnvelope(boundary)
	fake := &fakeArchive{last: boundary, ok: true, archivedErr: errors.New("解码冷块 6f1d（seq 3）: 校验和不符")}
	metrics := &fakeMetrics{}
	p := &Processor{Archive: fake, Metrics: metrics}

	if p.archivedBefore(context.Background(), e) {
		t.Fatal("拿不准时不能判为已归档（那样会永久丢事件）")
	}
	if got := metrics.count("lookup"); got != 1 {
		t.Fatalf("fail-open 应计数 1 次，实际 %d", got)
	}
	// 计数不随日志限流：每条 fail-open 的事件都要算进去。
	if p.archivedBefore(context.Background(), e); metrics.count("lookup") != 2 {
		t.Fatalf("第二次 fail-open 应继续计数，实际 %d", metrics.count("lookup"))
	}
}

// 边界查询失败同样 fail-open，且失败状态被缓存，不会每条事件都去查库。
func TestArchivedBeforeBoundaryErrorFailsOpenOncePerTTL(t *testing.T) {
	e := oldEnvelope(time.Now())
	fake := &fakeArchive{ok: true, boundaryErr: errors.New("dial tcp 127.0.0.1:5432: connect: connection refused")}
	metrics := &fakeMetrics{}
	clock := &fakeClock{now: time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC)}
	archive := NewCachedArchive(fake)
	archive.Now = clock.Now
	p := &Processor{Archive: archive, Metrics: metrics}

	for i := 0; i < 5; i++ {
		if p.archivedBefore(context.Background(), e) {
			t.Fatal("边界读不到时不能判为已归档")
		}
	}
	if boundaryCalls, archivedCalls := fake.counts(); boundaryCalls != 1 || archivedCalls != 0 {
		t.Fatalf("60 秒内只该查一次边界、不发 Archived，实际 boundary=%d archived=%d", boundaryCalls, archivedCalls)
	}
	if got := metrics.count("boundary"); got != 5 {
		t.Fatalf("每次 fail-open 都要计数，实际 %d", got)
	}
	clock.advance(DefaultArchiveBoundaryTTL + time.Second)
	p.archivedBefore(context.Background(), e)
	if boundaryCalls, _ := fake.counts(); boundaryCalls != 2 {
		t.Fatalf("缓存过期后应重新查边界，实际 %d 次", boundaryCalls)
	}
}

// Archive=nil（EVENT_ARCHIVE_DEDUP 未开启）时完全不查、不计数，行为与改动前一致。
func TestArchivedBeforeNilArchive(t *testing.T) {
	metrics := &fakeMetrics{}
	p := &Processor{Metrics: metrics}
	if p.archivedBefore(context.Background(), oldEnvelope(time.Now())) {
		t.Fatal("没有接归档时不该判重")
	}
	if len(metrics.failOpen) != 0 {
		t.Fatalf("没有接归档时不该计数：%v", metrics.failOpen)
	}
}

// 边界缓存：TTL 内多次调用只查一次库，过期后重查；缓存的是结果本身（含 ok=false）。
func TestCachedArchiveBoundaryTTL(t *testing.T) {
	boundary := time.Date(2026, 9, 10, 3, 4, 5, 0, time.UTC)
	fake := &fakeArchive{last: boundary, ok: true}
	clock := &fakeClock{now: time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC)}
	cached := NewCachedArchive(fake)
	cached.Now = clock.Now

	for i := 0; i < 60; i++ {
		got, ok, err := cached.ArchiveBoundary(context.Background())
		if err != nil || !ok || !got.Equal(boundary) {
			t.Fatalf("第 %d 次读边界: %v %v %v", i, got, ok, err)
		}
		clock.advance(time.Second)
	}
	if boundaryCalls, _ := fake.counts(); boundaryCalls != 1 {
		t.Fatalf("60 秒内的 60 次调用只该查一次库，实际 %d 次", boundaryCalls)
	}

	// 60 秒过期（上面停在 59 秒处）：下一次调用重查，新边界立即生效。
	clock.advance(2 * time.Second)
	fake.mu.Lock()
	fake.last = boundary.Add(24 * time.Hour)
	fake.mu.Unlock()
	if _, _, err := cached.ArchiveBoundary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if boundaryCalls, _ := fake.counts(); boundaryCalls != 2 {
		t.Fatalf("缓存过期后应重查一次，实际 %d 次", boundaryCalls)
	}
}

// 调用方自己的 ctx 结束（取消/超时）不是冷层故障，不能写进缓存，否则 60 秒内判重全失效。
func TestCachedArchiveDoesNotCacheCallerCancellation(t *testing.T) {
	fake := &fakeArchive{ok: false}
	cached := NewCachedArchive(fake)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := cached.ArchiveBoundary(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("应把取消原样返回，实际 %v", err)
	}
	if _, _, err := cached.ArchiveBoundary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if boundaryCalls, _ := fake.counts(); boundaryCalls != 2 {
		t.Fatalf("取消不该写缓存，下一次应重新查库，实际 %d 次", boundaryCalls)
	}
}

// 日志限流：同一原因每分钟一条，不同原因各自计；键的数量有上限。
func TestReasonLimiter(t *testing.T) {
	now := time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC)
	limiter := &reasonLimiter{seen: map[string]time.Time{}, every: time.Minute}
	if !limiter.allow("lookup|块损坏", now) {
		t.Fatal("第一次应放行")
	}
	if limiter.allow("lookup|块损坏", now.Add(59*time.Second)) {
		t.Fatal("同一原因在一分钟内应被限流")
	}
	if !limiter.allow("boundary|连接失败", now.Add(time.Second)) {
		t.Fatal("不同原因应各自放行")
	}
	if !limiter.allow("lookup|块损坏", now.Add(time.Minute)) {
		t.Fatal("满一分钟应再次放行")
	}
	for i := 0; i < archiveWarnReasons*2; i++ {
		limiter.allow("lookup|块 "+string(rune('a'+i%26))+string(rune('a'+i/26)), now)
	}
	if len(limiter.seen) > archiveWarnReasons {
		t.Fatalf("限流器的键数应有上限，实际 %d", len(limiter.seen))
	}
}

// fakeClock 是可推进的假时钟。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
