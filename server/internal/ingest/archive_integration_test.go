//go:build integration

package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/eventarchive"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/sigma"
)

// 冷归档重传判重（阶段 C 接线）的端到端集成测试。
//
// 夹具是一条「没有告警」的老事件：它不会被 alerts 钉住，所以能真正被 shadow + swap 移出热表；
// 规则在切换之后才上线——这正是重放会「重新检测」的现实场景（规则热更新、补丁后收紧）。
// 于是：
//   - 接了判重：重放不入库、不检测、不产告警；
//   - 没接判重：同一条重放重新入库，并真的产出一条新告警（反例，证明接线在起作用）。

// archiveDedupAdapter 与 main.go 里的适配器同构：把冷归档的两个只读函数接到 ingest 的最小接口上，
// 另外数调用次数——「近期事件一次 Archived 都不发」这条性能断言靠它证明。
type archiveDedupAdapter struct {
	db          *sql.DB
	archivedErr error

	mu            sync.Mutex
	boundaryCalls int
	archivedCalls int
}

func (a *archiveDedupAdapter) Archived(ctx context.Context, id uuid.UUID) (bool, error) {
	a.mu.Lock()
	a.archivedCalls++
	err := a.archivedErr
	a.mu.Unlock()
	if err != nil {
		return false, err
	}
	return eventarchive.Exists(ctx, a.db, id)
}

func (a *archiveDedupAdapter) ArchiveBoundary(ctx context.Context) (time.Time, bool, error) {
	a.mu.Lock()
	a.boundaryCalls++
	a.mu.Unlock()
	return eventarchive.Boundary(ctx, a.db)
}

func (a *archiveDedupAdapter) counts() (boundary, archived int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.boundaryCalls, a.archivedCalls
}

// swappedFixture 是一天已经切走的现场：events 里没有这条事件，冷块里有，且没有任何告警。
type swappedFixture struct {
	p      *Processor
	client *ent.Client
	db     *sql.DB
	e      Envelope
	runID  uuid.UUID
	day    time.Time
}

func newSwappedFixture(t *testing.T) swappedFixture {
	t.Helper()
	ctx := context.Background()
	p, client, db := testProcessor(t)
	t.Cleanup(func() {
		client.Close()
		db.Close()
	})
	if err := eventarchive.EnsureSchema(ctx, db); err != nil {
		t.Fatalf("建冷归档表: %v", err)
	}
	for _, table := range []string{"event_archive_chunks", "event_archive_runs"} {
		if _, err := db.ExecContext(ctx, `DELETE FROM `+table); err != nil {
			t.Fatalf("清空 %s: %v", table, err)
		}
	}
	// 空归档的边界：ok=false，闸门据此完全不查冷层。
	if last, ok, err := eventarchive.Boundary(ctx, db); err != nil || ok || !last.IsZero() {
		t.Fatalf("空归档的边界应返回 ok=false：%v %v %v", last, ok, err)
	}

	// testdb 只预建今天起的分区；这里要切的是 3 天前（P4 起 min-age/消费进度闸门拒绝更近的日子，
	// 该文件验证的是判重接线而不是闸门本身），先补出独立日分区（Swap 拒绝默认分区里的行）。
	day := archiveDayStart().AddDate(0, 0, -3)
	// janitor 的集成测试会留下跨整月的归档分区（其 defer db.Close() 先于 t.Cleanup 执行，
	// cleanup 里的 DROP 静默失败——该测试自身的问题），挡住这里要建的历史日分区；拆掉再建。
	if _, err := db.ExecContext(ctx, `DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT c.relname FROM pg_class c JOIN pg_inherits i ON c.oid=i.inhrelid
  WHERE i.inhparent='events'::regclass AND c.relname LIKE 'events_a%' LOOP
  EXECUTE format('DROP TABLE IF EXISTS %I', r.relname);
 END LOOP; END $$`); err != nil {
		t.Fatalf("清理残留月归档分区: %v", err)
	}
	if _, err := eventpart.EnsureDays(ctx, db, eventpart.Parent, day, 0); err != nil {
		t.Fatalf("建日分区: %v", err)
	}
	asset := client.Asset.Create().SetHostname("archive-replay").SetOs("linux").SaveX(ctx)
	// P4 闸门的夹具适配（经上游裁决，仅本夹具）：关掉运营下限（temporal 边界仍生效，
	// 3 天前的日结束已足够老），并给 ueba 播种一条越过待切日的基线——run 口径是
	// 1007/agent，ueba 是唯一口径相交的消费者，空表会被按 unknown 拒绝。
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	if _, err := db.ExecContext(ctx, `INSERT INTO process_baselines (id, asset_id, exe_path, first_seen)
 VALUES ($1, $2, '/usr/bin/sshd', $3)`, uuid.Must(uuid.NewV7()), asset.ID, day.AddDate(0, 0, 2)); err != nil {
		t.Fatalf("播种 ueba 进度: %v", err)
	}
	// 这一天的日分区落在 janitor 集成测试的退役窗口里（它按个数断言退役的分区），
	// 用完即拆，不跨包泄漏。
	t.Cleanup(func() {
		_, _ = db.Exec(`DROP TABLE IF EXISTS ` + eventpart.DailyName(day))
	})
	e := Envelope{
		Version: EnvelopeVersion, ID: StableID(t.Name(), "replay"), PartitionKey: asset.ID.String(),
		Timestamp: day.Add(5 * time.Minute), ClassUID: 1007, Source: "agent", AssetOS: "linux",
		AssetID: &asset.ID, Raw: json.RawMessage(`{"process":{"cmd_line":"archive-dedup-marker"}}`),
	}
	// 受理时规则库是空的：事件落库但没有告警，于是能进冷块、能被 swap 移出热表。
	if err := p.Process(ctx, e); err != nil {
		t.Fatalf("处理原始事件: %v", err)
	}
	if !eventRowExists(t, ctx, db, e.ID) {
		t.Fatal("原始事件应已入库")
	}
	if n := alertRows(t, ctx, client); n != 0 {
		t.Fatalf("夹具事件不该产告警（否则会被钉在热表里），实际 %d 条", n)
	}

	runID, err := eventarchive.Shadow(ctx, db, eventarchive.Options{
		From: day, To: day, Classes: []int{1007}, Sources: []string{"agent"}, Confirm: true,
	})
	if err != nil {
		t.Fatalf("影子归档: %v", err)
	}
	if last, ok, err := eventarchive.Boundary(ctx, db); err != nil || !ok || !last.Equal(e.Timestamp) {
		t.Fatalf("归档后的边界应是这条事件的 ts：%v %v %v（期望 %v）", last, ok, err, e.Timestamp)
	}
	if err := eventarchive.Verify(ctx, db, runID); err != nil {
		t.Fatalf("对拍: %v", err)
	}
	if _, err := eventarchive.Swap(ctx, db, runID, day); err != nil {
		t.Fatalf("切换: %v", err)
	}
	if eventRowExists(t, ctx, db, e.ID) {
		t.Fatal("切换后这条事件应已移出热表")
	}
	return swappedFixture{p: p, client: client, db: db, e: e, runID: runID, day: day}
}

// addReplayRule 把「切换之后才上线」的规则装进处理器：这条老事件一旦被重新接收就会命中。
func addReplayRule(t *testing.T, p *Processor, e Envelope) {
	t.Helper()
	dir := t.TempDir()
	rule := `title: Archive replay
id: 33333333-3333-4333-8333-333333333333
status: test
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: archive-dedup-marker
  condition: selection
level: high
`
	if err := os.WriteFile(filepath.Join(dir, "rule.yml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	p.Rules = sigma.LoadDir(dir)
	// 规则确实命中这条事件：否则「重放不产告警」可能只是规则没匹配上。
	var raw map[string]any
	if err := json.Unmarshal(e.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	if hits := p.Rules.Evaluate(e.ClassUID, e.AssetOS, raw); len(hits) != 1 {
		t.Fatalf("重放规则应命中这条老事件，实际命中 %d 条", len(hits))
	}
}

func archiveDayStart() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

func eventRowExists(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE id = $1)`, id).Scan(&ok); err != nil {
		t.Fatalf("查事件 %s: %v", id, err)
	}
	return ok
}

func alertRows(t *testing.T, ctx context.Context, client *ent.Client) int {
	t.Helper()
	n, err := client.Alert.Query().Count(ctx)
	if err != nil {
		t.Fatalf("统计告警: %v", err)
	}
	return n
}

// 1. 时间闸门：近期事件连一次 Archived 都不发（边界可以查），并且照常入库、照常检测产告警。
func TestRecentEventSkipsArchiveLookup(t *testing.T) {
	ctx := context.Background()
	f := newSwappedFixture(t)
	addReplayRule(t, f.p, f.e)
	adapter := &archiveDedupAdapter{db: f.db}
	f.p.Archive = NewCachedArchive(adapter)

	recent := f.e
	recent.ID = StableID(t.Name(), "recent")
	recent.Timestamp = time.Now().UTC().Truncate(time.Microsecond)
	if err := f.p.Process(ctx, recent); err != nil {
		t.Fatalf("处理近期事件: %v", err)
	}
	if !eventRowExists(t, ctx, f.db, recent.ID) {
		t.Fatal("近期事件必须正常入库")
	}
	if n := alertRows(t, ctx, f.client); n != 1 {
		t.Fatalf("近期事件应照常检测出一条告警，实际 %d 条", n)
	}
	boundary, archived := adapter.counts()
	t.Logf("近期事件：边界查询 %d 次，Archived 调用 %d 次", boundary, archived)
	if archived != 0 {
		t.Fatalf("近期事件不可能在冷块里，Archived 调用次数必须是 0，实际 %d", archived)
	}
	if boundary != 1 {
		t.Fatalf("边界查询应走缓存、只查一次库，实际 %d 次", boundary)
	}
}

// 2. 端到端关键用例：切走之后用同一个 Envelope（同 ID、同 ts）重放 → 不入库、不产告警。
func TestArchiveDedupBlocksSwappedReplay(t *testing.T) {
	ctx := context.Background()
	f := newSwappedFixture(t)
	addReplayRule(t, f.p, f.e)
	adapter := &archiveDedupAdapter{db: f.db}
	f.p.Archive = NewCachedArchive(adapter)
	metrics := &fakeMetrics{}
	f.p.Metrics = metrics

	for i := 0; i < 3; i++ {
		if err := f.p.Process(ctx, f.e); err != nil {
			t.Fatalf("第 %d 次重放: %v", i+1, err)
		}
	}
	if eventRowExists(t, ctx, f.db, f.e.ID) {
		t.Fatal("切走后重放不该重新入库")
	}
	if n := alertRows(t, ctx, f.client); n != 0 {
		t.Fatalf("切走后重放不该重新检测、重新告警，实际 %d 条告警", n)
	}
	// stored=false 体现在指标上：duplicate=true、alerts=0。
	last, ok := metrics.lastProcessed()
	if !ok || !last.duplicate || last.alerts != 0 {
		t.Fatalf("重放应判为重复（duplicate=true、alerts=0），实际 %+v", last)
	}
	boundary, archived := adapter.counts()
	t.Logf("3 次重放：Archived 调用 %d 次，边界查询 %d 次（60 秒缓存）", archived, boundary)
	if archived != 3 {
		t.Fatalf("每次重放都该查一次冷层，实际 %d 次", archived)
	}
	if boundary != 1 {
		t.Fatalf("三次重放只该查一次边界（60 秒缓存），实际 %d 次", boundary)
	}
}

// 3. 旧事件但冷层没有（不在归档口径内）：闸门放行、Archived 返回 false → 照常入库与检测。
func TestOldEventNotArchivedIsStored(t *testing.T) {
	ctx := context.Background()
	f := newSwappedFixture(t)
	addReplayRule(t, f.p, f.e)
	adapter := &archiveDedupAdapter{db: f.db}
	f.p.Archive = NewCachedArchive(adapter)

	// 时间在边界之内（昨天更早），但这条事件从未入库、也不在任何冷块里。
	old := f.e
	old.ID = StableID(t.Name(), "unarchived")
	old.Timestamp = f.e.Timestamp.Add(-time.Hour)
	if err := f.p.Process(ctx, old); err != nil {
		t.Fatalf("处理旧事件: %v", err)
	}
	if !eventRowExists(t, ctx, f.db, old.ID) {
		t.Fatal("冷层没有的旧事件必须照常入库")
	}
	if n := alertRows(t, ctx, f.client); n != 1 {
		t.Fatalf("冷层没有的旧事件应照常检测出一条告警，实际 %d 条", n)
	}
	if boundary, archived := adapter.counts(); archived != 1 || boundary != 1 {
		t.Fatalf("旧事件应查一次冷层（%d）与一次边界（%d）", archived, boundary)
	}
}

// 4. 对照：同一条重放，但 Processor.Archive=nil → 重新入库，并真的产生新告警。
// 这个反例证明上一条用例的「不产告警」是接线起效，而不是规则没命中。
func TestSwappedReplayWithoutArchiveDedupReenters(t *testing.T) {
	ctx := context.Background()
	f := newSwappedFixture(t)
	addReplayRule(t, f.p, f.e)
	control := *f.p
	control.Archive = nil

	if err := control.Process(ctx, f.e); err != nil {
		t.Fatalf("未接判重的重放: %v", err)
	}
	if !eventRowExists(t, ctx, f.db, f.e.ID) {
		t.Fatal("没接判重时重放会重新入库——这正是接线要解决的")
	}
	if n := alertRows(t, ctx, f.client); n != 1 {
		t.Fatalf("没接判重时重放会产生一条新告警，实际 %d 条", n)
	}
}

// 4. Restore 之后重放：行已在 events，原有主键判重与归档闸门都不重复告警。
func TestReplayAfterRestoreIsStillDuplicate(t *testing.T) {
	ctx := context.Background()
	f := newSwappedFixture(t)
	addReplayRule(t, f.p, f.e)
	restored, err := eventarchive.Restore(ctx, f.db, f.runID, f.day)
	if err != nil {
		t.Fatalf("还原: %v", err)
	}
	if restored != 1 {
		t.Fatalf("还原应插入 1 行，实际 %d", restored)
	}

	// 不接归档时走原有 ON CONFLICT：插入 0 行 → 不检测、不告警。
	plain := *f.p
	plain.Archive = nil
	if err := plain.Process(ctx, f.e); err != nil {
		t.Fatalf("还原后重放（原有判重）: %v", err)
	}
	if n := alertRows(t, ctx, f.client); n != 0 {
		t.Fatalf("原有 ON CONFLICT 判重应挡住重放，实际 %d 条告警", n)
	}

	// 接线后同样不重复：事件仍在冷层，闸门在插入之前就判为已归档。
	f.p.Archive = NewCachedArchive(&archiveDedupAdapter{db: f.db})
	if err := f.p.Process(ctx, f.e); err != nil {
		t.Fatalf("还原后重放（接归档判重）: %v", err)
	}
	if !eventRowExists(t, ctx, f.db, f.e.ID) {
		t.Fatal("还原的行不该被重放删掉")
	}
	if n := alertRows(t, ctx, f.client); n != 0 {
		t.Fatalf("还原后重放不该产告警，实际 %d 条", n)
	}
	var rows int
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE id = $1`, f.e.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("重放不该产生第二行，实际 %d 行", rows)
	}
}

// 5. Archived 报错（块损坏 / ErrChunkBudget / 库不可用）→ fail-open：照常入库、继续检测，计数加一。
func TestArchiveLookupErrorFailsOpen(t *testing.T) {
	ctx := context.Background()
	f := newSwappedFixture(t)
	addReplayRule(t, f.p, f.e)
	metrics := &fakeMetrics{}
	f.p.Metrics = metrics
	f.p.Archive = NewCachedArchive(&archiveDedupAdapter{
		db:          f.db,
		archivedErr: errors.New("解码冷块 0bad（seq 1）: 校验和不符"),
	})

	if err := f.p.Process(ctx, f.e); err != nil {
		t.Fatalf("fail-open 时处理不该失败: %v", err)
	}
	if !eventRowExists(t, ctx, f.db, f.e.ID) {
		t.Fatal("拿不准是否已归档时必须照常入库（把不确定当成已归档会永久丢事件）")
	}
	if n := alertRows(t, ctx, f.client); n != 1 {
		t.Fatalf("fail-open 后仍应继续检测出一条告警，实际 %d 条", n)
	}
	if got := metrics.count("lookup"); got != 1 {
		t.Fatalf("fail-open 应计数 1 次，实际 %d", got)
	}
	t.Logf("Archived 报错后 fail-open(lookup) 计数 = %d，事件照常入库并产告警", metrics.count("lookup"))
}
