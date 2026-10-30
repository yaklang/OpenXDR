package eventarchive

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// 本文件不连数据库：query 只依赖 chunkSource，用内存实现就能覆盖收窄、过滤、去重、
// 排序、截断与预算。SQL 侧的收窄由 query_integration_test.go 对着真实冷块验证。

// fakeSource 是内存里的冷块来源。candidates 只按「预算 + 顺序」返回，不替调用方做
// 时间/类别/来源收窄——那正是 query 自己要保证的事。
type fakeSource struct {
	cands  []chunkMeta
	loads  map[uuid.UUID]Chunk
	loaded []uuid.UUID
}

func (f *fakeSource) candidates(_ context.Context, _ Filter, want int) ([]chunkMeta, bool, error) {
	if len(f.cands) > want {
		return f.cands[:want], true, nil
	}
	return f.cands, false, nil
}

func (f *fakeSource) load(_ context.Context, id uuid.UUID) (Chunk, error) {
	ch, ok := f.loads[id]
	if !ok {
		return Chunk{}, fmt.Errorf("冷块 %s 不存在", id)
	}
	f.loaded = append(f.loaded, id)
	return ch, nil
}

// sourceOf 把块装进 fakeSource。顺序即 candidates 的返回顺序（真实实现按 first_ts 倒序）。
func sourceOf(chunks ...Chunk) *fakeSource {
	src := &fakeSource{loads: map[uuid.UUID]Chunk{}}
	for _, ch := range chunks {
		src.cands = append(src.cands, chunkMeta{ID: ch.ID, Seq: ch.Seq, Day: ch.Day, ClassUID: ch.ClassUID,
			Source: ch.Source, FirstTs: ch.FirstTs, LastTs: ch.LastTs, Count: ch.EventCount})
		src.loads[ch.ID] = ch
	}
	return src
}

// chunkOf 把一组已按 ts 升序、同 (日, 类别, 来源) 的事件封成一块，元数据与真实写入一致。
func chunkOf(t *testing.T, events []Event) Chunk {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("空块不允许")
	}
	block, err := EncodeBlock(events)
	if err != nil {
		t.Fatalf("编码冷块: %v", err)
	}
	last := events[len(events)-1]
	return Chunk{
		ID: uuid.New(), Seq: 1, Day: dayStart(events[0].Ts),
		ClassUID: int(events[0].ClassUID), Source: events[0].Source,
		FirstTs: events[0].Ts, LastTs: last.Ts, EventCount: len(events),
		PayloadLen: int64(len(block.Payload)), Block: block,
	}
}

func testEvent(id uuid.UUID, ts time.Time, class int64, source string, asset *uuid.UUID) Event {
	return Event{ID: id, Ts: ts.UTC(), ClassUID: class, Source: source, AssetID: asset,
		Raw: json.RawMessage(`{"message":"ssh failed"}`)}
}

func idOf(n int) uuid.UUID {
	return uuid.MustParse(fmt.Sprintf("0199d3a0-0000-7000-8000-%012d", n))
}

var base = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func ids(t *testing.T, events []Event) []uuid.UUID {
	t.Helper()
	out := make([]uuid.UUID, len(events))
	for i, e := range events {
		out[i] = e.ID
	}
	return out
}

func assertIDs(t *testing.T, got []Event, want ...uuid.UUID) {
	t.Helper()
	have := ids(t, got)
	if len(have) != len(want) {
		t.Fatalf("返回 %d 条，期望 %d 条：%v vs %v", len(have), len(want), have, want)
	}
	for i := range want {
		if have[i] != want[i] {
			t.Fatalf("第 %d 条是 %s，期望 %s（完整结果 %v）", i, have[i], want[i], have)
		}
	}
}

// 1. 时间窗（左闭右开）、类别、来源、事件 ID 过滤。
func TestQueryFilters(t *testing.T) {
	e1 := testEvent(idOf(1), base, 4001, "agent", nil)
	e2 := testEvent(idOf(2), base.Add(time.Minute), 4001, "agent", nil)
	e3 := testEvent(idOf(3), base.Add(2*time.Minute), 4001, "agent", nil)
	e4 := testEvent(idOf(4), base.Add(30*time.Second), 4003, "sensor", nil)
	e5 := testEvent(idOf(5), base.Add(90*time.Second), 4003, "sensor", nil)
	src := sourceOf(
		chunkOf(t, []Event{e1, e2, e3}),
		chunkOf(t, []Event{e4, e5}),
	)

	cases := []struct {
		name string
		f    Filter
		want []uuid.UUID
	}{
		{"零值返回全部并按 ts 倒序", Filter{}, []uuid.UUID{e3.ID, e5.ID, e2.ID, e4.ID, e1.ID}},
		{"时间窗左闭右开：to 上的事件不含", Filter{From: base.Add(time.Minute), To: base.Add(2 * time.Minute)}, []uuid.UUID{e5.ID, e2.ID}},
		{"只给 from 时到最新", Filter{From: base.Add(2 * time.Minute)}, []uuid.UUID{e3.ID}},
		{"只给 to 时从最早", Filter{To: base.Add(time.Minute)}, []uuid.UUID{e4.ID, e1.ID}},
		{"类别过滤", Filter{Classes: []int{4003}}, []uuid.UUID{e5.ID, e4.ID}},
		{"来源过滤", Filter{Sources: []string{"agent"}}, []uuid.UUID{e3.ID, e2.ID, e1.ID}},
		{"类别与来源同时生效", Filter{Classes: []int{4001}, Sources: []string{"sensor"}}, nil},
		{"按事件 ID 定位", Filter{IDs: []uuid.UUID{e4.ID, e1.ID}}, []uuid.UUID{e4.ID, e1.ID}},
		{"ID 与时间窗叠加", Filter{IDs: []uuid.UUID{e1.ID, e4.ID}, From: base.Add(10 * time.Second)}, []uuid.UUID{e4.ID}},
		{"不存在的事件 ID", Filter{IDs: []uuid.UUID{idOf(99)}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			events, cov, err := query(context.Background(), src, c.f)
			if err != nil {
				t.Fatalf("查询失败: %v", err)
			}
			assertIDs(t, events, c.want...)
			if cov.Matched != len(c.want) || cov.Truncated {
				t.Errorf("覆盖度不符: %+v（命中应为 %d）", cov, len(c.want))
			}
		})
	}
}

// 2. 资产过滤：nil 资产被排除；集合内保留、集合外排除；空集合是「一无所见」而不是「不限」。
func TestQueryAssetFilter(t *testing.T) {
	assetA, assetB, foreign := uuid.New(), uuid.New(), uuid.New()
	eA := testEvent(idOf(1), base, 4001, "agent", &assetA)
	eB := testEvent(idOf(2), base.Add(time.Minute), 4001, "agent", &assetB)
	eNil := testEvent(idOf(3), base.Add(2*time.Minute), 4001, "agent", nil)
	eOut := testEvent(idOf(4), base.Add(3*time.Minute), 4001, "agent", &foreign)
	src := sourceOf(chunkOf(t, []Event{eA, eB, eNil, eOut}))

	cases := []struct {
		name string
		f    Filter
		want []uuid.UUID
	}{
		{"nil 表示不限：无归属事件也返回", Filter{AssetIDs: nil}, []uuid.UUID{eOut.ID, eNil.ID, eB.ID, eA.ID}},
		{"集合内的保留、集合外与无归属都丢弃", Filter{AssetIDs: []uuid.UUID{assetA}}, []uuid.UUID{eA.ID}},
		{"多资产集合", Filter{AssetIDs: []uuid.UUID{assetA, assetB}}, []uuid.UUID{eB.ID, eA.ID}},
		{"空集合一无所见", Filter{AssetIDs: []uuid.UUID{}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			events, cov, err := query(context.Background(), src, c.f)
			if err != nil {
				t.Fatalf("查询失败: %v", err)
			}
			assertIDs(t, events, c.want...)
			if cov.Matched != len(c.want) {
				t.Errorf("命中 %d 条，期望 %d 条", cov.Matched, len(c.want))
			}
			if c.f.AssetIDs != nil && len(c.f.AssetIDs) == 0 && cov.ScannedChunks != 0 {
				t.Errorf("空资产集合不该解压任何块，实际扫了 %d 块", cov.ScannedChunks)
			}
		})
	}
}

// 3. 去重：同一 id + ts 出现在两块里只返回一条，且只算一条命中（冷块按 run 叠加时会重复）。
func TestQueryDeduplicates(t *testing.T) {
	dup := testEvent(idOf(1), base, 4001, "agent", nil)
	other := testEvent(idOf(2), base.Add(time.Minute), 4001, "agent", nil)
	first := chunkOf(t, []Event{dup})
	second := chunkOf(t, []Event{dup, other})
	events, cov, err := query(context.Background(), sourceOf(first, second), Filter{})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	assertIDs(t, events, other.ID, dup.ID)
	if cov.Matched != 2 {
		t.Errorf("命中应去重后计 2 条，实际 %d", cov.Matched)
	}
}

// 4. 排序：(ts, id) 倒序，同一 ts 按 id 倒序。
func TestQueryOrder(t *testing.T) {
	early := testEvent(idOf(1), base, 4001, "agent", nil)
	sameTsLow := testEvent(idOf(2), base.Add(time.Minute), 4001, "agent", nil)
	sameTsHigh := testEvent(idOf(3), base.Add(time.Minute), 4001, "agent", nil)
	late := testEvent(idOf(4), base.Add(2*time.Minute), 4001, "agent", nil)
	// 故意让块的顺序与结果顺序不一致
	events, cov, err := query(context.Background(), sourceOf(
		chunkOf(t, []Event{early, sameTsLow, sameTsHigh, late}),
	), Filter{})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	assertIDs(t, events, late.ID, sameTsHigh.ID, sameTsLow.ID, early.ID)
	if !sortDesc(events) {
		t.Error("结果不是 (ts, id) 倒序")
	}
	if cov.Matched != 4 || cov.Truncated {
		t.Errorf("覆盖度不符: %+v", cov)
	}
}

func sortDesc(events []Event) bool {
	for i := 1; i < len(events); i++ {
		// 后一条必须真的排在前一条之后（ts 更早，或 ts 相同 id 更小）
		if !later(events[i], events[i-1]) {
			return false
		}
	}
	return true
}

// 5. Limit 截断时 Truncated=true；恰好取满但没有被挤掉的命中时不算截断。
func TestQueryLimit(t *testing.T) {
	events := make([]Event, 5)
	for i := range events {
		events[i] = testEvent(idOf(i+1), base.Add(time.Duration(i)*time.Minute), 4001, "agent", nil)
	}
	src := sourceOf(chunkOf(t, events))

	got, cov, err := query(context.Background(), src, Filter{Limit: 2})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	assertIDs(t, got, events[4].ID, events[3].ID)
	if !cov.Truncated || cov.Matched != 5 {
		t.Errorf("截断时应报 Truncated 且命中 5 条: %+v", cov)
	}
	// Limit 截断不是扫描缺口：块都扫完了，只是结果条数到了上限
	if cov.ScanIncomplete {
		t.Errorf("Limit 截断不该报 ScanIncomplete: %+v", cov)
	}

	got, cov, err = query(context.Background(), src, Filter{Limit: 5})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if len(got) != 5 || cov.Truncated || cov.Matched != 5 || cov.ScanIncomplete {
		t.Errorf("恰好取满且没有丢弃时不应报截断: %d 条 %+v", len(got), cov)
	}
}

// 6. 块损坏：整体报错并带上块 id，不返回部分结果。
func TestQueryCorruptChunk(t *testing.T) {
	good := chunkOf(t, []Event{testEvent(idOf(1), base, 4001, "agent", nil)})
	bad := chunkOf(t, []Event{testEvent(idOf(2), base.Add(time.Minute), 4001, "agent", nil)})
	bad.Payload = append([]byte(nil), bad.Block.Payload...)
	bad.Payload[0] ^= 0xff
	bad.Block.Payload = bad.Payload
	events, _, err := query(context.Background(), sourceOf(good, bad), Filter{})
	if err == nil {
		t.Fatal("块损坏必须返回错误")
	}
	if len(events) != 0 {
		t.Fatalf("块损坏时不能返回部分结果，实际 %d 条", len(events))
	}
	if !strings.Contains(err.Error(), bad.ID.String()) {
		t.Errorf("错误里应带块 id %s: %v", bad.ID, err)
	}
}

// 6b. 块头与内容不符（元数据被改过）同样整体报错：否则按 first_ts/last_ts 收窄会漏事件，
// 把「查不到」说成「不存在」。
func TestQueryChunkMetadataMismatch(t *testing.T) {
	ch := chunkOf(t, []Event{testEvent(idOf(1), base, 4001, "agent", nil)})
	ch.LastTs = ch.LastTs.Add(time.Hour) // 块头声明的末条 ts 与块内内容不符
	_, _, err := query(context.Background(), sourceOf(ch), Filter{})
	if err == nil || !strings.Contains(err.Error(), ch.ID.String()) {
		t.Fatalf("块头与内容不符必须报错并带块 id: %v", err)
	}
}

// 7. 预算上限：候选块超过上限时只扫 200 块，并报 Truncated。
func TestQueryChunkBudget(t *testing.T) {
	var chunks []Chunk
	for i := 0; i < maxScannedChunks+50; i++ {
		chunks = append(chunks, chunkOf(t, []Event{testEvent(idOf(i+1), base.Add(time.Duration(i)*time.Minute), 4001, "agent", nil)}))
	}
	events, cov, err := query(context.Background(), sourceOf(chunks...), Filter{})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if cov.ScannedChunks != maxScannedChunks {
		t.Errorf("应只扫 %d 块，实际 %d", maxScannedChunks, cov.ScannedChunks)
	}
	if !cov.Truncated {
		t.Error("有候选块没扫时必须报 Truncated")
	}
	if !cov.ScanIncomplete {
		t.Error("预算耗尽必须报 ScanIncomplete：这是「没扫完」，与 Limit 截断不同")
	}
	if len(events) != maxScannedChunks || cov.Matched != maxScannedChunks {
		t.Errorf("结果与命中都应是 %d 条，实际 %d 条、命中 %d", maxScannedChunks, len(events), cov.Matched)
	}
}

// 块级收窄：窗口之外的块连解压都不该发生（这里它们本身就是坏块，扫到就会报错）。
func TestQuerySkipsChunksOutsideWindow(t *testing.T) {
	latest := testEvent(idOf(1), base, 4001, "agent", nil)
	oldest := testEvent(idOf(2), base.Add(-48*time.Hour), 4001, "agent", nil)
	inside := chunkOf(t, []Event{latest})
	outside := chunkOf(t, []Event{oldest})
	outside.Payload = append([]byte(nil), outside.Block.Payload...)
	outside.Payload[0] ^= 0xff
	outside.Block.Payload = outside.Payload
	src := sourceOf(inside, outside)

	events, cov, err := query(context.Background(), src, Filter{From: base.Add(-time.Hour), To: base.Add(time.Hour)})
	if err != nil {
		t.Fatalf("窗口外的块不该被解压: %v", err)
	}
	assertIDs(t, events, latest.ID)
	if cov.ScannedChunks != 1 || len(src.loaded) != 1 || src.loaded[0] != inside.ID {
		t.Errorf("只应解压窗口内的块: scanned=%d loaded=%v", cov.ScannedChunks, src.loaded)
	}
}

// 候选块按类别与来源也能先筛掉，不是等解压后才靠事件过滤。
func TestAllowsChunk(t *testing.T) {
	ch := chunkMeta{ClassUID: 4001, Source: "agent", FirstTs: base, LastTs: base.Add(time.Minute), Day: dayStart(base)}
	cases := []struct {
		name string
		f    Filter
		want bool
	}{
		{"零值一律允许", Filter{}, true},
		{"窗口覆盖整块", Filter{From: base, To: base.Add(2 * time.Minute)}, true},
		{"窗口右边界正好是块起点：块内没有更早的事件", Filter{From: base.Add(-time.Hour), To: base}, false},
		{"窗口左边界在块末条之后", Filter{From: base.Add(2 * time.Minute)}, false},
		{"窗口左边界等于块末条：含末条", Filter{From: base.Add(time.Minute), To: base.Add(2 * time.Minute)}, true},
		{"类别不符", Filter{Classes: []int{4003}}, false},
		{"来源不符", Filter{Sources: []string{"sensor"}}, false},
	}
	for _, c := range cases {
		if got := c.f.allowsChunk(ch); got != c.want {
			t.Errorf("%s: allowsChunk = %v，期望 %v", c.name, got, c.want)
		}
	}
}
