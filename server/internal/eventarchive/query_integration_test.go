//go:build integration

package eventarchive_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/eventarchive"
)

// 与真实冷块对拍：先影子归档一批事件，再走 Query 读回来。单元测试用内存块覆盖了
// 过滤/去重/排序/预算，这里要验的是 SQL 侧的候选块收窄、载荷读取与表存在性判断。

// seedQuery 造一天内的事件：4001/agent 两条（分属两个资产）、4003/sensor 一条无归属。
func seedQuery(t *testing.T, ctx context.Context, client *ent.Client, db *sql.DB) (assetA, assetB uuid.UUID, events []*ent.Event) {
	t.Helper()
	day := eventpartToday().AddDate(0, 0, -1)
	a := client.Asset.Create().SetHostname("qa").SaveX(ctx)
	b := client.Asset.Create().SetHostname("qb").SaveX(ctx)
	add := func(ts time.Time, class int, source string, asset *uuid.UUID, raw string) *ent.Event {
		c := client.Event.Create().SetTs(ts).SetClassUID(class).SetSource(source).SetRaw(json.RawMessage(raw))
		if asset != nil {
			c.SetAssetID(*asset)
		}
		return c.SaveX(ctx)
	}
	events = []*ent.Event{
		add(day.Add(time.Minute), 4001, "agent", &a.ID, `{"conn":{"dst":"10.0.0.1:443"}}`),
		add(day.Add(2*time.Minute), 4001, "agent", &b.ID, `{"conn":{"dst":"10.0.0.2:443"}}`),
		add(day.Add(3*time.Minute), 4003, "sensor", nil, `{"file":{"path":"/tmp/a"}}`),
	}
	if _, err := eventarchive.Shadow(ctx, db, eventarchive.Options{
		From: day, To: day, Classes: []int{4001, 4003}, Confirm: true,
	}); err != nil {
		t.Fatalf("影子归档失败: %v", err)
	}
	return a.ID, b.ID, events
}

func queryIDs(events []eventarchive.Event) []uuid.UUID {
	out := make([]uuid.UUID, len(events))
	for i, e := range events {
		out[i] = e.ID
	}
	return out
}

func wantIDs(t *testing.T, got []eventarchive.Event, want ...uuid.UUID) {
	t.Helper()
	have := queryIDs(got)
	if len(have) != len(want) {
		t.Fatalf("返回 %d 条，期望 %d 条：%v vs %v", len(have), len(want), have, want)
	}
	for i := range want {
		if have[i] != want[i] {
			t.Fatalf("第 %d 条是 %s，期望 %s（完整结果 %v）", i, have[i], want[i], have)
		}
	}
}

// 1. 归档范围、全量读回、(ts, id) 倒序与类别/时间/ID 过滤。
func TestQueryReadsArchivedEvents(t *testing.T) {
	ctx, client, db := open(t)
	_, _, seeded := seedQuery(t, ctx, client, db)
	day := eventpartToday().AddDate(0, 0, -1)

	ext, err := eventarchive.ArchiveExtent(ctx, db)
	if err != nil {
		t.Fatalf("读归档范围: %v", err)
	}
	if !ext.Schema || !ext.Has || !ext.First.Equal(seeded[0].Ts) || !ext.Last.Equal(seeded[2].Ts) {
		t.Fatalf("归档范围不符: %+v，事件 %s..%s", ext, seeded[0].Ts, seeded[2].Ts)
	}

	all, cov, err := eventarchive.Query(ctx, db, eventarchive.Filter{})
	if err != nil {
		t.Fatalf("全量查询失败: %v", err)
	}
	wantIDs(t, all, seeded[2].ID, seeded[1].ID, seeded[0].ID)
	if cov.Matched != 3 || cov.Truncated || cov.ScannedChunks == 0 {
		t.Errorf("覆盖度不符: %+v", cov)
	}
	// 解出来的事件与 events 里的原文逐字节一致（events 侧要重新查一次，jsonb 的文本表示带空格）
	fresh, err := client.Event.Get(ctx, seeded[2].ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(all[0].Raw) != string(fresh.Raw) {
		t.Errorf("raw 不一致：冷块 %s，events %s", all[0].Raw, fresh.Raw)
	}

	// 只查 4001、且窗口落在中间的半小时
	events, cov, err := eventarchive.Query(ctx, db, eventarchive.Filter{
		From: day.Add(90 * time.Second), To: day.Add(3 * time.Minute), Classes: []int{4001},
	})
	if err != nil {
		t.Fatalf("按类别与时间窗查询失败: %v", err)
	}
	wantIDs(t, events, seeded[1].ID)
	if cov.Matched != 1 {
		t.Errorf("命中 %d 条，期望 1 条", cov.Matched)
	}

	// 按事件 ID 精确定位
	events, _, err = eventarchive.Query(ctx, db, eventarchive.Filter{IDs: []uuid.UUID{seeded[2].ID}})
	if err != nil {
		t.Fatalf("按 ID 查询失败: %v", err)
	}
	wantIDs(t, events, seeded[2].ID)
}

// 2. 资产过滤：集合内保留、集合外与无归属（asset_id IS NULL）一律丢弃；空集合一无所见。
func TestQueryAssetScope(t *testing.T) {
	ctx, client, db := open(t)
	assetA, assetB, _ := seedQuery(t, ctx, client, db)

	events, cov, err := eventarchive.Query(ctx, db, eventarchive.Filter{AssetIDs: []uuid.UUID{assetA}})
	if err != nil {
		t.Fatalf("按资产查询失败: %v", err)
	}
	if len(events) != 1 || events[0].AssetID == nil || *events[0].AssetID != assetA {
		t.Fatalf("资产 A 只应返回 1 条，实际 %v", queryIDs(events))
	}

	events, _, err = eventarchive.Query(ctx, db, eventarchive.Filter{AssetIDs: []uuid.UUID{assetA, assetB}})
	if err != nil {
		t.Fatalf("按资产集合查询失败: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("资产 A+B 应返回 2 条，实际 %v", queryIDs(events))
	}
	for _, e := range events {
		if e.AssetID == nil {
			t.Errorf("无归属事件不该出现在受限于资产集合的结果里: %s", e.ID)
		}
	}

	// 空集合（非 nil）是「一无所见」，不是「不限」
	events, cov, err = eventarchive.Query(ctx, db, eventarchive.Filter{AssetIDs: []uuid.UUID{}})
	if err != nil {
		t.Fatalf("空资产集合查询失败: %v", err)
	}
	if len(events) != 0 || cov.ScannedChunks != 0 {
		t.Errorf("空资产集合不该返回或扫描任何东西: %d 条 %+v", len(events), cov)
	}

	// nil 是不限：admin 能看到无归属事件
	events, _, err = eventarchive.Query(ctx, db, eventarchive.Filter{AssetIDs: nil})
	if err != nil {
		t.Fatalf("不限资产查询失败: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("不限资产应返回 3 条，实际 %v", queryIDs(events))
	}
}

// 3. 块损坏：Query 整体报错并带上块 id，不返回部分结果。
func TestQueryCorruptChunkInDatabase(t *testing.T) {
	ctx, client, db := open(t)
	seedQuery(t, ctx, client, db)

	var id uuid.UUID
	var payload []byte
	if err := db.QueryRowContext(ctx,
		`SELECT id, payload FROM event_archive_chunks ORDER BY seq LIMIT 1`).Scan(&id, &payload); err != nil {
		t.Fatal(err)
	}
	payload[0] ^= 0xff
	if _, err := db.ExecContext(ctx, `UPDATE event_archive_chunks SET payload = $2 WHERE id = $1`, id, payload); err != nil {
		t.Fatal(err)
	}

	events, _, err := eventarchive.Query(ctx, db, eventarchive.Filter{})
	if err == nil {
		t.Fatal("块损坏必须返回错误")
	}
	if len(events) != 0 {
		t.Fatalf("块损坏时不能返回部分结果，实际 %d 条", len(events))
	}
	if !strings.Contains(err.Error(), id.String()) {
		t.Errorf("错误里应带块 id %s: %v", id, err)
	}
}

// 4. 没有冷数据时（表在、但一块都没有）Query 返回空结果，而不是报错。
func TestQueryWithoutArchiveData(t *testing.T) {
	ctx, _, db := open(t)
	events, cov, err := eventarchive.Query(ctx, db, eventarchive.Filter{})
	if err != nil {
		t.Fatalf("空归档不该报错: %v", err)
	}
	if len(events) != 0 || cov.ScannedChunks != 0 || cov.Matched != 0 || cov.Truncated {
		t.Errorf("空归档应返回空结果: %d 条 %+v", len(events), cov)
	}
	ext, err := eventarchive.ArchiveExtent(ctx, db)
	if err != nil || ext.Has || !ext.Schema {
		t.Errorf("空归档的 Extent 应是「表在、没有块」: %+v %v", ext, err)
	}
}

// 5. 表还不存在（没跑过 ensure-schema）：Query 报 ErrNoSchema，调用方据此按「没有冷数据」处理，
// 不能当成数据损坏。
func TestQueryWithoutSchema(t *testing.T) {
	ctx, _, db := open(t)
	if _, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS event_archive_locator, event_archive_chunks, event_archive_runs`); err != nil {
		t.Fatal(err)
	}
	ext, err := eventarchive.ArchiveExtent(ctx, db)
	if err != nil || ext.Schema || ext.Has {
		t.Errorf("没有表时 Extent 应是 Schema=false: %+v %v", ext, err)
	}
	if _, _, err := eventarchive.Query(ctx, db, eventarchive.Filter{}); !errors.Is(err, eventarchive.ErrNoSchema) {
		t.Errorf("没有表时 Query 应报 ErrNoSchema，实际 %v", err)
	}
}
