//go:build integration

package correlate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
)

// 同资产、时间窗内的两条告警 → 归入同一个 incident，图上挂出 asset+process 节点。
func TestCorrelateBatchGroupsByAsset(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	pg := uuid.New()

	asset, err := client.Asset.Create().SetHostname("host-a").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	mkAlert := func(ts time.Time, ruleID string, pg uuid.UUID) *ent.Alert {
		evt, err := client.Event.Create().
			SetTs(ts).
			SetClassUID(1007).SetSource("agent").
			SetProcessGUID(pg).
			SetRaw(json.RawMessage(`{"process":{"name":"cmd.exe","pid":1}}`)).
			Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		al, err := client.Alert.Create().
			SetTs(ts).SetRuleID(ruleID).SetSeverity(3).
			SetEventID(evt.ID).SetNillableAssetID(&asset.ID).
			Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return al
	}

	al1 := mkAlert(now, "r-one", pg)
	al2 := mkAlert(now.Add(time.Minute), "r-two", pg)

	eng := &Engine{
		DB:            client,
		Rules:         &sigma.Engine{},
		Window:        30 * time.Minute,
		MaxGraphNodes: 50,
	}
	if err := eng.batch(ctx); err != nil {
		t.Fatalf("batch 失败: %v", err)
	}

	// 恰好一个 incident
	incs, err := client.Incident.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) != 1 {
		t.Fatalf("同资产两告警应归入 1 个 incident，实际 %d", len(incs))
	}

	// 两条告警都已归属
	got1, _ := client.Alert.Get(ctx, al1.ID)
	got2, _ := client.Alert.Get(ctx, al2.ID)
	if got1.IncidentID == nil || *got1.IncidentID != incs[0].ID {
		t.Errorf("alert1 未归属到 incident")
	}
	if got2.IncidentID == nil || *got2.IncidentID != incs[0].ID {
		t.Errorf("alert2 未归属到 incident")
	}

	// 图节点：asset + process
	graph := string(incs[0].Graph)
	for _, want := range []string{"asset:" + asset.ID.String(), "process:" + pg.String()} {
		if !strings.Contains(graph, want) {
			t.Errorf("incident 图应含节点 %q，实际 %s", want, graph)
		}
	}
}

// 批次内 byAsset 缓存：同批同资产直接命中内存 incident，不复查时间窗（见 batch 注释，
// 这是防风暴的刻意取舍）。因此这里应是：asset A 两条合并 + asset B 独立 = 2 个 incident。
func TestCorrelateBatchSeparates(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()

	assetA, _ := client.Asset.Create().SetHostname("host-a").Save(ctx)
	assetB, _ := client.Asset.Create().SetHostname("host-b").Save(ctx)

	mk := func(ts time.Time, ruleID string, aid *uuid.UUID, pg uuid.UUID) *ent.Alert {
		evt, err := client.Event.Create().
			SetTs(ts).SetClassUID(1007).SetSource("agent").
			SetProcessGUID(pg).SetRaw(json.RawMessage(`{}`)).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		al, err := client.Alert.Create().
			SetTs(ts).SetRuleID(ruleID).SetSeverity(3).
			SetEventID(evt.ID).SetNillableAssetID(aid).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return al
	}

	a1 := mk(now, "r-a", &assetA.ID, uuid.New())
	a3 := mk(now.Add(time.Hour), "r-a2", &assetA.ID, uuid.New()) // 同资产、超窗 → 批内仍合并
	b1 := mk(now, "r-b", &assetB.ID, uuid.New())                 // 不同资产 → 独立

	eng := &Engine{
		DB:            client,
		Rules:         &sigma.Engine{},
		Window:        30 * time.Minute,
		MaxGraphNodes: 50,
	}
	if err := eng.batch(ctx); err != nil {
		t.Fatalf("batch 失败: %v", err)
	}

	incs, err := client.Incident.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) != 2 {
		t.Fatalf("期待 2 个 incident（asset A 合并 + asset B），实际 %d", len(incs))
	}

	// asset A 的两条归同一个 incident；asset B 独立
	getInc := func(id uuid.UUID) *uuid.UUID {
		al, err := client.Alert.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return al.IncidentID
	}
	ia := getInc(a1.ID)
	ia3 := getInc(a3.ID)
	ib := getInc(b1.ID)
	if ia == nil || *ia != *ia3 {
		t.Errorf("asset A 两条告警应归同一 incident，ia=%v ia3=%v", ia, ia3)
	}
	if ib == nil || *ib == *ia {
		t.Errorf("asset B 应独立于 asset A，ib=%v ia=%v", ib, ia)
	}
}
