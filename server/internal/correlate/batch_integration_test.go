//go:build integration

package correlate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
	"openxdr/server/ent"
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

// 不同资产、超出时间窗的告警各成 incident，不互相污染。
func TestCorrelateBatchSeparates(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()

	assetA, _ := client.Asset.Create().SetHostname("host-a").Save(ctx)
	assetB, _ := client.Asset.Create().SetHostname("host-b").Save(ctx)

	mk := func(ts time.Time, ruleID string, aid *uuid.UUID, pg uuid.UUID) {
		evt, err := client.Event.Create().
			SetTs(ts).SetClassUID(1007).SetSource("agent").
			SetProcessGUID(pg).SetRaw(json.RawMessage(`{}`)).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Alert.Create().
			SetTs(ts).SetRuleID(ruleID).SetSeverity(3).
			SetEventID(evt.ID).SetNillableAssetID(aid).Save(ctx); err != nil {
			t.Fatal(err)
		}
	}

	p1, p2 := uuid.New(), uuid.New()
	mk(now, "r-a", &assetA.ID, p1)          // asset A
	mk(now, "r-b", &assetB.ID, p2)          // asset B → 不同
	mk(now.Add(time.Hour), "r-a2", &assetA.ID, uuid.New()) // asset A 但超出窗口

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
	// asset A 两条（一条超出窗口 → 不同 incident）+ asset B 一条 = 3
	if len(incs) != 3 {
		t.Fatalf("期望 3 个独立 incident，实际 %d", len(incs))
	}
}
