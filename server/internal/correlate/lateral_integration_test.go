//go:build integration

package correlate

import (
	"encoding/json"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
)

// 横向移动：A 上有告警成 incident，A→B 有网络会话，B 上随后的告警
// 应归入 A 的 incident，且图上出现 lateral 边。
func TestCorrelateLateralMovement(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()

	hostA, err := client.Asset.Create().SetHostname("host-a").
		SetIPAddrs([]string{"10.0.0.5"}).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hostB, err := client.Asset.Create().SetHostname("host-b").
		SetIPAddrs([]string{"10.0.0.8"}).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	mkAlert := func(ts time.Time, ruleID string, asset *ent.Asset) *ent.Alert {
		evt, err := client.Event.Create().
			SetTs(ts).SetClassUID(1007).SetSource("agent").
			SetNillableAssetID(&asset.ID).
			SetRaw(json.RawMessage(`{"process":{"name":"sh","pid":1}}`)).
			Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		al, err := client.Alert.Create().
			SetTs(ts).SetRuleID(ruleID).SetSeverity(4).
			SetEventID(evt.ID).SetNillableAssetID(&asset.ID).
			Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return al
	}

	eng := &Engine{DB: client, Rules: &sigma.Engine{}, Window: 30 * time.Minute, MaxGraphNodes: 50}

	// 第一批：A 上的告警自成 incident
	alA := mkAlert(now.Add(-10*time.Minute), "recon", hostA)
	if err := eng.batch(ctx); err != nil {
		t.Fatal(err)
	}

	// A → B 的网络会话（sensor 流事件按源 IP 归属到 A）
	tuple := "tcp:10.0.0.5:44000>10.0.0.8:22"
	if _, err := client.Event.Create().
		SetTs(now.Add(-5*time.Minute)).SetClassUID(4001).SetSource("sensor").
		SetNillableAssetID(&hostA.ID).SetConnTuple(tuple).
		SetRaw(json.RawMessage(`{"dst_endpoint":{"ip":"10.0.0.8","port":22}}`)).
		Save(ctx); err != nil {
		t.Fatal(err)
	}

	// 第二批：B 上的告警应接进 A 的故事
	alB := mkAlert(now, "reverse-shell", hostB)
	if err := eng.batch(ctx); err != nil {
		t.Fatal(err)
	}

	incs, err := client.Incident.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) != 1 {
		t.Fatalf("横向移动应归并成 1 个 incident，实际 %d", len(incs))
	}

	gotA, _ := client.Alert.Get(ctx, alA.ID)
	gotB, _ := client.Alert.Get(ctx, alB.ID)
	if gotA.IncidentID == nil || gotB.IncidentID == nil || *gotA.IncidentID != *gotB.IncidentID {
		t.Fatal("两台主机的告警应在同一 incident")
	}

	var g struct {
		Edges []struct {
			From string `json:"from"`
			To   string `json:"to"`
			Rel  string `json:"rel"`
		} `json:"edges"`
	}
	if err := json.Unmarshal(incs[0].Graph, &g); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range g.Edges {
		if e.Rel == "lateral" && e.From == "asset:"+hostA.ID.String() && e.To == "asset:"+hostB.ID.String() {
			found = true
		}
	}
	if !found {
		t.Errorf("图上缺 lateral 边：%s", incs[0].Graph)
	}
}
