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

// 同一批次也必须遵守时间窗；批次边界不能改变关联语义。
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
	a3 := mk(now.Add(time.Hour), "r-a2", &assetA.ID, uuid.New()) // 同资产但超窗 → 独立
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
	if len(incs) != 3 {
		t.Fatalf("期待 3 个 incident（asset A 超窗拆分 + asset B），实际 %d", len(incs))
	}

	// asset A 超窗拆开；asset B 也独立
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
	if ia == nil || ia3 == nil || *ia == *ia3 {
		t.Errorf("asset A 超窗告警必须拆分，ia=%v ia3=%v", ia, ia3)
	}
	if ib == nil || *ib == *ia {
		t.Errorf("asset B 应独立于 asset A，ib=%v ia=%v", ib, ia)
	}
}

// XDR 核心：父进程血缘跨越时间窗归并攻击链。
// A 进程早两小时触发告警归入 incident，B 进程（B 的父=A）新告警即使超窗口
// 也经 findByLineage 归到同一 incident，而不是另起事件风暴。
func TestCorrelateBatchLineage(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()

	asset, err := client.Asset.Create().SetHostname("host-l").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	guidA, guidB := uuid.New(), uuid.New()

	// A：进程 A，无父进程，2 小时前（超出 30 分钟窗口）
	evtA, err := client.Event.Create().
		SetTs(now.Add(-2 * time.Hour)).SetClassUID(1007).SetSource("agent").
		SetProcessGUID(guidA).SetRaw(json.RawMessage(`{}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(now.Add(-2 * time.Hour)).SetRuleID("r-A").SetSeverity(3).
		SetEventID(evtA.ID).SetNillableAssetID(&asset.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	eng := &Engine{
		DB:            client,
		Rules:         &sigma.Engine{},
		Window:        30 * time.Minute,
		MaxGraphNodes: 50,
	}
	// 首批：A 归入 incident1
	if err := eng.batch(ctx); err != nil {
		t.Fatalf("batch1 失败: %v", err)
	}

	// B：进程 B 的父是 A，现在（与 A 差 2 小时，超窗口）。A 已经在上一批
	// 归属 incident，B 才能通过持久化的进程血缘找到它。
	evtB, err := client.Event.Create().
		SetTs(now).SetClassUID(1007).SetSource("agent").
		SetProcessGUID(guidB).SetParentProcessGUID(guidA).
		SetRaw(json.RawMessage(`{}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	alertB, err := client.Alert.Create().
		SetTs(now).SetRuleID("r-B").SetSeverity(3).
		SetEventID(evtB.ID).SetNillableAssetID(&asset.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 次批：B 经血缘归入同 incident
	if err := eng.batch(ctx); err != nil {
		t.Fatalf("batch2 失败: %v", err)
	}

	incs, err := client.Incident.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) != 1 {
		t.Fatalf("血缘应把攻击链归到 1 个 incident，实际 %d", len(incs))
	}

	got, _ := client.Alert.Get(ctx, alertB.ID)
	if got.IncidentID == nil || *got.IncidentID != incs[0].ID {
		t.Errorf("B 应经血缘归入 incident，得到 %v", got.IncidentID)
	}
}
