//go:build integration

package suppressclose

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/fpstats"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func TestSweepClosesFullyCoveredBenign(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	host := db.Asset.Create().SetHostname("runner").SetGroupID(g.ID).SaveX(ctx)
	other := db.Asset.Create().SetHostname("other").SetGroupID(g.ID).SaveX(ctx)
	now := time.Now().UTC().Truncate(time.Microsecond)
	noise := `{"process":{"file":{"path":"/tmp/go-build1/b001/x.test"}}}`
	real := `{"process":{"file":{"path":"/tmp/evil"}}}`
	incident := func(verdict string, alerts ...[2]string) *ent.Incident {
		inc := db.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SetCreatedAt(now.Add(-time.Hour)).
			SetTriagedAt(now.Add(-30 * time.Minute)).SetAiVerdict(json.RawMessage(`{"verdict":"` + verdict + `"}`)).SaveX(ctx)
		for _, a := range alerts {
			asset := host.ID
			if a[0] == "other" {
				asset = other.ID
			}
			ev := db.Event.Create().SetTs(now.Add(-time.Hour)).SetClassUID(1007).SetSource("agent").SetAssetID(asset).SetRaw(json.RawMessage(a[1])).SaveX(ctx)
			db.Alert.Create().SetTs(ev.Ts).SetRuleID("tmp-exec").SetSeverity(3).SetAssetID(asset).SetIncidentID(inc.ID).SetEventID(ev.ID).SaveX(ctx)
		}
		return inc
	}
	covered := incident("benign", [2]string{"runner", noise}, [2]string{"runner", noise})
	partial := incident("benign", [2]string{"runner", noise}, [2]string{"runner", real})
	elsewhere := incident("benign", [2]string{"other", noise})
	doubtful := incident("suspicious", [2]string{"runner", noise})
	locked := incident("benign", [2]string{"runner", noise})
	db.Incident.UpdateOneID(locked.ID).SetWork(&schema.IncidentWork{ManualLock: true}).ExecX(ctx)
	sup := db.Suppression.Create().SetRuleID("tmp-exec").SetAssetID(host.ID).SetStatus("active").SetCreatedBy(fpstats.CreatedByAI).
		SetConditions([]suppress.Condition{{Field: "process.file.path", Op: "contains", Value: "/tmp/go-build"}}).SaveX(ctx)
	// 待批草案不算生效
	db.Suppression.Create().SetRuleID("tmp-exec").SetAssetID(other.ID).SetStatus("proposed").SetCreatedBy(fpstats.CreatedByAI).SaveX(ctx)
	store := suppress.New(db, time.Minute)
	store.Reload(ctx)
	c := &Closer{DB: db, Store: store}
	if n, err := c.Sweep(ctx, now); err != nil || n != 1 {
		t.Fatalf("只应结案全部告警被覆盖的良性事件：%d %v", n, err)
	}
	got := db.Incident.GetX(ctx, covered.ID)
	if got.Status != "false_positive" || got.ResolutionSource == nil || *got.ResolutionSource != Source || got.ResolvedBy == nil || *got.ResolvedBy != "system" {
		t.Fatalf("%+v", got)
	}
	for _, id := range []uuid.UUID{partial.ID, elsewhere.ID, doubtful.ID, locked.ID} {
		if s := db.Incident.GetX(ctx, id).Status; s != "triaged" {
			t.Errorf("%s 不该结案：%s", id, s)
		}
	}
	db.Suppression.UpdateOne(sup).SetMatchedCount(0).ExecX(ctx)
	if n, err := c.Sweep(ctx, now); err != nil || n != 0 {
		t.Fatalf("再扫一轮不应重复：%d %v", n, err)
	}
	if db.Suppression.GetX(ctx, sup.ID).MatchedCount != 0 {
		t.Fatal("回头核对不应计入抑制命中次数")
	}
}
