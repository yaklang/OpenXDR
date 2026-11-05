//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"openxdr/server/ent/schema"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func TestManualReopenInvalidatesWorkAndRunningLease(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	inc := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus("triaged").SetTriagedAt(now).SetAiVerdict(json.RawMessage(`{"verdict":"benign"}`)).SetWork(&schema.IncidentWork{Version: 1, Owner: "ai", Stage: "followup", VerdictAt: now}).SetWorkNextCheckAt(now.Add(time.Hour)).SetTriageStartedAt(now).SetTriageHeartbeatAt(now).SaveX(ctx)
	ts := httptest.NewServer(asAdmin(Handler(db, nil, loadRules(t), response.NewHub(db, false), suppress.New(db, time.Hour), intel.New(db, time.Hour), nil)))
	defer ts.Close()
	r, err := postJSON(ts, "/api/incidents/"+inc.ID.String()+"/status", `{"status":"open"}`)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 204 {
		t.Fatal(r.StatusCode)
	}
	got := db.Incident.GetX(ctx, inc.ID)
	if got.Status != "open" || got.Work != nil || got.WorkNextCheckAt != nil || got.TriageStartedAt != nil || got.TriageHeartbeatAt != nil {
		t.Fatal("人工重开仍保留旧计划或执行租约")
	}
}

func TestFindingWorkOwnerIsServerPaged(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("ops").SaveX(ctx)
	a := db.Asset.Create().SetHostname("host").SetGroupID(g.ID).SaveX(ctx)
	for index, owner := range []string{"ai", "ai", "human"} {
		db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey(fmt.Sprintf("%s-%d", owner, index)).SetTitle("待复查").SetDetail("真实工作状态").SetWorkOwner(owner).ExecX(ctx)
	}
	ts := httptest.NewServer(asAdmin(Handler(db, nil, loadRules(t), response.NewHub(db, false), suppress.New(db, time.Hour), intel.New(db, time.Hour), nil)))
	defer ts.Close()
	r, raw := get(t, ts, "/api/findings?workOwner=ai&limit=1")
	var rows []findingRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 200 || r.Header.Get("X-Total-Count") != "2" || len(rows) != 1 || rows[0].WorkOwner != "ai" {
		t.Fatal("负责人筛选未先于全库计数及分页", string(raw))
	}
	bad, _ := get(t, ts, "/api/findings?workOwner=unknown")
	if bad.StatusCode != 400 {
		t.Fatal("无效负责人未拒绝")
	}
}
