//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func TestTriageRunsPaginationAndScope(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("visible").SaveX(ctx)
	other := db.Group.Create().SetName("hidden").SaveX(ctx)
	user := db.User.Create().SetUsername("viewer").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	db.GroupMember.Create().SetGroupID(g.ID).SetUserID(user.ID).SetRole("viewer").SaveX(ctx)
	makeIncident := func(group *ent.Group) *ent.Incident {
		a := db.Asset.Create().SetHostname(group.Name).SetGroupID(group.ID).SaveX(ctx)
		i := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
		db.Alert.Create().SetIncidentID(i.ID).SetAssetID(a.ID).SetRuleID("test").SetSeverity(3).SetTs(time.Now()).SaveX(ctx)
		return i
	}
	visible, hidden := makeIncident(g), makeIncident(other)
	for n := 0; n < 25; n++ {
		db.TriageRun.Create().SetIncidentID(visible.ID).SetTrigger("initial").SetStartedAt(time.Now().Add(time.Duration(n) * time.Second)).SaveX(ctx)
	}
	db.TriageRun.Create().SetIncidentID(hidden.ID).SetTrigger("initial").SetModel("hidden-model").SaveX(ctx)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/incidents/{id}/triage-runs", incidentTriageRuns(db))
	srv := httptest.NewServer(as(user, mux))
	defer srv.Close()
	seen := map[string]bool{}
	for page := 1; page <= 2; page++ {
		resp, body := get(t, srv, fmt.Sprintf("/api/incidents/%s/triage-runs?page=%d", visible.ID, page))
		var out struct {
			Items []*ent.TriageRun `json:"items"`
			More  bool             `json:"more"`
		}
		if resp.StatusCode != 200 || json.Unmarshal(body, &out) != nil || out.More != (page == 1) {
			t.Fatalf("分页失败：%s", body)
		}
		for _, row := range out.Items {
			if seen[row.ID.String()] {
				t.Fatal("记录重复")
			}
			seen[row.ID.String()] = true
		}
	}
	if len(seen) != 25 {
		t.Fatal(len(seen))
	}
	if resp, _ := get(t, srv, "/api/incidents/"+hidden.ID.String()+"/triage-runs"); resp.StatusCode != 404 {
		t.Fatal("跨组泄露")
	}
	if resp, _ := get(t, srv, "/api/incidents/"+visible.ID.String()+"/triage-runs?page=0"); resp.StatusCode != 400 {
		t.Fatal("分页未校验")
	}
}
