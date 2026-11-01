//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func TestSuricataVisibility(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("allowed").SaveX(ctx)
	other := client.Group.Create().SetName("other").SaveX(ctx)
	a := client.Asset.Create().SetHostname("allowed").SetGroupID(g.ID).SaveX(ctx)
	b := client.Asset.Create().SetHostname("other").SetGroupID(other.ID).SaveX(ctx)
	var incidents []*ent.Incident
	for i, asset := range []*ent.Asset{a, b, nil} {
		create := client.Event.Create().SetTs(time.Now()).SetClassUID(2004).SetSource("suricata").SetRaw(json.RawMessage(fmt.Sprintf(`{"suricata":{"marker":"evidence-%d"}}`, i)))
		if asset != nil {
			create.SetAssetID(asset.ID)
		}
		event := create.SaveX(ctx)
		inc := client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
		incidents = append(incidents, inc)
		alert := client.Alert.Create().SetTs(time.Now()).SetRuleID("suricata:1:42").SetSeverity(4).SetEventID(event.ID).SetIncidentID(inc.ID).SetDetail("网络测试告警")
		if asset != nil {
			alert.SetAssetID(asset.ID)
		}
		alert.SaveX(ctx)
	}
	user := client.User.Create().SetUsername("reader").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetUserID(user.ID).SetGroupID(g.ID).SetRole("viewer").SaveX(ctx)
	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	for i, inc := range incidents {
		r := httptest.NewRequest("GET", "/api/incidents/"+inc.ID.String(), nil)
		w := httptest.NewRecorder()
		as(user, h).ServeHTTP(w, r)
		if i == 0 {
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"ruleTitle":"网络测试告警"`) || !strings.Contains(w.Body.String(), "evidence-0") {
				t.Fatalf("告警标题或证据不可见: %d %s", w.Code, w.Body.String())
			}
		} else if w.Code != 404 {
			t.Fatalf("跨组或未知证据泄露: %d", w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/api/events?source=suricata", nil)
	w := httptest.NewRecorder()
	as(user, h).ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "evidence-1") || strings.Contains(w.Body.String(), "evidence-2") || !strings.Contains(w.Body.String(), "evidence-0") {
		t.Fatalf("事件列表范围不正确: %s", w.Body.String())
	}
}
