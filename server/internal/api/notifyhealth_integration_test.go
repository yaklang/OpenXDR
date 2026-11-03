//go:build integration

package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/notify"
	"openxdr/server/internal/testdb"
)

// 没配推送目标时，admin 看到全局积压；不在任何组的 viewer 看不到别组事件，只见渠道状态
func TestNotifyHealthAPI(t *testing.T) {
	ctx, client := testdb.New(t)
	inc, err := client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus("open").
		SetCreatedAt(time.Now().Add(-time.Hour)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(5).SetIncidentID(inc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	h := NotifyHealth(client, &notify.Settings{DB: client})

	for _, c := range []struct {
		name    string
		user    *ent.User
		pending int
	}{
		{"admin", &ent.User{Username: "admin", Role: "admin"}, 1},
		{"无组 viewer", &ent.User{ID: uuid.New(), Username: "v", Role: "viewer"}, 0},
	} {
		ts := httptest.NewServer(as(c.user, h))
		resp, body := get(t, ts, "/api/notify/health")
		ts.Close()
		var got notify.Health
		if err := json.Unmarshal(body, &got); err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", c.name, resp.StatusCode, body)
		}
		if got.Status != "unconfigured" || got.PendingIncidents != c.pending {
			t.Errorf("%s: got %+v", c.name, got)
		}
	}
}
