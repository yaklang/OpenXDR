//go:build integration

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// AI 提议的抑制：批准前不生效；组内 analyst 不能批，组管理员能；批准后立即生效，有效期从批准时重新算
func TestSuppressionReview(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("A").SaveX(ctx)
	host := client.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SaveX(ctx)
	created := time.Now().Add(-10 * 24 * time.Hour)
	p := client.Suppression.Create().SetRuleID("probe").SetAssetID(host.ID).SetStatus("proposed").SetReason("例行巡检").
		SetCreatedBy("ai:x").SetCreatedAt(created).SetExpiresAt(created.Add(30 * 24 * time.Hour)).SaveX(ctx)
	analyst := client.User.Create().SetUsername("ana").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(analyst.ID).SetRole("analyst").SaveX(ctx)
	lead := client.User.Create().SetUsername("lead").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(lead.ID).SetRole("admin").SaveX(ctx)

	store := suppress.New(client, time.Hour)
	store.Reload(ctx)
	if store.Suppressed("probe", &host.ID, nil, time.Now()) {
		t.Fatal("提议在批准前不能生效")
	}
	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), store, intel.New(client, time.Hour), nil)
	review := func(ts *httptest.Server, decision string) int {
		resp, err := http.Post(ts.URL+"/api/suppressions/"+p.ID.String()+"/review", "application/json", strings.NewReader(`{"decision":"`+decision+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	asAnalyst := httptest.NewServer(as(analyst, h))
	t.Cleanup(asAnalyst.Close)
	asLead := httptest.NewServer(as(lead, h))
	t.Cleanup(asLead.Close)
	if code := review(asAnalyst, "approve"); code != http.StatusForbidden {
		t.Fatalf("组内 analyst 不能批准，得到 %d", code)
	}
	if code := review(asLead, "approve"); code != http.StatusNoContent {
		t.Fatalf("组管理员批准应 204，得到 %d", code)
	}
	got := client.Suppression.GetX(ctx, p.ID)
	if got.Status != "active" || got.ReviewedBy == nil || got.ExpiresAt.Before(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("批准后应生效、有效期从批准时重新算: %+v", got)
	}
	if !store.Suppressed("probe", &host.ID, nil, time.Now()) {
		t.Fatal("批准后应立即生效")
	}
	if code := review(asLead, "reject"); code != http.StatusConflict {
		t.Fatalf("已处理的提议不能再审，得到 %d", code)
	}
}
