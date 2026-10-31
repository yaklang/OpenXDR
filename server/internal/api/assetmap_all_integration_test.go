//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

// 全部组视图会露出别组主机名，只给全局 admin；组管理员拿 403
func TestAssetMapAllGroupsAdminOnly(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("ops").SaveX(ctx)
	client.Asset.Create().SetHostname("h1").SetGroupID(g.ID).SetLastSeen(time.Now()).SaveX(ctx)
	lead := client.User.Create().SetUsername("lead").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(g.ID).SetUserID(lead.ID).SetRole("admin").SaveX(ctx)
	h := AssetMap(client, func() bool { return false })

	asLead := httptest.NewServer(as(lead, h))
	t.Cleanup(asLead.Close)
	resp, err := http.Get(asLead.URL + "/api/asset-map?groupId=all")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("组管理员请求全部组视图应 403，实际 %d", resp.StatusCode)
	}

	admin := httptest.NewServer(as(&ent.User{Username: "admin", Role: "admin"}, h))
	t.Cleanup(admin.Close)
	resp, err = http.Get(admin.URL + "/api/asset-map?groupId=all")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var graph struct {
		Nodes []struct{ Label string } `json:"nodes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&graph); err != nil || resp.StatusCode != http.StatusOK || len(graph.Nodes) != 1 || graph.Nodes[0].Label != "h1" {
		t.Fatalf("全局 admin 应看到全部资产: %d %+v %v", resp.StatusCode, graph, err)
	}
}
