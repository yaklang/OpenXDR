//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/containment"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

// 决策记录按组可见，别组的来源主机不给名字；解除要组 analyst，撤不回的返回 409，成功的下发恢复动作
func TestContainmentsListAndLift(t *testing.T) {
	ctx, client := testdb.New(t)
	group := client.Group.Create().SetName("prod").SaveX(ctx)
	other := client.Group.Create().SetName("lab").SaveX(ctx)
	agent := uuid.New()
	web := client.Asset.Create().SetHostname("web").SetGroupID(group.ID).SetAgentID(agent).SaveX(ctx)
	rng := client.Asset.Create().SetHostname("range").SetGroupID(other.ID).SaveX(ctx)
	viewer := client.User.Create().SetUsername("vi").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(group.ID).SetUserID(viewer.ID).SetRole("viewer").SaveX(ctx)
	ana := client.User.Create().SetUsername("ana").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(group.ID).SetUserID(ana.ID).SetRole("analyst").SaveX(ctx)

	alertID := uuid.New()
	block := client.Containment.Create().SetAssetID(web.ID).SetGroupID(group.ID).SetKind("block_network").SetTarget("10.1.1.170").
		SetKey("k1").SetSignal("xdr:internal-lateral-spray").SetAlertID(alertID).SetSourceAssetID(rng.ID).
		SetRole("victim").SetState("active").SetReason("封锁来源").SaveX(ctx)
	kill := client.Containment.Create().SetAssetID(web.ID).SetGroupID(group.ID).SetKind("kill_process").SetTarget(uuid.NewString()).
		SetKey("k2").SetSignal("intel:ip:1.2.3.4").SetAlertID(alertID).SetRole("host").SetState("executed").SetReason("结束进程").SaveX(ctx)
	client.Containment.Create().SetAssetID(rng.ID).SetGroupID(other.ID).SetKind("isolate_host").
		SetKey("k3").SetSignal("xdr:internal-lateral-spray").SetAlertID(alertID).SetRole("source").SetState("active").SetReason("隔离").SaveX(ctx)

	hub := response.NewHub(client, true)
	inbox := hub.Attach(agent)
	h := Containments(client, hub, nil)
	vi := httptest.NewServer(as(viewer, h))
	t.Cleanup(vi.Close)
	an := httptest.NewServer(as(ana, h))
	t.Cleanup(an.Close)
	admin := httptest.NewServer(asAdmin(h))
	t.Cleanup(admin.Close)

	resp, body := get(t, vi, "/api/containments")
	var list struct {
		Items []containmentRow `json:"items"`
		Total int              `json:"total"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &list) != nil || list.Total != 2 {
		t.Fatalf("组内只看到本组两条: %d %s", resp.StatusCode, body)
	}
	for _, row := range list.Items {
		if row.SourceHostname != "" || row.AssetHostname != "web" {
			t.Fatalf("别组来源主机不给名字: %+v", row)
		}
	}
	if _, body = get(t, admin, "/api/containments?state=active"); json.Unmarshal(body, &list) != nil || list.Total != 2 || list.Items[0].State != "active" {
		t.Fatalf("admin 按状态筛: %s", body)
	}

	lift := "/api/containments/" + block.ID.String() + "/lift"
	if code := send(t, vi, "POST", lift, `{"reason":"x"}`); code != http.StatusForbidden {
		t.Errorf("viewer 不能解除: %d", code)
	}
	if code := send(t, an, "POST", "/api/containments/"+kill.ID.String()+"/lift", `{}`); code != http.StatusConflict {
		t.Errorf("结束进程撤不回应 409: %d", code)
	}
	if code := send(t, an, "POST", lift, `{"reason":"确认是演练"}`); code != http.StatusOK {
		t.Fatalf("analyst 解除: %d", code)
	}
	c := <-inbox
	if c.Target != "10.1.1.170" {
		t.Fatalf("应下发 unblock: %v", c)
	}
	got := client.Containment.GetX(ctx, block.ID)
	if got.State != "active" || got.LiftedBy == nil || *got.LiftedBy != "ana" || got.LiftCommandID == nil || got.EndedAt != nil {
		t.Fatalf("解除回执到达前应保持 active 且不写 EndedAt: %+v", got)
	}
	if err := hub.Complete(ctx, agent, &pb.CommandResult{CommandId: c.Id, Status: pb.CommandResult_SUCCEEDED}); err != nil {
		t.Fatal(err)
	}
	if err := containment.Reconcile(ctx, client, time.Now()); err != nil {
		t.Fatal(err)
	}
	got = client.Containment.GetX(ctx, block.ID)
	if got.State != "lifted" || got.LiftedBy == nil || *got.LiftedBy != "ana" || got.LiftCommandID == nil || got.EndedAt == nil {
		t.Fatalf("成功回执对账后应记人工解除: %+v", got)
	}

	resp, body = get(t, vi, "/api/containments/status")
	var st struct {
		Enabled bool `json:"enabled"`
		Active  int  `json:"active"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &st) != nil || st.Enabled || st.Active != 1 {
		t.Fatalf("未开启时状态照样可查: %s", body)
	}
}
