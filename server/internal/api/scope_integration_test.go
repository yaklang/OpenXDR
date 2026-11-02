//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// 非 admin 只看得到自己组里的资产、事件、告警与 incident；跨组 incident 整体不可见，
// 组内 viewer 不能做写操作。
func TestAPIGroupScope(t *testing.T) {
	ctx, client := testdb.New(t)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	a1 := client.Asset.Create().SetHostname("a1").SetCollectorHealth(json.RawMessage(`{"bootId":"health-visible"}`)).SetGroupID(gA.ID).SaveX(ctx)
	b1 := client.Asset.Create().SetHostname("b1").SetCollectorHealth(json.RawMessage(`{"bootId":"health-hidden"}`)).SetGroupID(gB.ID).SaveX(ctx)
	client.Asset.Create().SetHostname("loose").SaveX(ctx)

	alertOn := func(asset *ent.Asset, inc *ent.Incident) {
		evt := client.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").
			SetAssetID(asset.ID).SetRaw(json.RawMessage(`{}`)).SaveX(ctx)
		client.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(3).
			SetEventID(evt.ID).SetAssetID(asset.ID).SetIncidentID(inc.ID).SaveX(ctx)
	}
	newInc := func(title string) *ent.Incident {
		return client.Incident.Create().SetTitle(title).SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	}
	incA, incB, incAB := newInc("A"), newInc("B"), newInc("AB")
	alertOn(a1, incA)
	alertOn(b1, incB)
	alertOn(a1, incAB)
	alertOn(b1, incAB)

	alice := client.User.Create().SetUsername("alice").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(alice.ID).SetRole("viewer").SaveX(ctx)

	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	ts := httptest.NewServer(as(alice, h))
	t.Cleanup(ts.Close)

	count := func(path string) int {
		t.Helper()
		resp, body := get(t, ts, path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s status = %d", path, resp.StatusCode)
		}
		var list []json.RawMessage
		if err := json.Unmarshal(body, &list); err != nil {
			// /api/events 已是对象契约 {items,...}：数 items 长度
			var obj struct {
				Items []json.RawMessage `json:"items"`
			}
			if json.Unmarshal(body, &obj) != nil {
				t.Fatal(err)
			}
			list = obj.Items
		}
		return len(list)
	}
	if n := count("/api/assets"); n != 1 {
		t.Errorf("资产应只见 1 台，得到 %d", n)
	}
	_, healthBody := get(t, ts, "/api/assets")
	if !bytes.Contains(healthBody, []byte("health-visible")) || bytes.Contains(healthBody, []byte("health-hidden")) {
		t.Fatal("采集状态未返回或跨组泄露")
	}
	if n := count("/api/events"); n != 2 {
		t.Errorf("事件应只见 a1 的 2 条，得到 %d", n)
	}
	if n := count("/api/events?assetId=" + a1.ID.String()); n != 2 {
		t.Errorf("组内资产应返回 2 条事件，实际 %d", n)
	}
	if n := count("/api/events?assetId=" + b1.ID.String()); n != 0 {
		t.Errorf("组外资产不应返回事件，实际 %d", n)
	}
	if resp, _ := get(t, ts, "/api/events?assetId=invalid"); resp.StatusCode != 400 {
		t.Errorf("组内 viewer 的非法资产筛选应返回 400，实际 %d", resp.StatusCode)
	}
	if n := count("/api/incidents"); n != 1 {
		t.Errorf("incident 应只见 A，跨组的 AB 不可见，得到 %d", n)
	}
	for _, inc := range []*ent.Incident{incB, incAB} {
		if resp, _ := get(t, ts, "/api/incidents/"+inc.ID.String()); resp.StatusCode != 404 {
			t.Errorf("组外 incident %s 应 404，得到 %d", *inc.Title, resp.StatusCode)
		}
	}
	if resp, _ := get(t, ts, "/api/assets/"+b1.ID.String()+"/config"); resp.StatusCode != 404 {
		t.Errorf("组外资产配置应 404，得到 %d", resp.StatusCode)
	}

	var stats statsResponse
	_, body := get(t, ts, "/api/stats")
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatal(err)
	}
	if stats.AssetsTotal != 1 || stats.Events24h != 2 || stats.Alerts24h != 2 || stats.IncidentsByStatus["open"] != 1 {
		t.Errorf("统计应按组裁剪：%+v", stats)
	}
	if stats.AlertsBySeverity[3] != 2 || len(stats.AlertsBySeverity) != 1 {
		t.Errorf("级别分布应只计组内 2 条中危：%v", stats.AlertsBySeverity)
	}
	// 资产详情：按主机筛事件与指令，组外主机筛出来也是空
	if n := count("/api/incidents?assetId=" + a1.ID.String()); n != 1 {
		t.Errorf("a1 涉及的可见 incident 应为 1，得到 %d", n)
	}
	if n := count("/api/incidents?assetId=" + b1.ID.String()); n != 0 {
		t.Errorf("组外主机的 incident 不可见，得到 %d", n)
	}
	if n := count("/api/commands?assetId=" + a1.ID.String()); n != 0 {
		t.Errorf("a1 没有指令，得到 %d", n)
	}

	// 组内只是 viewer：改 incident 状态与下发指令都不行
	r, _ := postJSON(ts, "/api/incidents/"+incA.ID.String()+"/status", `{"status":"closed","note":"x"}`)
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Errorf("viewer 改状态应被拒，得到 %d", r.StatusCode)
	}
	r, _ = postJSON(ts, "/api/commands", `{"kind":"exec","cmd":"id","assetId":"`+a1.ID.String()+`"}`)
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Errorf("viewer 下发指令应被拒，得到 %d", r.StatusCode)
	}
}

// 抑制按资产所在组授权：组内 viewer 只看本组资产的抑制，全局抑制只有 admin 可见；
// 增删要求该资产组内 analyst，全局抑制只有 admin 能动。
func TestAPISuppressionScope(t *testing.T) {
	ctx, client := testdb.New(t)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	a1 := client.Asset.Create().SetHostname("a1").SetCollectorHealth(json.RawMessage(`{"bootId":"health-visible"}`)).SetGroupID(gA.ID).SaveX(ctx)
	b1 := client.Asset.Create().SetHostname("b1").SetCollectorHealth(json.RawMessage(`{"bootId":"health-hidden"}`)).SetGroupID(gB.ID).SaveX(ctx)
	supA := client.Suppression.Create().SetRuleID("r").SetAssetID(a1.ID).SetCreatedBy("t").SaveX(ctx)
	supB := client.Suppression.Create().SetRuleID("r").SetAssetID(b1.ID).SetCreatedBy("t").SaveX(ctx)
	supAll := client.Suppression.Create().SetRuleID("r").SetCreatedBy("t").SaveX(ctx)

	member := func(name, role string) *ent.User {
		u := client.User.Create().SetUsername(name).SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
		client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(u.ID).SetRole(role).SaveX(ctx)
		return u
	}
	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	serve := func(u *ent.User) *httptest.Server {
		ts := httptest.NewServer(as(u, h))
		t.Cleanup(ts.Close)
		return ts
	}
	viewerTS := serve(member("vera", "viewer"))
	analystTS := serve(member("ana", "analyst"))
	adminTS := serve(&ent.User{Username: "admin", Role: "admin"})

	ids := func(ts *httptest.Server) []string {
		t.Helper()
		resp, body := get(t, ts, "/api/suppressions")
		if resp.StatusCode != 200 {
			t.Fatalf("GET status = %d", resp.StatusCode)
		}
		var rows []struct{ ID string }
		if err := json.Unmarshal(body, &rows); err != nil {
			t.Fatal(err)
		}
		out := make([]string, len(rows))
		for i, r := range rows {
			out[i] = r.ID
		}
		return out
	}
	if got := ids(viewerTS); len(got) != 1 || got[0] != supA.ID.String() {
		t.Errorf("组 A viewer 只应看到 A 的抑制，得到 %v", got)
	}
	if got := ids(adminTS); len(got) != 3 {
		t.Errorf("admin 应看到全部 3 条，得到 %v", got)
	}

	create := func(asset string) string {
		if asset == "" {
			return `{"ruleId":"r"}`
		}
		return `{"ruleId":"r","assetId":"` + asset + `"}`
	}
	cases := []struct {
		name         string
		ts           *httptest.Server
		method, path string
		body         string
		want         int
	}{
		{"viewer 不能建本组抑制", viewerTS, "POST", "/api/suppressions", create(a1.ID.String()), 403},
		{"analyst 不能建别组抑制", analystTS, "POST", "/api/suppressions", create(b1.ID.String()), 403},
		{"analyst 不能建全局抑制", analystTS, "POST", "/api/suppressions", create(""), 403},
		{"analyst 不能撤别组抑制", analystTS, "DELETE", "/api/suppressions/" + supB.ID.String(), "", 403},
		{"analyst 不能撤全局抑制", analystTS, "DELETE", "/api/suppressions/" + supAll.ID.String(), "", 403},
		{"analyst 可建本组抑制", analystTS, "POST", "/api/suppressions", create(a1.ID.String()), 201},
		{"analyst 可撤本组抑制", analystTS, "DELETE", "/api/suppressions/" + supA.ID.String(), "", 204},
		{"admin 可建别组抑制", adminTS, "POST", "/api/suppressions", create(b1.ID.String()), 201},
		{"admin 可建全局抑制", adminTS, "POST", "/api/suppressions", create(""), 201},
		{"admin 可撤别组抑制", adminTS, "DELETE", "/api/suppressions/" + supB.ID.String(), "", 204},
		{"admin 可撤全局抑制", adminTS, "DELETE", "/api/suppressions/" + supAll.ID.String(), "", 204},
	}
	for _, c := range cases {
		resp, err := doReq(t, c.ts, c.method, c.path, c.body)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s: 得到 %d，期望 %d", c.name, resp.StatusCode, c.want)
		}
	}
}
