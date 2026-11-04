//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"openxdr/server/internal/testdb"
)

func send(t *testing.T, ts *httptest.Server, method, path, body string) int {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// 区域定义要组 admin、网段规范化；人工改的标注锁定；区域指派不能跨组；
// analyst 能改标注但不能改区域。
func TestAssetMapPermissionsAndLocks(t *testing.T) {
	ctx, client := testdb.New(t)
	group := client.Group.Create().SetName("prod").SaveX(ctx)
	other := client.Group.Create().SetName("other").SaveX(ctx)
	host := client.Asset.Create().SetHostname("db-01").SetIPAddrs([]string{"10.1.1.5"}).SetGroupID(group.ID).SaveX(ctx)
	analyst := client.User.Create().SetUsername("ana").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(group.ID).SetUserID(analyst.ID).SetRole("analyst").SaveX(ctx)

	admin := httptest.NewServer(asAdmin(AssetMap(client, func() bool { return true })))
	t.Cleanup(admin.Close)
	ana := httptest.NewServer(as(analyst, AssetMap(client, func() bool { return true })))
	t.Cleanup(ana.Close)

	gid := group.ID.String()
	if code := send(t, admin, "POST", "/api/zones", `{"groupId":"`+gid+`","name":"DMZ","kind":"dmz","cidrs":["10.1.1.9/24"]}`); code != http.StatusCreated {
		t.Fatalf("建区域: %d", code)
	}
	z := client.Zone.Query().OnlyX(ctx)
	if z.Cidrs[0] != "10.1.1.0/24" {
		t.Fatalf("网段应规范化: %v", z.Cidrs)
	}
	for _, bad := range []string{`"kind":"moon","cidrs":[]`, `"kind":"dmz","cidrs":["10.1.1.1/99"]`} {
		if code := send(t, admin, "POST", "/api/zones", `{"groupId":"`+gid+`","name":"x",`+bad+`}`); code != http.StatusBadRequest {
			t.Errorf("非法区域应 400: %s → %d", bad, code)
		}
	}
	if code := send(t, admin, "POST", "/api/zones", `{"groupId":"`+gid+`","name":"DMZ","kind":"dmz"}`); code != http.StatusConflict {
		t.Errorf("同名区域应 409: %d", code)
	}
	if code := send(t, ana, "POST", "/api/zones", `{"groupId":"`+gid+`","name":"Y","kind":"dmz"}`); code != http.StatusForbidden {
		t.Errorf("analyst 不能定义区域: %d", code)
	}

	// 网段命中即进 DMZ，攻击面与画像都按它判定
	resp, body := get(t, ana, "/api/assets/"+host.ID.String()+"/profile")
	var profile struct {
		Zone struct{ Name, Source string }
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &profile) != nil || profile.Zone.Name != "DMZ" || profile.Zone.Source != "cidr" {
		t.Fatalf("画像区域: %d %s", resp.StatusCode, body)
	}

	if code := send(t, ana, "PUT", "/api/assets/"+host.ID.String()+"/profile", `{"role":"核心库","criticality":5}`); code != http.StatusNoContent {
		t.Fatalf("analyst 改标注: %d", code)
	}
	got := client.Asset.GetX(ctx, host.ID)
	if *got.Role != "核心库" || *got.Criticality != 5 || len(got.LockedFields) != 2 {
		t.Fatalf("人工改动应锁定: %+v", got.LockedFields)
	}
	if code := send(t, ana, "PUT", "/api/assets/"+host.ID.String()+"/profile", `{"criticality":9}`); code != http.StatusBadRequest {
		t.Errorf("越界重要程度应 400: %d", code)
	}
	if code := send(t, ana, "PUT", "/api/assets/"+host.ID.String()+"/profile", `{"unlock":["role"]}`); code != http.StatusNoContent {
		t.Fatal("解锁失败")
	}
	got = client.Asset.GetX(ctx, host.ID)
	if len(got.LockedFields) != 1 || got.AnnotateRequestedAt == nil {
		t.Fatalf("解锁后交还 AI 并请求重新标注: %+v", got.LockedFields)
	}

	if code := send(t, ana, "PUT", "/api/assets/"+host.ID.String()+"/zone", `{"zoneId":"`+z.ID.String()+`"}`); code != http.StatusForbidden {
		t.Errorf("analyst 不能指派区域: %d", code)
	}
	foreign := client.Zone.Create().SetGroupID(other.ID).SetName("别组").SetKind("internal").SaveX(ctx)
	if code := send(t, admin, "PUT", "/api/assets/"+host.ID.String()+"/zone", `{"zoneId":"`+foreign.ID.String()+`"}`); code != http.StatusBadRequest {
		t.Errorf("不能指派别组区域: %d", code)
	}
	if code := send(t, admin, "PUT", "/api/assets/"+host.ID.String()+"/zone", `{"zoneId":"`+z.ID.String()+`"}`); code != http.StatusNoContent {
		t.Fatal("admin 指派区域失败")
	}
	// 自主响应处置等级：新建默认生产；旧前端改区域不带该字段时保持原值；资产可单独指定，null 回到跟随区域
	if z.ResponseTier != "production" {
		t.Fatalf("新建区域默认生产等级: %s", z.ResponseTier)
	}
	if code := send(t, admin, "PUT", "/api/zones/"+z.ID.String(), `{"name":"DMZ","kind":"dmz","responseTier":"lab"}`); code != http.StatusOK {
		t.Fatalf("改处置等级: %d", code)
	}
	if code := send(t, admin, "PUT", "/api/zones/"+z.ID.String(), `{"name":"DMZ","kind":"dmz","cidrs":["10.1.1.0/24"]}`); code != http.StatusOK ||
		client.Zone.GetX(ctx, z.ID).ResponseTier != "lab" {
		t.Fatal("不带 responseTier 的修改应保持原等级")
	}
	if code := send(t, admin, "PUT", "/api/zones/"+z.ID.String(), `{"name":"DMZ","kind":"dmz","responseTier":"max"}`); code != http.StatusBadRequest {
		t.Errorf("非法等级应 400: %d", code)
	}
	tierURL := "/api/assets/" + host.ID.String() + "/response-tier"
	if code := send(t, ana, "PUT", tierURL, `{"tier":"lab"}`); code != http.StatusForbidden {
		t.Errorf("analyst 不能指定处置等级: %d", code)
	}
	if code := send(t, admin, "PUT", tierURL, `{"tier":"core"}`); code != http.StatusNoContent || *client.Asset.GetX(ctx, host.ID).ResponseTier != "core" {
		t.Fatalf("admin 指定处置等级: %d", code)
	}
	if code := send(t, admin, "PUT", tierURL, `{"tier":null}`); code != http.StatusNoContent || client.Asset.GetX(ctx, host.ID).ResponseTier != nil {
		t.Fatalf("null 应回到跟随区域: %d", code)
	}
	if code := send(t, admin, "PUT", tierURL, `{"tier":"max"}`); code != http.StatusBadRequest {
		t.Errorf("非法等级应 400: %d", code)
	}

	if code := send(t, admin, "DELETE", "/api/zones/"+z.ID.String(), ``); code != http.StatusNoContent {
		t.Fatal("删区域失败")
	}
	if client.Asset.GetX(ctx, host.ID).ZoneID != nil {
		t.Error("删区域后资产回到自动划分")
	}

	// 人工给服务定名：只认真实存在的监听；viewer 不能改
	client.Asset.UpdateOneID(host.ID).SetListening([]byte(`[{"proto":"udp","addr":"10.1.1.5","port":5405,"process":"corosync"}]`)).ExecX(ctx)
	if code := send(t, ana, "PUT", "/api/assets/"+host.ID.String()+"/services", `{"port":"udp/5405","name":"集群心跳","risk":"low"}`); code != http.StatusNoContent {
		t.Fatalf("analyst 定名: %d", code)
	}
	if code := send(t, ana, "PUT", "/api/assets/"+host.ID.String()+"/services", `{"port":"tcp/1","name":"x"}`); code != http.StatusBadRequest {
		t.Errorf("不存在的监听应 400: %d", code)
	}
	if code := send(t, ana, "PUT", "/api/assets/"+host.ID.String()+"/services", `{"port":"udp/5405","name":"x","risk":"extreme"}`); code != http.StatusBadRequest {
		t.Errorf("非法风险应 400: %d", code)
	}

	// 没开 AI 时拒绝标注请求
	noAI := httptest.NewServer(asAdmin(AssetMap(client, func() bool { return false })))
	t.Cleanup(noAI.Close)
	if code := send(t, noAI, "POST", "/api/assets/"+host.ID.String()+"/annotate", ``); code != http.StatusServiceUnavailable {
		t.Errorf("未配置模型应 503: %d", code)
	}
}
