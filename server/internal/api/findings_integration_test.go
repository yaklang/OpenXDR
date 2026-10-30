//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func TestAPIFindingsAssetFilter(t *testing.T) {
	ctx, client := testdb.New(t)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	target := client.Asset.Create().SetHostname("target").SetGroupID(gA.ID).SaveX(ctx)
	busy := client.Asset.Create().SetHostname("busy").SetGroupID(gA.ID).SaveX(ctx)
	secret := client.Asset.Create().SetHostname("secret").SetGroupID(gB.ID).SaveX(ctx)
	old := client.Finding.Create().SetGroupID(gA.ID).SetAssetID(target.ID).SetKey("old").SetTitle("旧待办仍需处理").SetLastSeen(time.Now().Add(-24 * time.Hour)).SaveX(ctx)
	secretFinding := client.Finding.Create().SetGroupID(gB.ID).SetAssetID(secret.ID).SetKey("secret").SetTitle("不可见待办").SaveX(ctx)
	bulk := make([]*ent.FindingCreate, 501)
	lastSeen := time.Now()
	for i := range bulk {
		bulk[i] = client.Finding.Create().SetGroupID(gA.ID).SetAssetID(busy.ID).SetKey(fmt.Sprint(i)).SetTitle("其他资产的新待办").SetLastSeen(lastSeen)
	}
	client.Finding.CreateBulk(bulk...).SaveX(ctx)
	u := client.User.Create().SetUsername("viewer").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(u.ID).SetRole("viewer").SaveX(ctx)
	mux := http.NewServeMux()
	mapFindings(mux, client)
	ts := httptest.NewServer(as(u, mux))
	t.Cleanup(ts.Close)
	code, body := get(t, ts, "/api/findings?assetId="+target.ID.String())
	var rows []findingRow
	if err := json.Unmarshal(body, &rows); code.StatusCode != 200 || err != nil || len(rows) != 1 || rows[0].ID != old.ID {
		t.Fatalf("资产筛选必须先于 500 条截断: status=%d rows=%d err=%v", code.StatusCode, len(rows), err)
	}
	for _, query := range []string{"assetId=" + secret.ID.String(), "assetId=" + target.ID.String() + "&status=resolved"} {
		code, body = get(t, ts, "/api/findings?"+query)
		if err := json.Unmarshal(body, &rows); code.StatusCode != 200 || err != nil || len(rows) != 0 {
			t.Errorf("资产筛选不能绕过组范围或状态过滤: status=%d body=%s", code.StatusCode, body)
		}
	}
	if code, _ := get(t, ts, "/api/findings?assetId=invalid"); code.StatusCode != 400 {
		t.Errorf("无效资产 ID 不能退回全量查询: status=%d", code.StatusCode)
	}
	seen := map[string]bool{}
	for offset := 0; offset < 501; offset += 200 {
		resp, body := get(t, ts, fmt.Sprintf("/api/findings?assetId=%s&limit=200&offset=%d", busy.ID, offset))
		if err := json.Unmarshal(body, &rows); err != nil || len(rows) != min(200, 501-offset) || resp.Header.Get("X-Total-Count") != "501" {
			t.Fatalf("分页须返回当前页与筛选后的总量: offset=%d rows=%d total=%q err=%v", offset, len(rows), resp.Header.Get("X-Total-Count"), err)
		}
		for _, row := range rows {
			if seen[row.ID.String()] {
				t.Fatal("分页顺序不稳定，重复返回待办")
			}
			seen[row.ID.String()] = true
		}
	}
	if len(seen) != 501 {
		t.Fatalf("分页漏掉待办: %d", len(seen))
	}
	for _, tc := range []struct {
		query, truncated string
		count            int
	}{
		{"limit=9999", "1", 500},
		{"limit=20&offset=500", "", 1},
		{"limit=20&offset=501", "", 0},
	} {
		resp, body := get(t, ts, "/api/findings?assetId="+busy.ID.String()+"&"+tc.query)
		if err := json.Unmarshal(body, &rows); resp.StatusCode != http.StatusOK || err != nil ||
			len(rows) != tc.count || resp.Header.Get("X-Total-Count") != "501" || resp.Header.Get("X-Truncated") != tc.truncated {
			t.Errorf("分页边界或截断标志错误: query=%s status=%d count=%d headers=%v err=%v", tc.query, resp.StatusCode, len(rows), resp.Header, err)
		}
	}
	resp, body := get(t, ts, "/api/findings?assetId="+secret.ID.String()+"&limit=1")
	if resp.Header.Get("X-Total-Count") != "0" || string(body) != "[]\n" {
		t.Errorf("总数同样不能泄露跨组待办: total=%s body=%s", resp.Header.Get("X-Total-Count"), body)
	}
	resp, body = get(t, ts, "/api/findings?ids="+old.ID.String()+","+secretFinding.ID.String())
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != 1 || rows[0].ID != old.ID || resp.Header.Get("X-Total-Count") != "1" {
		t.Errorf("会话引用必须按 ID 找到旧待办，不受最近 500 条限制: rows=%d total=%s err=%v", len(rows), resp.Header.Get("X-Total-Count"), err)
	}
	for _, ids := range []string{"", "invalid", strings.Repeat(old.ID.String()+",", 10) + old.ID.String()} {
		if resp, _ := get(t, ts, "/api/findings?ids="+ids); resp.StatusCode != 400 {
			t.Errorf("空、无效或超过 10 个 ID 的查询必须拒绝: status=%d", resp.StatusCode)
		}
	}
}

func TestAPIFindings(t *testing.T) {
	ctx, client := testdb.New(t)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	hA := client.Asset.Create().SetHostname("pve1").SetGroupID(gA.ID).SaveX(ctx)
	hB := client.Asset.Create().SetHostname("pve2").SetGroupID(gB.ID).SaveX(ctx)
	fA := client.Finding.Create().SetGroupID(gA.ID).SetAssetID(hA.ID).SetKey("disk").SetTitle("磁盘将满").SaveX(ctx)
	client.Finding.Create().SetGroupID(gB.ID).SetAssetID(hB.ID).SetKey("secret").SetTitle("B组秘密").SaveX(ctx)
	alice := client.User.Create().SetUsername("alice").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(alice.ID).SetRole("viewer").SaveX(ctx)

	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	admin := httptest.NewServer(asAdmin(h))
	t.Cleanup(admin.Close)
	viewer := httptest.NewServer(as(alice, h))
	t.Cleanup(viewer.Close)

	_, body := get(t, viewer, "/api/findings")
	var rows []findingRow
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != 1 || rows[0].Hostname != "pve1" || strings.Contains(string(body), "B组秘密") {
		t.Fatalf("待办越组或缺主机名：%s", body)
	}
	post := func(ts *httptest.Server, body string) int {
		resp, err := http.Post(ts.URL+"/api/findings/"+fA.ID.String()+"/status", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(viewer, `{"status":"ignored","note":"x"}`); code != http.StatusForbidden {
		t.Errorf("组内 viewer 不能改待办，得到 %d", code)
	}
	if code := post(admin, `{"status":"ignored"}`); code != http.StatusBadRequest {
		t.Errorf("忽略不写原因应 400，得到 %d", code)
	}
	if code := post(admin, `{"status":"ignored","note":"计划下线"}`); code != http.StatusNoContent {
		t.Fatalf("忽略应 204，得到 %d", code)
	}
	if f := client.Finding.GetX(ctx, fA.ID); f.Status != "ignored" || f.Note == nil || *f.Note != "计划下线" || f.ResolvedBy == nil {
		t.Errorf("忽略未落库：%+v", f)
	}
	if n := client.AuditLog.Query().Where(auditlog.ActionEQ("finding_status"), auditlog.DetailEQ("ignored 计划下线")).CountX(ctx); n != 1 {
		t.Errorf("忽略应落审计，得到 %d 条", n)
	}
	if code := post(admin, `{"status":"open"}`); code != http.StatusNoContent || client.Finding.GetX(ctx, fA.ID).Note != nil {
		t.Errorf("重开应清掉原因，得到 %d", code)
	}
	_, body = get(t, admin, "/api/findings?status=open")
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != 2 {
		t.Errorf("管理员应看到全部遗留待办：%s", body)
	}
}
