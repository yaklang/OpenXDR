//go:build integration

package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func TestAPIReportRender(t *testing.T) {
	ctx, client := testdb.New(t)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	session := client.AgentSession.Create().SetKind("task").SetGroupID(gA.ID).SetInitiator("system").SetModel("m").SaveX(ctx)
	session.Update().SetTitle("每日主机巡检").ExecX(ctx)
	rep := client.Report.Create().SetSessionID(session.ID).SetGroupID(gA.ID).SetTitle("日报").SetSummary("一切正常").SetLevel("ok").
		SetMarkdown("# 模型自写标题\n## 结论\n\n<script>alert(1)</script>").SaveX(ctx)
	bob := client.User.Create().SetUsername("bob").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gB.ID).SetUserID(bob.ID).SetRole("viewer").SaveX(ctx)

	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	admin := httptest.NewServer(asAdmin(h))
	t.Cleanup(admin.Close)
	other := httptest.NewServer(as(bob, h))
	t.Cleanup(other.Close)

	resp, body := get(t, admin, "/api/agent-reports/"+rep.ID.String()+"/html")
	// 页头由平台渲染：标题、级别、来源与一句话结论；正文里模型自写的一级标题去掉
	if resp.StatusCode != 200 || !strings.Contains(string(body), "<h1>日报</h1>") || !strings.Contains(string(body), "定时任务 · 每日主机巡检") ||
		!strings.Contains(string(body), "一切正常") || strings.Contains(string(body), "模型自写标题") || strings.Contains(string(body), "<script>") {
		t.Errorf("HTML 渲染不符：%d %s", resp.StatusCode, body)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("缺少 CSP：%q", csp)
	}
	if resp, _ := get(t, other, "/api/agent-reports/"+rep.ID.String()+"/html"); resp.StatusCode != 403 {
		t.Errorf("别组用户应 403，得到 %d", resp.StatusCode)
	}

	r, _ := postJSON(admin, "/api/users", `{"username":"system","password":"12345678","role":"viewer"}`)
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Errorf("system 用户名应保留，得到 %d", r.StatusCode)
	}
}

// 报告已读按人记：打开 HTML 或点开预览算看过，一个人看过不影响别人；全部标为已读只动本组
func TestAPIReportReads(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("A").SaveX(ctx)
	other := client.Group.Create().SetName("B").SaveX(ctx)
	session := client.AgentSession.Create().SetKind("chat").SetGroupID(g.ID).SetInitiator("alice").SetModel("m").SaveX(ctx)
	r1 := client.Report.Create().SetSessionID(session.ID).SetGroupID(g.ID).SetTitle("一").SetMarkdown("## 结论").SaveX(ctx)
	r2 := client.Report.Create().SetSessionID(session.ID).SetGroupID(g.ID).SetTitle("二").SetMarkdown("## 结论").SaveX(ctx)
	elsewhere := client.Report.Create().SetSessionID(session.ID).SetGroupID(other.ID).SetTitle("别组").SetMarkdown("## 结论").SaveX(ctx)
	users := map[string]*httptest.Server{}
	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	for _, name := range []string{"alice", "carol"} {
		u := client.User.Create().SetUsername(name).SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
		client.GroupMember.Create().SetGroupID(g.ID).SetUserID(u.ID).SetRole("viewer").SaveX(ctx)
		users[name] = httptest.NewServer(as(u, h))
		t.Cleanup(users[name].Close)
	}
	read := func(who string) map[string]bool {
		t.Helper()
		_, body := get(t, users[who], "/api/agent-reports?groupId="+g.ID.String())
		var rows []struct {
			Title string `json:"title"`
			Read  bool   `json:"read"`
		}
		if err := json.Unmarshal(body, &rows); err != nil {
			t.Fatal(err, string(body))
		}
		out := map[string]bool{}
		for _, r := range rows {
			out[r.Title] = r.Read
		}
		return out
	}
	if got := read("alice"); got["一"] || got["二"] {
		t.Fatalf("新报告应未读：%v", got)
	}
	if resp, _ := get(t, users["alice"], "/api/agent-reports/"+r1.ID.String()+"/html"); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if got := read("alice"); !got["一"] || got["二"] {
		t.Errorf("打开 HTML 应只标这一份：%v", got)
	}
	if got := read("carol"); got["一"] {
		t.Errorf("alice 看过不影响 carol：%v", got)
	}
	for i := 0; i < 2; i++ { // 重复标记无害
		if r, _ := postJSON(users["carol"], "/api/agent-reports/"+r2.ID.String()+"/read", ""); r.StatusCode != 204 {
			t.Fatalf("标记已读应 204，得到 %d", r.StatusCode)
		}
	}
	if got := read("carol"); !got["二"] || got["一"] {
		t.Errorf("点开预览应只标这一份：%v", got)
	}
	if r, _ := postJSON(users["carol"], "/api/agent-reports/"+elsewhere.ID.String()+"/read", ""); r.StatusCode != 403 {
		t.Errorf("别组报告不能标，得到 %d", r.StatusCode)
	}
	if r, _ := postJSON(users["carol"], "/api/agent-reports/read?groupId="+g.ID.String(), ""); r.StatusCode != 204 {
		t.Fatalf("全部已读应 204，得到 %d", r.StatusCode)
	}
	if got := read("carol"); !got["一"] || !got["二"] {
		t.Errorf("全部标为已读后都应已读：%v", got)
	}
	if n := client.ReportRead.Query().CountX(ctx); n != 3 {
		t.Errorf("alice 1 份、carol 2 份，应共 3 条记录，得到 %d", n)
	}
}
