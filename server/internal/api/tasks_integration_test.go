//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/agentchat"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func TestAPITasks(t *testing.T) {
	ctx, client := testdb.New(t)
	client.Task.Create().SetID("daily").SetName("巡检").SetSchedule("0 2 * * *").SetPrompt("x").SaveX(ctx)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	sess := client.AgentSession.Create().SetKind("task").SetGroupID(gA.ID).SetInitiator("system").SetModel("m").SetStatus("idle").SaveX(ctx)
	for i, role := range []string{"assistant", "toolResult", "toolResult", "assistant"} {
		client.SessionMessage.Create().SetSessionID(sess.ID).SetSeq(i + 1).SetRole(role).SetContent(json.RawMessage(`{}`)).SaveX(ctx)
	}
	client.Report.Create().SetSessionID(sess.ID).SetGroupID(gA.ID).SetTitle("每日巡检报告").SetMarkdown("m").SaveX(ctx)
	client.TaskRun.Create().SetTaskID("daily").SetGroupID(gA.ID).SetSessionID(sess.ID).SaveX(ctx)
	client.TaskRun.Create().SetTaskID("daily").SetGroupID(gB.ID).SaveX(ctx)
	// 模型没在时限内交报告、平台出了保底报告的一轮：运行记录标 partial
	partial := client.AgentSession.Create().SetKind("task").SetGroupID(gA.ID).SetInitiator("system").SetModel("m").
		SetStatus("succeeded").SetError(agentchat.PartialNote).SaveX(ctx)
	client.TaskRun.Create().SetTaskID("daily").SetGroupID(gA.ID).SetSessionID(partial.ID).SetStatus("succeeded").SetStartedAt(time.Now().Add(-time.Hour)).SaveX(ctx)
	alice := client.User.Create().SetUsername("alice").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(alice.ID).SetRole("viewer").SaveX(ctx)

	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	admin := httptest.NewServer(asAdmin(h))
	t.Cleanup(admin.Close)
	viewer := httptest.NewServer(as(alice, h))
	t.Cleanup(viewer.Close)

	patch := func(body string) int {
		req, _ := http.NewRequest("PATCH", admin.URL+"/api/tasks/daily", strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := patch(`{"customSchedule":"every day"}`); code != 400 {
		t.Errorf("坏 cron 应 400，得到 %d", code)
	}
	if code := patch(`{"enabled":false,"customSchedule":"*/30 * * * *"}`); code != 200 {
		t.Fatalf("改任务应 200，得到 %d", code)
	}
	if task := client.Task.GetX(ctx, "daily"); task.Enabled || task.CustomSchedule == nil {
		t.Errorf("启停与周期未生效：%+v", task)
	}
	if code := patch(`{"customSchedule":""}`); code != 200 || client.Task.GetX(ctx, "daily").CustomSchedule != nil {
		t.Errorf("空串应恢复 YAML 周期")
	}

	run := func() int {
		resp, err := http.Post(admin.URL+"/api/tasks/daily/run", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := run(); code != http.StatusConflict {
		t.Errorf("停用的任务立即运行应 409，得到 %d", code)
	}
	patch(`{"enabled":true}`)
	if code := run(); code != http.StatusAccepted || client.Task.GetX(ctx, "daily").RunRequestedAt == nil {
		t.Errorf("立即运行应记下请求时间，得到 %d", code)
	}

	client.Task.Create().SetID("only-a").SetName("A任务").SetSchedule("0 2 * * *").SetTargetGroup("A").SetPrompt("A指令").SaveX(ctx)
	client.Task.Create().SetID("only-b").SetName("B任务").SetSchedule("0 2 * * *").SetTargetGroup("B").SetPrompt("B秘密指令").SaveX(ctx)
	_, definitions := get(t, viewer, "/api/tasks")
	var tasks []taskRow
	if err := json.Unmarshal(definitions, &tasks); err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 2 || strings.Contains(string(definitions), "B秘密指令") {
		t.Fatalf("任务定义越组: %s", definitions)
	}
	nobody := client.User.Create().SetUsername("nobody").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	empty := httptest.NewServer(as(nobody, h))
	defer empty.Close()
	_, definitions = get(t, empty, "/api/tasks")
	if string(definitions) != "[]\n" {
		t.Fatalf("无组用户不应读取任务: %s", definitions)
	}
	_, definitions = get(t, admin, "/api/tasks")
	if err := json.Unmarshal(definitions, &tasks); err != nil || len(tasks) != 3 {
		t.Fatalf("管理员应看到全部任务: %s", definitions)
	}
	_, body := get(t, viewer, "/api/tasks/daily/runs")
	var runs []taskRunRow
	if err := json.Unmarshal(body, &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].GroupID != gA.ID || runs[1].GroupID != gA.ID {
		t.Fatalf("运行记录应只见 A 组：%+v", runs)
	}
	if r := runs[0]; r.Steps != 2 || r.ReportTitle == nil || *r.ReportTitle != "每日巡检报告" || r.Partial {
		t.Errorf("运行记录应带步数与报告：%+v", r)
	}
	if !runs[1].Partial {
		t.Errorf("保底报告的一轮应标 partial：%+v", runs[1])
	}
	_, body = get(t, viewer, "/api/tasks")
	var listed []taskRow
	if err := json.Unmarshal(body, &listed); err != nil || len(listed) == 0 {
		t.Fatalf("任务列表：%s", body)
	}
	for _, task := range listed {
		if task.NextRun == nil || task.NextRun.Before(time.Now()) {
			t.Errorf("启用的任务应带下一次运行时间：%+v", task)
		}
		// 按组错峰：只给看得到的组，且就是 NextRun
		if next, ok := task.NextRuns[gA.ID.String()]; len(task.NextRuns) != 1 || !ok || !next.Equal(*task.NextRun) {
			t.Errorf("下次运行时间应只含本组且按偏移计算：%+v", task.NextRuns)
		}
	}
}

// 按组开关：组管理员能开关本组，别的组与组内 viewer 不行；列表只回显看得到的组；
// 全局关闭但有组开启的任务可以立即运行
func TestAPITaskGroups(t *testing.T) {
	ctx, client := testdb.New(t)
	client.Task.Create().SetID("cert").SetName("证书").SetSchedule("0 2 * * *").SetPrompt("x").SetEnabled(false).SaveX(ctx)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	bob := client.User.Create().SetUsername("bob").SetPasswordHash("x").SetRole("analyst").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(bob.ID).SetRole("admin").SaveX(ctx)
	alice := client.User.Create().SetUsername("alice").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(alice.ID).SetRole("viewer").SaveX(ctx)

	h := Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)
	admin := httptest.NewServer(asAdmin(h))
	t.Cleanup(admin.Close)
	groupAdmin := httptest.NewServer(as(bob, h))
	t.Cleanup(groupAdmin.Close)
	viewer := httptest.NewServer(as(alice, h))
	t.Cleanup(viewer.Close)

	put := func(srv *httptest.Server, group, body string) int {
		req, _ := http.NewRequest("PUT", srv.URL+"/api/tasks/cert/groups/"+group, strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := put(groupAdmin, gA.ID.String(), `{"enabled":true}`); code != 200 {
		t.Fatalf("组管理员开启本组应 200，得到 %d", code)
	}
	if code := put(groupAdmin, gB.ID.String(), `{"enabled":true}`); code != 403 {
		t.Errorf("开启别的组应 403，得到 %d", code)
	}
	if code := put(viewer, gA.ID.String(), `{"enabled":false}`); code != 403 {
		t.Errorf("组内 viewer 应 403，得到 %d", code)
	}
	if code := put(admin, gB.ID.String(), `{"enabled":false}`); code != 200 {
		t.Fatalf("平台 admin 应能设置任意组，得到 %d", code)
	}
	if got := client.Task.GetX(ctx, "cert").GroupEnabled; !got[gA.ID.String()] || got[gB.ID.String()] || len(got) != 2 {
		t.Errorf("按组开关未落库：%v", got)
	}

	var rows []struct {
		ID           string          `json:"id"`
		GroupEnabled map[string]bool `json:"groupEnabled"`
		NextRun      *time.Time      `json:"nextRun"`
	}
	_, body := get(t, groupAdmin, "/api/tasks")
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) != 1 {
		t.Fatalf("任务列表：%s %v", body, err)
	}
	if _, leaked := rows[0].GroupEnabled[gB.ID.String()]; leaked || !rows[0].GroupEnabled[gA.ID.String()] || rows[0].NextRun == nil {
		t.Errorf("只应回显本组开关且有下次运行时间：%+v", rows[0])
	}

	if code := put(admin, gA.ID.String(), `{"enabled":null}`); code != 200 {
		t.Fatal(code)
	}
	if _, ok := client.Task.GetX(ctx, "cert").GroupEnabled[gA.ID.String()]; ok {
		t.Error("null 应恢复跟随全局")
	}
	resp, err := http.Post(admin.URL+"/api/tasks/cert/run", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("所有组都关闭时立即运行应 409，得到 %d", resp.StatusCode)
	}
	put(admin, gA.ID.String(), `{"enabled":true}`)
	if resp, _ = http.Post(admin.URL+"/api/tasks/cert/run", "", nil); resp.StatusCode != http.StatusAccepted {
		t.Errorf("有组开启时应能立即运行，得到 %d", resp.StatusCode)
	}
	resp.Body.Close()
}
