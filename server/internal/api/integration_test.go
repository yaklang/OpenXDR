//go:build integration

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

var oneRuleYaml = `
id: 6e0c8f0e-9a44-4b4d-9b6e-1f2a5d9c8b7a
title: Sample Rule
logsource:
  category: application
detection:
  selection:
    message|contains: 'failed'
  condition: selection
`

func loadRules(t *testing.T) *sigma.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yml"), []byte(oneRuleYaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return sigma.LoadDir(dir)
}

// 准备一个 incident + 一条带 event 的告警 + 一个资产。
func seed(t *testing.T) (*httptest.Server, uuid.UUID) {
	t.Helper()
	ctx, client := testdb.New(t)

	asset, err := client.Asset.Create().SetHostname("web01").SetOs("linux").
		SetIPAddrs([]string{"10.0.0.5"}).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	evt, err := client.Event.Create().
		SetTs(time.Now()).SetClassUID(100001).SetSource("syslog").
		SetRaw(json.RawMessage(`{"message":"ssh failed"}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inc, err := client.Incident.Create().
		SetStatus("open").SetTitle("SSH brute force").
		SetGraph(json.RawMessage(`{"nodes":[]}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(time.Now()).SetRuleID("6e0c8f0e-9a44-4b4d-9b6e-1f2a5d9c8b7a").
		SetSeverity(4).SetEventID(evt.ID).SetIncidentID(inc.ID).
		SetNillableAssetID(&asset.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(asAdmin(Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)))
	t.Cleanup(ts.Close)
	return ts, inc.ID
}

// asAdmin 测试绕开登录中间件，直接以全局 admin 身份访问。
func asAdmin(h http.Handler) http.Handler { return as(&ent.User{Username: "admin", Role: "admin"}, h) }

func as(u *ent.User, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
	})
}

func get(t *testing.T, ts *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func postJSON(ts *httptest.Server, path, body string) (*http.Response, error) {
	req, err := http.NewRequest("POST", ts.URL+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

// GET /api/incidents 列出 incident，带告警计数。
func TestAPIGetIncidents(t *testing.T) {
	ts, incID := seed(t)
	resp, body := get(t, ts, "/api/incidents")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var list []map[string]any
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("期望 1 个 incident，实际 %d", len(list))
	}
	it := list[0]
	if it["id"] != incID.String() || it["status"] != "open" {
		t.Errorf("incident 摘要不符: %v", it)
	}
	if n, _ := it["alertCount"].(float64); n != 1 {
		t.Errorf("alertCount = %v, want 1", it["alertCount"])
	}
}

// GET /api/incidents 分页：unresolved 合并 open+triaged，X-Total-Count 是分页前总数，
// groupId 取第一条有资产的告警所在组。
func TestAPIIncidentsPaging(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("A").SaveX(ctx)
	grouped := client.Asset.Create().SetHostname("a1").SetGroupID(g.ID).SaveX(ctx)
	loose := client.Asset.Create().SetHostname("loose").SaveX(ctx)
	now := time.Now()
	var incs []*ent.Incident
	for i, status := range []string{"open", "triaged", "closed", "open"} {
		incs = append(incs, client.Incident.Create().SetStatus(status).SetGraph(json.RawMessage(`{}`)).
			SetCreatedAt(now.Add(time.Duration(i)*time.Minute)).SaveX(ctx))
	}
	// incs[0]：无资产告警最早，其次是有组资产，最后是未分组资产 → 取有组资产的组
	client.Alert.Create().SetTs(now).SetRuleID("r").SetSeverity(1).SetIncidentID(incs[0].ID).SaveX(ctx)
	client.Alert.Create().SetTs(now.Add(time.Second)).SetRuleID("r").SetSeverity(1).
		SetAssetID(grouped.ID).SetIncidentID(incs[0].ID).SaveX(ctx)
	client.Alert.Create().SetTs(now.Add(2 * time.Second)).SetRuleID("r").SetSeverity(1).
		SetAssetID(loose.ID).SetIncidentID(incs[0].ID).SaveX(ctx)
	// incs[1]：第一条有资产的告警在未分组资产上 → groupId 为空
	client.Alert.Create().SetTs(now).SetRuleID("r").SetSeverity(1).
		SetAssetID(loose.ID).SetIncidentID(incs[1].ID).SaveX(ctx)
	client.Alert.Create().SetTs(now.Add(time.Second)).SetRuleID("r").SetSeverity(1).
		SetAssetID(grouped.ID).SetIncidentID(incs[1].ID).SaveX(ctx)

	ts := httptest.NewServer(asAdmin(Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)))
	t.Cleanup(ts.Close)
	list := func(path string) ([]incidentSummary, string) {
		t.Helper()
		resp, body := get(t, ts, path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s status = %d", path, resp.StatusCode)
		}
		var out []incidentSummary
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out, resp.Header.Get("X-Total-Count")
	}

	if got, total := list("/api/incidents?status=unresolved"); len(got) != 3 || total != "3" {
		t.Errorf("unresolved 应含 3 个 open/triaged，得到 %d 个，总数 %s", len(got), total)
	}
	got, total := list("/api/incidents?status=unresolved&limit=1&offset=1")
	if len(got) != 1 || total != "3" || got[0].ID != incs[1].ID {
		t.Errorf("第二页应只有 incs[1]，总数 3，得到 %v 总数 %s", got, total)
	}
	if got, total := list("/api/incidents?limit=0"); len(got) != 1 || total != "4" {
		t.Errorf("limit 下限应夹到 1，得到 %d 个，总数 %s", len(got), total)
	}

	byID := map[uuid.UUID]*uuid.UUID{}
	all, _ := list("/api/incidents")
	for _, inc := range all {
		byID[inc.ID] = inc.GroupID
	}
	if gid := byID[incs[0].ID]; gid == nil || *gid != g.ID {
		t.Errorf("incs[0] groupId 应为组 A，得到 %v", gid)
	}
	if gid := byID[incs[1].ID]; gid != nil {
		t.Errorf("incs[1] 第一条有资产告警在未分组资产上，groupId 应为空，得到 %v", gid)
	}

	_, body := get(t, ts, "/api/incidents/"+incs[0].ID.String())
	var detail incidentDetail
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.GroupID == nil || *detail.GroupID != g.ID {
		t.Errorf("详情 groupId 应为组 A，得到 %v", detail.GroupID)
	}
}

// status=review 与 stats.reviewIncidents 同一口径：未结案，且 AI 没判良性或最高级别达到高危。
func TestAPIIncidentsReview(t *testing.T) {
	ctx, client := testdb.New(t)
	cases := []struct {
		status, verdict string
		severity        int16
		review          bool
	}{
		{"open", "", 1, true},
		{"triaged", `{"verdict":"suspicious"}`, 1, true},
		{"triaged", `{"verdict":"benign"}`, 3, false},
		{"triaged", `{"verdict":"benign"}`, 4, true},
		{"open", `{"confidence":3}`, 1, true},
		{"closed", `{"verdict":"malicious"}`, 5, false},
	}
	want := map[uuid.UUID]bool{}
	for _, c := range cases {
		create := client.Incident.Create().SetStatus(c.status).SetGraph(json.RawMessage(`{}`))
		if c.verdict != "" {
			create.SetAiVerdict(json.RawMessage(c.verdict))
		}
		inc := create.SaveX(ctx)
		client.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(1).SetIncidentID(inc.ID).SaveX(ctx)
		client.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(c.severity).SetIncidentID(inc.ID).SaveX(ctx)
		if c.review {
			want[inc.ID] = true
		}
	}
	ts := httptest.NewServer(asAdmin(Handler(client, nil, loadRules(t), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil)))
	t.Cleanup(ts.Close)

	resp, body := get(t, ts, "/api/incidents?status=review")
	var got []incidentSummary
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) || resp.Header.Get("X-Total-Count") != "4" {
		t.Fatalf("需复核应为 4 个，得到 %d 个，总数 %s", len(got), resp.Header.Get("X-Total-Count"))
	}
	for _, inc := range got {
		if !want[inc.ID] {
			t.Errorf("%s 不该进复核清单", inc.ID)
		}
	}
	_, body = get(t, ts, "/api/stats")
	var stats struct {
		ReviewIncidents int `json:"reviewIncidents"`
	}
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatal(err)
	}
	if stats.ReviewIncidents != 4 {
		t.Errorf("reviewIncidents 应为 4，得到 %d", stats.ReviewIncidents)
	}
}

// GET /api/incidents/{id} 返回图、告警明细、规则标题与事件原文。
func TestAPIGetIncidentDetail(t *testing.T) {
	ts, incID := seed(t)
	resp, body := get(t, ts, "/api/incidents/"+incID.String())
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var detail map[string]any
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatal(err)
	}
	alerts, _ := detail["alerts"].([]any)
	if len(alerts) != 1 {
		t.Fatalf("alerts 应为 1 条，实际 %d", len(alerts))
	}
	al := alerts[0].(map[string]any)
	if al["ruleTitle"] != "Sample Rule" {
		t.Errorf("ruleTitle = %v, want Sample Rule", al["ruleTitle"])
	}
	evt, _ := al["event"].(map[string]any)
	if evt["message"] != "ssh failed" {
		t.Errorf("event 原文不符: %v", al["event"])
	}
}

// 状态流转：非法状态 400、合法 204、不存在 404。
func TestAPIStatusUpdate(t *testing.T) {
	ts, incID := seed(t)

	resp, err := postJSON(ts, "/api/incidents/"+incID.String()+"/status", `{"status":"triaged"}`)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("非法状态应 400，得到 %d", resp.StatusCode)
	}

	bare, err := postJSON(ts, "/api/incidents/"+incID.String()+"/status", `{"status":"closed","note":"  "}`)
	if err != nil {
		t.Fatal(err)
	}
	bare.Body.Close()
	if bare.StatusCode != 400 {
		t.Errorf("结案不写备注应 400，得到 %d", bare.StatusCode)
	}

	resp2, err := postJSON(ts, "/api/incidents/"+incID.String()+"/status", `{"status":"closed","note":"已隔离并重装"}`)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 204 {
		t.Errorf("合法状态应 204，得到 %d", resp2.StatusCode)
	}
	_, raw := get(t, ts, "/api/incidents/"+incID.String())
	if body := string(raw); !strings.Contains(body, `"resolution":"已隔离并重装"`) || !strings.Contains(body, `"resolvedBy":`) {
		t.Errorf("结案信息未落库：%s", raw)
	}
	reopen, err := postJSON(ts, "/api/incidents/"+incID.String()+"/status", `{"status":"open"}`)
	if err != nil {
		t.Fatal(err)
	}
	reopen.Body.Close()
	if _, raw = get(t, ts, "/api/incidents/"+incID.String()); reopen.StatusCode != 204 || !strings.Contains(string(raw), `"resolution":null`) {
		t.Errorf("重开应清掉结案信息：%d %s", reopen.StatusCode, raw)
	}

	resp3, err := postJSON(ts, "/api/incidents/"+uuid.New().String()+"/status", `{"status":"closed","note":"x"}`)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 404 {
		t.Errorf("不存在 incident 应 404，得到 %d", resp3.StatusCode)
	}
}

// 无效 id 应 400。
func TestAPIBadID(t *testing.T) {
	ts, _ := seed(t)
	resp, _ := get(t, ts, "/api/incidents/not-a-uuid")
	if resp.StatusCode != 400 {
		t.Errorf("无效 id 应 400，得到 %d", resp.StatusCode)
	}
}

// 资产列表。
func TestAPIGetAssets(t *testing.T) {
	ts, _ := seed(t)
	resp, body := get(t, ts, "/api/assets")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var assets []map[string]any
	if err := json.Unmarshal(body, &assets); err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0]["hostname"] != "web01" {
		t.Errorf("资产列表不符: %v", assets)
	}
}

// GET /api/incidents/{id}/report 导出 Markdown：带附件头，内容含告警明细。
func TestAPIIncidentReport(t *testing.T) {
	ts, incID := seed(t)
	resp, body := get(t, ts, "/api/incidents/"+incID.String()+"/report")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("Content-Type 应为 markdown，实际 %s", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, ".md") {
		t.Errorf("应带附件下载头，实际 %s", cd)
	}
	md := string(body)
	for _, want := range []string{
		"# 安全事件报告：SSH brute force",
		"## 研判结论",
		"## 告警时间线",
		"Sample Rule", // 规则标题而非裸 UUID
		"ssh failed",  // 证据取自原始事件
		"## 处置记录",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("报告缺少 %q\n---\n%s", want, md)
		}
	}
}

// 不存在的 incident 返回 404，不是 500
func TestAPIReportNotFound(t *testing.T) {
	ts, _ := seed(t)
	resp, _ := get(t, ts, "/api/incidents/"+uuid.New().String()+"/report")
	if resp.StatusCode != 404 {
		t.Errorf("应返回 404，实际 %d", resp.StatusCode)
	}
}
