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

	ts := httptest.NewServer(Handler(client, loadRules(t), t.TempDir(), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil, nil))
	t.Cleanup(ts.Close)
	return ts, inc.ID
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

	resp2, err := postJSON(ts, "/api/incidents/"+incID.String()+"/status", `{"status":"closed"}`)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 204 {
		t.Errorf("合法状态应 204，得到 %d", resp2.StatusCode)
	}

	resp3, err := postJSON(ts, "/api/incidents/"+uuid.New().String()+"/status", `{"status":"closed"}`)
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
