//go:build integration

package triage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

// buildContext 生成给 LLM 的研判上下文：标题、图、按时间排序的告警明细，
// 超长事件原文截断。
func TestBuildContext(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()

	// 超长事件原文（>500，应截断加省略号）
	longRaw := json.RawMessage(`{"process":{"name":"` + strings.Repeat("x", 600) + `"}}`)
	evt1, err := client.Event.Create().
		SetTs(now.Add(-2 * time.Minute)).SetClassUID(1007).SetSource("agent").
		SetRaw(longRaw).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	evt2, err := client.Event.Create().
		SetTs(now.Add(-time.Minute)).SetClassUID(1007).SetSource("agent").
		SetRaw(json.RawMessage(`{"process":{"name":"parent.exe"}}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	title := "SSH brute force"
	inc, err := client.Incident.Create().
		SetStatus("open").SetTitle(title).SetGraph(json.RawMessage(`{"nodes":[]}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(now).SetRuleID("r-loud").SetSeverity(4).SetCount(3).
		SetEventID(evt1.ID).SetIncidentID(inc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(now).SetRuleID("r-quiet").SetSeverity(2).
		SetEventID(evt2.ID).SetIncidentID(inc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}

	e := &Engine{DB: client}
	out, err := e.buildContext(ctx, inc)
	if err != nil {
		t.Fatalf("buildContext 失败: %v", err)
	}
	for _, want := range []string{
		title,          // 标题
		`{"nodes":[]}`, // 图
		"r-loud", "r-quiet", "severity=4", "count=3",
		"parent.exe", // 未截断事件原文
		"…",          // 超长事件截断标记
	} {
		if !strings.Contains(out, want) {
			t.Errorf("上下文缺少 %q，实际:\n%s", want, out)
		}
	}
}

// 同规则的历史误报案例应回流进上下文；无案例时不加该段落。
func TestBuildContextFalsePositiveHistory(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()

	// 历史：r-noisy 所在 incident 被判误报
	fpTitle := "扫描器噪声"
	fpInc, err := client.Incident.Create().
		SetStatus("false_positive").SetTitle(fpTitle).
		SetGraph(json.RawMessage(`{}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(now.Add(-24 * time.Hour)).SetRuleID("r-noisy").SetSeverity(3).
		SetIncidentID(fpInc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}

	// 当前：同一规则的新 incident
	inc, err := client.Incident.Create().
		SetStatus("open").SetTitle("新事件").SetGraph(json.RawMessage(`{}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(now).SetRuleID("r-noisy").SetSeverity(3).
		SetIncidentID(inc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}

	e := &Engine{DB: client}
	out, err := e.buildContext(ctx, inc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "历史误报参考") || !strings.Contains(out, fpTitle) {
		t.Errorf("上下文应包含历史误报案例：\n%s", out)
	}

	// 无历史案例的规则不该出现该段落
	inc2, err := client.Incident.Create().
		SetStatus("open").SetTitle("另一事件").SetGraph(json.RawMessage(`{}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(now).SetRuleID("r-clean").SetSeverity(3).
		SetIncidentID(inc2.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	out2, err := e.buildContext(ctx, inc2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out2, "历史误报参考") {
		t.Errorf("无案例时不该有误报参考段落：\n%s", out2)
	}
}
