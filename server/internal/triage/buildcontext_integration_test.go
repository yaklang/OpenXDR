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
