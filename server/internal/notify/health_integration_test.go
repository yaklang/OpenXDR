//go:build integration

package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

func oldIncident(ctx context.Context, t *testing.T, client *ent.Client, status, verdict string, severity int16) *ent.Incident {
	t.Helper()
	c := client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus(status).SetCreatedAt(time.Now().Add(-time.Hour))
	if verdict != "" {
		c.SetAiVerdict(json.RawMessage(`{"verdict":"` + verdict + `"}`))
	}
	inc, err := c.Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(severity).SetIncidentID(inc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	return inc
}

// 推送目标为空：需人工处理的积压照数，状态 unconfigured；良性低危、新建未满宽限、已推送的不算
func TestHealthUnconfigured(t *testing.T) {
	ctx, client := testdb.New(t)
	s := &Settings{DB: client}

	oldIncident(ctx, t, client, "triaged", "malicious", 3)
	oldIncident(ctx, t, client, "triaged", "benign", 4) // 高危良性仍需复核
	oldIncident(ctx, t, client, "triaged", "benign", 2) // 良性低危不推
	oldIncident(ctx, t, client, "closed", "malicious", 5)
	pushed := oldIncident(ctx, t, client, "open", "", 5)
	if err := client.Incident.UpdateOneID(pushed.ID).SetNotifiedAt(time.Now()).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus("open").Save(ctx); err != nil {
		t.Fatal(err) // 刚建的还在宽限期
	}

	h, err := s.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != "unconfigured" || h.PendingIncidents != 2 {
		t.Fatalf("应为 unconfigured 且积压 2，got %+v", h)
	}
	expectGauge(t, s, "openxdr_notify_pending_incidents", "需人工处理、创建超过 15 分钟仍未推送的事件数", 2)
	expectGauge(t, s, "openxdr_notify_configured", "通知推送目标是否已配置（1 已配置，0 未配置）", 0)

	// 推送门槛把低于它的排除，与 sweep 静默落标记同口径
	s.Default = Target{URL: "http://x", MinSeverity: 4}
	if h, _ = s.Health(ctx); h.Status != "ok" || h.PendingIncidents != 1 {
		t.Fatalf("门槛 4 时只剩高危良性 1 件，got %+v", h)
	}
}

// 连续失败到阈值变 failing 并留下原因；一次成功清零；换推送地址也清零
func TestHealthFailuresAndRecovery(t *testing.T) {
	ctx, client := testdb.New(t)
	fail := true
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	t.Cleanup(hook.Close)
	s := &Settings{DB: client, Default: Target{URL: hook.URL, Format: "generic"}}
	n := &Notifier{DB: client, Settings: s, Client: hook.Client(), start: time.Now().Add(-2 * time.Hour)}
	oldIncident(ctx, t, client, "triaged", "malicious", 5)

	for range FailingAfter {
		if err := n.sweep(ctx); err != nil {
			t.Fatal(err)
		}
	}
	h, err := s.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != "failing" || h.ConsecutiveFailures != FailingAfter || h.PendingIncidents != 1 ||
		h.LastFailureAt == nil || !strings.Contains(h.LastError, "502") || h.LastSuccessAt != nil {
		t.Fatalf("连续失败后应为 failing，got %+v", h)
	}
	expectGauge(t, s, "openxdr_notify_consecutive_failures", "通知连续发送失败次数，成功一次清零", FailingAfter)

	fail = false
	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if h, _ = s.Health(ctx); h.Status != "ok" || h.ConsecutiveFailures != 0 || h.LastSuccessAt == nil || h.PendingIncidents != 0 {
		t.Fatalf("成功一次应清零且积压推完，got %+v", h)
	}

	// Webhook.Send 同样计入；换地址后旧渠道的失败不再算
	fail = true
	w := &Webhook{Settings: s, Client: hook.Client()}
	for range FailingAfter {
		_ = w.Send(ctx, "任务失败", "x", "")
	}
	if h, _ = s.Health(ctx); h.Status != "failing" {
		t.Fatalf("Webhook.Send 失败也应计入，got %+v", h)
	}
	if err := s.Save(ctx, Target{URL: hook.URL + "/new", Format: "generic"}); err != nil {
		t.Fatal(err)
	}
	if h, _ = s.Health(ctx); h.Status != "ok" || h.ConsecutiveFailures != 0 || h.LastFailureAt == nil {
		t.Fatalf("换地址应清零连续失败、保留历史时间，got %+v", h)
	}
}

// expectGauge 看门狗收集器里某个指标的值
func expectGauge(t *testing.T, s *Settings, name, help string, want int) {
	t.Helper()
	exp := fmt.Sprintf("# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, want)
	if err := testutil.CollectAndCompare(NewHealthCollector(s), strings.NewReader(exp), name); err != nil {
		t.Error(err)
	}
}
