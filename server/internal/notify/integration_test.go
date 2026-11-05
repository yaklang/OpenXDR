//go:build integration

package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/incident"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/testdb"
)

// 一次 sweep 的端到端行为：该推的推、benign 静默落标记、失败的下轮重试。
func TestSweep(t *testing.T) {
	ctx, client := testdb.New(t)

	var received []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = append(received, string(body))
	}))
	t.Cleanup(hook.Close)

	n := &Notifier{
		DB: client, Settings: &Settings{DB: client, Default: Target{URL: hook.URL, Format: "generic", LinkBase: "http://console"}},
		WaitTriage: func() bool { return true },
		Client:     hook.Client(),
		start:      time.Now().Add(-time.Minute),
	}

	title := "恶意进程链"
	bad, err := client.Incident.Create().
		SetGraph(json.RawMessage(`{}`)).SetStatus("triaged").SetTitle(title).
		SetAiVerdict(json.RawMessage(`{"verdict":"malicious","confidence":88,"summary":"s"}`)).
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	benign, err := client.Incident.Create().
		SetGraph(json.RawMessage(`{}`)).SetStatus("triaged").
		SetAiVerdict(json.RawMessage(`{"verdict":"benign"}`)).SetTriagedAt(time.Now()).
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := client.Incident.Create().
		SetGraph(json.RawMessage(`{}`)).SetStatus("open").
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := incidentwork.Refresh(ctx, client, client.Incident.GetX(ctx, benign.ID), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}

	if len(received) != 1 {
		t.Fatalf("应只推送 1 条，got %d", len(received))
	}
	var msg Message
	if err := json.Unmarshal([]byte(received[0]), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.IncidentID != bad.ID.String() || msg.Verdict != "malicious" || msg.Link == "" {
		t.Fatalf("推送内容不对：%+v", msg)
	}

	// 恶意与良性都应落投递标记，未研判的保持待投递
	for _, c := range []struct {
		name     string
		id       uuid.UUID
		notified bool
	}{
		{"恶意已推送", bad.ID, true},
		{"良性静默标记", benign.ID, true},
		{"未研判待投递", waiting.ID, false},
	} {
		inc, err := client.Incident.Query().Where(incident.IDEQ(c.id)).Only(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if (inc.NotifiedAt != nil) != c.notified {
			t.Errorf("%s: notified_at=%v", c.name, inc.NotifiedAt)
		}
	}
}

// webhook 挂掉时不落标记，恢复后重试成功。
func TestSweepRetries(t *testing.T) {
	for _, format := range []string{"generic", "wecom"} {
		t.Run(format, func(t *testing.T) { testSweepRetries(t, format) })
	}
}

func testSweepRetries(t *testing.T, format string) {
	ctx, client := testdb.New(t)

	fail := true
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			if format == "generic" {
				w.WriteHeader(http.StatusBadGateway)
			} else {
				_, _ = w.Write([]byte(`{"errcode":93000}`))
			}
			return
		}
		_, _ = w.Write([]byte(`{"errcode":0}`))
	}))
	t.Cleanup(hook.Close)

	n := &Notifier{
		DB: client, Settings: &Settings{DB: client, Default: Target{URL: hook.URL, Format: format}},
		Client: hook.Client(), start: time.Now().Add(-time.Minute),
	}
	inc, err := client.Incident.Create().
		SetGraph(json.RawMessage(`{}`)).SetStatus("open").
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := client.Incident.Query().Where(incident.IDEQ(inc.ID)).Only(ctx)
	if got.NotifiedAt != nil {
		t.Fatal("推送失败不应落投递标记")
	}

	fail = false
	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ = client.Incident.Query().Where(incident.IDEQ(inc.ID)).Only(ctx)
	if got.NotifiedAt == nil {
		t.Fatal("恢复后重试应成功落标记")
	}
}

// 低于 MinSeverity 的事件静默落标记，不打扰人。
func TestSweepMinSeverity(t *testing.T) {
	ctx, client := testdb.New(t)

	var received int
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received++
	}))
	t.Cleanup(hook.Close)

	n := &Notifier{
		DB: client, Settings: &Settings{DB: client, Default: Target{URL: hook.URL, Format: "generic", MinSeverity: 4}},
		Client: hook.Client(), start: time.Now().Add(-time.Minute),
	}

	low, err := client.Incident.Create().
		SetGraph(json.RawMessage(`{}`)).SetStatus("open").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(time.Now()).SetRuleID("r-low").SetSeverity(2).
		SetIncidentID(low.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	high, err := client.Incident.Create().
		SetGraph(json.RawMessage(`{}`)).SetStatus("open").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(time.Now()).SetRuleID("r-high").SetSeverity(5).
		SetIncidentID(high.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}

	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if received != 1 {
		t.Fatalf("只有高危应被推送，实际推了 %d 条", received)
	}
	// 低危也要落标记，不能每轮都重新评估
	got, _ := client.Incident.Query().Where(incident.IDEQ(low.ID)).Only(ctx)
	if got.NotifiedAt == nil {
		t.Fatal("低于阈值的事件应静默落标记")
	}
}

// 控制台保存的目标覆盖环境变量默认值；从未配置目标时不推送也不落标记，配置后只推之后的事件。
func TestSettingsOverrideAndLateEnable(t *testing.T) {
	ctx, client := testdb.New(t)

	var received int
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received++
	}))
	t.Cleanup(hook.Close)

	settings := &Settings{DB: client}
	if got := settings.Load(ctx); got.URL != "" {
		t.Fatalf("未保存时应返回默认值，实际 %+v", got)
	}
	n := &Notifier{DB: client, Settings: settings, Client: hook.Client()}

	before, _ := client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus("open").Save(ctx)
	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := client.Incident.Get(ctx, before.ID)
	if got.NotifiedAt != nil || received != 0 {
		t.Fatal("未配置目标时不应推送或落标记")
	}

	if err := settings.Save(ctx, Target{URL: hook.URL, Format: "generic"}); err != nil {
		t.Fatal(err)
	}
	if err := settings.Save(ctx, Target{URL: hook.URL, Format: "feishu"}); err != nil {
		t.Fatal(err)
	}
	if got := settings.Load(ctx); got.Format != "feishu" {
		t.Fatalf("再次保存应覆盖，实际 %+v", got)
	}
	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if received != 0 {
		t.Fatal("启用前的历史事件不应补发")
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus("open").Save(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if received != 1 {
		t.Fatalf("启用后的新事件应推送 1 条，实际 %d", received)
	}
}

// 重研判期间的通知：普通新证据冷却中照旧结论推，不卡；升级类等新结论，研判屡败后不等、且不带旧结论
func TestSweepDuringRetriage(t *testing.T) {
	ctx, client := testdb.New(t)
	var received []Message
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m Message
		_ = json.NewDecoder(r.Body).Decode(&m)
		received = append(received, m)
	}))
	t.Cleanup(hook.Close)
	n := &Notifier{
		DB: client, Settings: &Settings{DB: client, Default: Target{URL: hook.URL, Format: "generic"}},
		WaitTriage: func() bool { return true }, Client: hook.Client(), start: time.Now().Add(-time.Minute),
	}
	triaged, later := time.Now().Add(-5*time.Minute), time.Now()
	mk := func(verdict string) uuid.UUID {
		inc := client.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus("triaged").
			SetAiVerdict(json.RawMessage(verdict)).SetTriagedAt(triaged).SetEvidenceAt(later).SaveX(ctx)
		client.Alert.Create().SetTs(later).SetRuleID("r").SetSeverity(3).SetIncidentID(inc.ID).ExecX(ctx)
		return inc.ID
	}
	cooling := mk(`{"verdict":"malicious","confidence":90,"summary":"外连"}`)
	escalated := mk(`{"verdict":"benign","summary":"例行"}`)
	client.Incident.UpdateOneID(escalated).SetUrgentAt(later).ExecX(ctx)

	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if len(received) != 1 || received[0].IncidentID != cooling.String() || received[0].Verdict != "malicious" {
		t.Fatalf("冷却中的应照旧结论推送、升级的应等：%+v", received)
	}
	if client.Incident.GetX(ctx, escalated).NotifiedAt != nil {
		t.Fatal("升级类等新结论期间不应落推送标记")
	}

	client.Incident.UpdateOneID(escalated).SetTriageFailures(giveUpAfter).ExecX(ctx)
	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if len(received) != 2 || received[1].IncidentID != escalated.String() || received[1].Verdict != "" ||
		received[1].Summary == "" || client.Incident.GetX(ctx, escalated).NotifiedAt == nil {
		t.Fatalf("研判屡败后应不带旧结论照推并落标记：%+v", received)
	}
}
