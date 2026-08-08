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
		DB: client, URL: hook.URL, Format: "generic",
		WaitTriage: true, LinkBase: "http://console",
		Client: hook.Client(),
		start:  time.Now().Add(-time.Minute),
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
		SetAiVerdict(json.RawMessage(`{"verdict":"benign"}`)).
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
	ctx, client := testdb.New(t)

	fail := true
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	t.Cleanup(hook.Close)

	n := &Notifier{
		DB: client, URL: hook.URL, Format: "generic",
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
		DB: client, URL: hook.URL, Format: "generic",
		MinSeverity: 4,
		Client:      hook.Client(), start: time.Now().Add(-time.Minute),
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
