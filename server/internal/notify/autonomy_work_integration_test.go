//go:build integration

package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"openxdr/server/ent/incident"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/review"
	"openxdr/server/internal/testdb"
)

func TestSweepUsesDurableReviewPolicyBothDirections(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	var sent []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg Message
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			t.Error(err)
		}
		sent = append(sent, msg.IncidentID)
	}))
	defer hook.Close()
	n := &Notifier{DB: db, Settings: &Settings{DB: db, Default: Target{URL: hook.URL, Format: "generic"}}, Client: hook.Client(), WaitTriage: func() bool { return true }, start: now.Add(-time.Hour)}
	orphan := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus("triaged").SetTriagedAt(now).SetAiVerdict(json.RawMessage(`{"verdict":"benign","action_codes":["monitor"]}`)).SaveX(ctx)
	owned := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus("triaged").SetTriagedAt(now).SetAiVerdict(json.RawMessage(`{"verdict":"suspicious","action_codes":["collect_original_records"]}`)).SaveX(ctx)
	db.Alert.Create().SetTs(now).SetRuleID("r").SetSeverity(3).SetIncidentID(orphan.ID).ExecX(ctx)
	db.Alert.Create().SetTs(now).SetRuleID("r").SetSeverity(3).SetIncidentID(owned.ID).ExecX(ctx)
	if err := incidentwork.Refresh(ctx, db, db.Incident.GetX(ctx, owned.ID), now); err != nil {
		t.Fatal(err)
	}
	if !db.Incident.Query().Where(incident.IDEQ(orphan.ID), review.Needed()).ExistX(ctx) || db.Incident.Query().Where(incident.IDEQ(owned.ID), review.Needed()).ExistX(ctx) {
		t.Fatal("测试负责人状态未建立")
	}
	// 旧纯函数会静默 benign、推送缺证；数据库口径必须能双向覆盖，而非只减少通知。
	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0] != orphan.ID.String() {
		t.Fatalf("通知未遵从持久责任口径: %v", sent)
	}
	if db.Incident.GetX(ctx, orphan.ID).NotifiedAt == nil || db.Incident.GetX(ctx, owned.ID).NotifiedAt == nil {
		t.Fatal("推送与静默均应完成本轮通知标记")
	}
}
