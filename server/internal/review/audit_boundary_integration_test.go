//go:build integration

package review

import (
	"encoding/json"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/testdb"
	"testing"
	"time"
)

func TestAuditHumanEscalationBoundaries(t *testing.T) {
	ctx, db := testdb.New(t)
	old := time.Now().Add(-48 * time.Hour)
	for _, tc := range []struct {
		name     string
		severity int16
		verdict  string
		proposal bool
	}{
		{"high_suspicious_unapproved_ai_proposal", 5, `{"verdict":"suspicious","action_codes":["monitor"]}`, true},
		{"manual_original_records_required", 3, `{"verdict":"suspicious","action_codes":["collect_original_records"]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := db.Incident.Create().SetStatus("triaged").SetCreatedAt(old).SetTriagedAt(old).SetGraph(json.RawMessage(`{}`)).SetAiVerdict(json.RawMessage(tc.verdict))
			if tc.proposal {
				b.SetClosureProposal(&schema.ClosureProposal{Status: "false_positive", Note: "仅为待人工确认的AI建议", At: old})
			}
			inc := b.SaveX(ctx)
			db.Alert.Create().SetTs(old).SetRuleID("audit-case").SetSeverity(tc.severity).SetIncidentID(inc.ID).ExecX(ctx)
			if !db.Incident.Query().Where(Needed()).Where(incident.IDEQ(inc.ID)).ExistX(ctx) {
				t.Error("unresolved human escalation disappeared from review")
			}
			if db.Incident.Query().Where(StaleBenign(time.Now().Add(-24 * time.Hour))).Where(incident.IDEQ(inc.ID)).ExistX(ctx) {
				t.Error("unverified suspicious incident eligible for automatic false-positive closure")
			}
		})
	}
}

func TestAuditBenignManualEscalation(t *testing.T) {
	ctx, db := testdb.New(t)
	old := time.Now().Add(-48 * time.Hour)
	for _, tc := range []struct {
		name, verdict, action string
		needReview, autoClose bool
	}{
		{"benign_requires_original_records", "benign", "collect_original_records", true, false},
		{"benign_routine_monitor", "benign", "monitor", false, true},
		{"suspicious_routine_monitor", "suspicious", "monitor", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"verdict": tc.verdict, "action_codes": []string{tc.action}})
			if err != nil {
				t.Fatal(err)
			}
			inc := db.Incident.Create().SetStatus("triaged").SetCreatedAt(old).SetTriagedAt(old).SetGraph(json.RawMessage(`{}`)).SetAiVerdict(raw).SaveX(ctx)
			db.Alert.Create().SetTs(old).SetRuleID("audit-benign-manual").SetSeverity(3).SetIncidentID(inc.ID).ExecX(ctx)
			if tc.action == "monitor" {
				if err := incidentwork.Refresh(ctx, db, db.Incident.GetX(ctx, inc.ID), time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if got := db.Incident.Query().Where(Needed(), incident.IDEQ(inc.ID)).ExistX(ctx); got != tc.needReview {
				t.Errorf("review needed=%v want %v", got, tc.needReview)
			}
			if got := db.Incident.Query().Where(StaleBenign(time.Now().Add(-24*time.Hour)), incident.IDEQ(inc.ID)).ExistX(ctx); got != tc.autoClose {
				t.Errorf("autoclose=%v want %v", got, tc.autoClose)
			}
		})
	}
}
