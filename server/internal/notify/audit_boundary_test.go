package notify

import (
	"encoding/json"
	"openxdr/server/ent"
	"openxdr/server/ent/schema"
	"testing"
	"time"
)

func TestAuditRequiredEscalationsNotify(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name     string
		severity int16
		actions  []string
		proposal bool
	}{
		{"unapproved_proposal_cannot_silence_high_suspicious", 5, []string{"monitor"}, true},
		{"unavoidable_manual_original_records", 3, []string{"collect_original_records"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"verdict": "suspicious", "action_codes": tc.actions})
			inc := &ent.Incident{Status: "triaged", CreatedAt: now, AiVerdict: raw}
			if tc.proposal {
				inc.ClosureProposal = &schema.ClosureProposal{Status: "false_positive"}
			}
			n := &Notifier{start: now.Add(-time.Hour)}
			if send, why := n.decide(inc, tc.severity); !send {
				t.Fatalf("human escalation suppressed: %s", why)
			}
		})
	}
}

func TestAuditBenignHumanEscalationNotify(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name, action string
		send         bool
	}{
		{"manual_original_records", "collect_original_records", true},
		{"routine_monitor", "monitor", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"verdict": "benign", "action_codes": []string{tc.action}})
			if err != nil {
				t.Fatal(err)
			}
			n := &Notifier{start: now.Add(-time.Hour)}
			got, why := n.decide(&ent.Incident{Status: "triaged", CreatedAt: now, AiVerdict: raw}, 3)
			if got != tc.send {
				t.Errorf("send=%v want %v: %s", got, tc.send, why)
			}
		})
	}
}
