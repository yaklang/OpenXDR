package triage

import (
	"openxdr/server/ent"
	"testing"
	"time"
)

func TestRunTriggerReadyTime(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	evidence := now.Add(-20 * time.Minute)
	last := now.Add(-25 * time.Minute)
	e := &Engine{Cooldown: 30 * time.Minute}
	cases := []struct {
		inc    ent.Incident
		reason string
		ready  *time.Time
	}{
		{ent.Incident{Status: "open", CreatedAt: old}, "initial", &old},
		{ent.Incident{Status: "open", CreatedAt: old, TriageCount: 2}, "reopened", nil},
		{ent.Incident{Status: "triaged", TriagedAt: &last, UrgentAt: &evidence}, "urgent", &evidence},
	}
	for _, tc := range cases {
		reason, ready := e.runTrigger(&tc.inc)
		if reason != tc.reason || (ready == nil) != (tc.ready == nil) || ready != nil && !ready.Equal(*tc.ready) {
			t.Fatal(reason, ready)
		}
	}
	_, ready := e.runTrigger(&ent.Incident{Status: "triaged", TriagedAt: &last, EvidenceAt: &evidence})
	if ready == nil || !ready.Equal(last.Add(e.Cooldown)) {
		t.Fatal("未扣除冷却期")
	}
}
