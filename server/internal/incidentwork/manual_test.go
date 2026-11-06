package incidentwork

import (
	"encoding/json"
	"openxdr/server/ent"
	"openxdr/server/ent/schema"
	"testing"
	"time"
)

func TestManualTakeoverSurvivesReplanning(t *testing.T) {
	now := time.Now()
	inc := &ent.Incident{Status: "triaged", CreatedAt: now.Add(-time.Hour), TriagedAt: &now, AiVerdict: json.RawMessage(`{"verdict":"benign"}`), Work: &schema.IncidentWork{ManualOwner: "analyst", ManualLock: true}}
	w, next := Plan(inc, 2, false, now)
	if w.Owner != "human" || w.ManualOwner != "analyst" || !w.ManualLock || next != nil {
		t.Fatal(w, next)
	}
}
