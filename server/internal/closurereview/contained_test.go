package closurereview

import (
	"encoding/json"
	"openxdr/server/ent"
	"openxdr/server/ent/schema"
	"testing"
	"time"
)

func TestContainedEligibility(t *testing.T) {
	now := time.Now().Add(-time.Minute)
	inc := &ent.Incident{Status: "triaged", TriagedAt: &now, AiVerdict: json.RawMessage(`{"verdict":"malicious"}`), Work: &schema.IncidentWork{Owner: "human", Stage: "escalated"}}
	if !containedEligible(inc) {
		t.Fatal("自动升级应允许进入复核")
	}
	inc.Work.ManualLock = true
	if containedEligible(inc) {
		t.Fatal("人工锁必须拒绝")
	}
	inc.Work.ManualLock = false
	inc.Work.ManualOwner = "analyst"
	if containedEligible(inc) {
		t.Fatal("人工接管必须拒绝")
	}
}

func TestSeparateContainedPrompt(t *testing.T) {
	if closurePrompt(`{"contained":{"quiet_hours":6}}`) != containedPrompt {
		t.Fatal("遏制审计必须使用独立提示词")
	}
	if closurePrompt(`{"verdict":{"verdict":"benign"}}`) != prompt {
		t.Fatal("良性审计提示词应保留")
	}
}
