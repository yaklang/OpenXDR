package triage

import (
	"encoding/json"
	"testing"
	"time"

	"openxdr/server/ent"
)

func TestCapabilityUpgradeEligibilityAndServerStamp(t *testing.T) {
	old := json.RawMessage(`{"verdict":"benign","action_codes":["collect_original_records"]}`)
	inc := ent.Incident{Status: "triaged", AiVerdict: old}
	if !needsCapabilityUpgrade(&inc) {
		t.Fatal("旧补证结论未纳入升级")
	}
	inc.AiVerdict = withEvidenceCapability(old)
	if needsCapabilityUpgrade(&inc) {
		t.Fatal("仍缺证的新版结论不能循环升级")
	}
	for _, status := range []string{"closed", "false_positive", "open"} {
		inc.Status, inc.AiVerdict = status, old
		if needsCapabilityUpgrade(&inc) {
			t.Fatal("不应升级状态", status)
		}
	}
	inc.Status = "triaged"
	now := time.Now()
	inc.EvidenceAt = &now
	if needsCapabilityUpgrade(&inc) {
		t.Fatal("新增证据应走原有优先队列")
	}
	inc.EvidenceAt = nil
	inc.AiVerdict = json.RawMessage(`{"action_codes":["monitor"]}`)
	if needsCapabilityUpgrade(&inc) {
		t.Fatal("不应扩大到无补证要求的事件")
	}
	var stamped map[string]any
	_ = json.Unmarshal(withEvidenceCapability(json.RawMessage(`{"evidence_capability_version":999,"summary":"test"}`)), &stamped)
	if stamped["evidence_capability_version"] != float64(evidenceCapabilityVersion) || stamped["summary"] != "test" {
		t.Fatal("版本必须由服务端覆盖模型输出", stamped)
	}
}
