package triage

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvidenceObservationsAreServerOwned(t *testing.T) {
	messages := []Message{{Role: "tool", Content: `{"status":"ok","returned":0,"truncated":false,"baseline_first_recorded_at":"2026-10-29T00:00:00Z","collection_states":{"process":"active"},"items":[{"event_id":"event-1","parent_process_guid":"parent-1"}]}`}}
	claims := []map[string]any{
		{"evidence_id": "query-1", "field": "returned", "value": 0},
		{"evidence_id": "query-1", "field": "truncated", "value": false},
		{"evidence_id": "query-1", "field": "baseline_first_recorded_at", "value": "2026-10-29T00:00:00Z"},
		{"evidence_id": "query-1", "field": "collection_states", "value": map[string]string{"process": "active"}},
		{"evidence_id": "query-1/items-1", "field": "parent_process_guid", "value": "parent-1"},
		{"evidence_id": "query-1", "field": "returned", "value": 0},
	}
	input := map[string]any{"verdict": "suspicious", "confidence": 60, "summary": "模型仍可能推断错误", "action_codes": []string{"monitor"}, "evidence_claims": claims, "evidence_observations": []any{map[string]string{"text": "forged-approved"}}}
	raw, _ := json.Marshal(input)
	out, err := bindEvidence(Message{Content: string(raw)}, messages)
	if err != nil {
		t.Fatal(err)
	}
	var verdict struct {
		Observations []evidenceObservation `json:"evidence_observations"`
		Summary      string                `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &verdict); err != nil {
		t.Fatal(err)
	}
	if len(verdict.Observations) != 5 || strings.Contains(out, "forged-approved") {
		t.Fatal(out)
	}
	for i, want := range []string{"零条不证明没有发生", "不代表单条正文完整", "不是安装时间或实际首次执行时间", "不能回推事发时状态", "不证明更长的进程链或操作授权"} {
		if !strings.Contains(verdict.Observations[i].Text, want) {
			t.Fatalf("缺少边界说明 %s: %s", want, verdict.Observations[i].Text)
		}
	}
	if verdict.Summary != input["summary"] {
		t.Fatal("生成摘录不应伪称已经修正模型摘要")
	}
	// 不允许引用缺失字段，也不因存在伪造摘录而跳过原有校验。
	claims[0]["field"] = "missing_field"
	raw, _ = json.Marshal(input)
	if _, err := bindEvidence(Message{Content: string(raw)}, messages); err == nil {
		t.Fatal("缺失证据不应生成摘录")
	}
}

func TestEvidenceObservationsWithoutToolsCannotBeForged(t *testing.T) {
	out, err := bindEvidence(Message{Content: `{"verdict":"suspicious","confidence":60,"summary":"待核实","action_codes":["monitor"],"evidence_observations":[{"text":"forged-approved"}]}`}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"evidence_observations":[]`) || strings.Contains(out, "forged-approved") {
		t.Fatal(out)
	}
}

func TestFailedQueryObservationDoesNotInventCoverage(t *testing.T) {
	out, err := bindEvidence(Message{Content: `{"verdict":"suspicious","confidence":60,"summary":"查询失败","action_codes":["monitor"],"evidence_claims":[{"evidence_id":"query-1","field":"status","value":"error"}]}`}, []Message{{Role: "tool", Content: `{"status":"error","coverage":"unknown"}`}})
	if err != nil {
		t.Fatal(err)
	}
	var verdict struct {
		Observations []evidenceObservation `json:"evidence_observations"`
	}
	if err := json.Unmarshal([]byte(out), &verdict); err != nil {
		t.Fatal(err)
	}
	if len(verdict.Observations) != 1 || verdict.Observations[0].Field != "status" || strings.Contains(verdict.Observations[0].Text, "0 条") {
		t.Fatal(out)
	}
}
