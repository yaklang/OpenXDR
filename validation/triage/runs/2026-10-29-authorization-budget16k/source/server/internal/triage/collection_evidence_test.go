package triage

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCollectionEvidencePreservesUnknownAndSnapshotTime(t *testing.T) {
	for _, raw := range []string{"", "null", "{}", `{"receivedAt":"broken"}`, `{"capabilities":{"process":{"state":"active"}}}`} {
		facts := collectionEvidence(json.RawMessage(raw))
		if len(facts) != 1 || facts["collection_status"] != "unknown" {
			t.Fatalf("%s: %v", raw, facts)
		}
	}
	facts := collectionEvidence(json.RawMessage(`{"receivedAt":"2020-01-01T00:00:00Z","capabilities":{"process":{"state":"degraded","path":"poll"},"dns":{"state":"active"},"auth":{"state":"invented"}}}`))
	if facts["collection_received_at"] != "2020-01-01T00:00:00Z" || facts["collection_status"] != "recorded_snapshot" {
		t.Fatal(facts)
	}
	states := facts["collection_states"].(map[string]string)
	if len(states) != 2 || states["process"] != "degraded" || states["dns"] != "active" {
		t.Fatal(states)
	}
	// 旧快照不改成当前时间，也不补写未报告组件。
	if _, exists := states["file"]; exists {
		t.Fatal(states)
	}
	facts["status"] = "ok"
	raw, _ := json.Marshal(facts)
	messages := []Message{{Role: "tool", Content: string(raw)}}
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{`{"process":"degraded","dns":"active"}`, true},
		{`{"process":"active","dns":"active"}`, false},
		{`{"process":"degraded","dns":"active","file":"disabled"}`, false},
	} {
		answer := strings.TrimSuffix(validVerdict, "}") + `,"evidence_claims":[{"evidence_id":"query-1","field":"collection_states","value":` + tc.value + `}]}`
		_, err := bindEvidence(Message{Content: answer}, messages)
		if (err == nil) != tc.valid {
			t.Fatalf("%s: %v", tc.value, err)
		}
	}
}
