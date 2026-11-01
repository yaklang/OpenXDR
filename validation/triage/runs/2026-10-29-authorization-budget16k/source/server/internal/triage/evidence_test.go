package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBindEvidence(t *testing.T) {
	messages := []Message{{Role: "tool", ToolCallID: "one", Content: `{"status":"ok","returned":15,"truncated":true,"items":[{"raw":"untrusted"}]}`}, {Role: "tool", ToolCallID: "two", Content: `{"status":"error","coverage":"unknown"}`}}
	base := `{"verdict":"suspicious","confidence":60,"summary":"待核实","kill_chain":[],"action_codes":["monitor"],"query_evidence":[{"id":"forged"}]`
	for _, tc := range []struct {
		name, claims string
		invalid      bool
	}{
		{"省略引用", "", true},
		{"空引用", `,"evidence_claims":[]`, true},
		{"null 引用", `,"evidence_claims":null`, true},
		{"准确引用", `,"evidence_claims":[{"evidence_id":"query-1","field":"truncated","value":true}]`, false},
		{"篡改截断", `,"evidence_claims":[{"evidence_id":"query-1","field":"truncated","value":false}]`, true},
		{"未知不是否", `,"evidence_claims":[{"evidence_id":"query-2","field":"truncated","value":false}]`, true},
		{"伪造编号", `,"evidence_claims":[{"evidence_id":"query-9","field":"status","value":"ok"}]`, true},
		{"类型不符", `,"evidence_claims":[{"evidence_id":"query-1","field":"returned","value":"15"}]`, true},
		{"正文不是元数据", `,"evidence_claims":[{"evidence_id":"query-1","field":"items","value":[]}]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := bindEvidence(Message{Content: base + tc.claims + "}"}, messages)
			if (err != nil) != tc.invalid {
				t.Fatalf("out=%s err=%v", out, err)
			}
			if tc.invalid {
				return
			}
			var result struct {
				Evidence []queryEvidence `json:"query_evidence"`
			}
			if json.Unmarshal([]byte(out), &result) != nil || len(result.Evidence) != 2 || strings.Contains(out, "forged") || strings.Contains(out, "untrusted") {
				t.Fatal(out)
			}
			if _, ok := result.Evidence[1].Facts["truncated"]; ok {
				t.Fatal("失败查询不能补造截断状态")
			}
		})
	}
}

func TestEvidenceRepairRejectsUnsupportedClaims(t *testing.T) {
	for _, repaired := range []bool{true, false} {
		t.Run(fmt.Sprint(repaired), func(t *testing.T) {
			calls := 0
			answer := func(value bool) string {
				return fmt.Sprintf(`{"verdict":"suspicious","confidence":60,"summary":"待核实","kill_chain":[],"action_codes":["monitor"],"evidence_claims":[{"evidence_id":"query-1","field":"truncated","value":%t}]}`, value)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var request struct {
					Tools []Tool `json:"tools"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				if len(request.Tools) != 0 {
					t.Error("修正不得重执行工具")
				}
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": Message{Content: answer(repaired)}}}})
			}))
			defer srv.Close()
			e := Engine{LLM: NewLLM(srv.URL, "test", "", time.Second)}
			_, err := e.finishVerdict(context.Background(), []Message{{Role: "tool", Content: `{"status":"ok","truncated":true}`}}, Message{Content: answer(false)})
			if calls != 1 || (err == nil) != repaired {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestContentCoverageIsNotResultCountCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, result string
		raw, dns     float64
		present      bool
	}{
		{"正文裁剪但条数未超限", `{"status":"ok","truncated":false,"items":[{"raw_truncated":true,"dns_omitted":["answers"]},{"raw_truncated":false,"raw":"raw_truncated=true"}]}`, 1, 1, true},
		{"血缘两侧", `{"status":"ok","self_and_ancestors":[{"raw_truncated":true}],"children":[{"raw_truncated":true}]}`, 2, 0, true},
		{"空结果", `{"status":"ok","items":[]}`, 0, 0, true},
		{"失败不是零条裁剪", `{"status":"error","coverage":"unknown"}`, 0, 0, false},
		{"告警列表不提供事件正文", `{"status":"ok","alerts":[]}`, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidence := queryEvidenceFrom([]Message{{Role: "tool", Content: tc.result}})
			facts := evidence[0].Facts
			raw, present := facts["raw_truncated_records"]
			if present != tc.present || present && (raw != tc.raw || facts["dns_omitted_records"] != tc.dns) {
				t.Fatal(facts)
			}
		})
	}
}

func TestInvestigationRetainsFailedToolEvidence(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var request struct {
			Messages []Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		var message Message
		if calls == 1 {
			// 无效 GUID 经过真实工具分发，在读库前失败。
			if err := json.Unmarshal([]byte(`{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"process_lineage","arguments":"{\"process_guid\":\"invalid\"}"}}]}`), &message); err != nil {
				t.Fatal(err)
			}
		} else {
			found := false
			for _, msg := range request.Messages {
				if msg.Role == "system" && strings.Contains(msg.Content, "query-1") && strings.Contains(msg.Content, "unknown") {
					found = true
				}
			}
			if !found {
				t.Error("下一轮缺少服务端查询台账")
			}
			value := "false"
			if calls == 3 {
				value = `"error"`
			}
			field := "truncated"
			if calls == 3 {
				field = "status"
			}
			message = Message{Role: "assistant", Content: fmt.Sprintf(`{"verdict":"suspicious","confidence":60,"summary":"进程血缘未查明","action_codes":["monitor"],"kill_chain":[],"evidence_claims":[{"evidence_id":"query-1","field":%q,"value":%s}]}`, field, value)}
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": message}}})
	}))
	defer srv.Close()
	e := Engine{LLM: NewLLM(srv.URL, "test", "", time.Second)}
	answer, err := e.investigate(context.Background(), "调查进程")
	if err != nil || calls != 3 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	var verdict struct {
		Evidence []queryEvidence `json:"query_evidence"`
	}
	if err := json.Unmarshal([]byte(answer), &verdict); err != nil {
		t.Fatal(err)
	}
	if len(verdict.Evidence) != 1 || verdict.Evidence[0].Tool != "process_lineage" || verdict.Evidence[0].Facts["status"] != "error" {
		t.Fatal(answer)
	}
	if _, ok := verdict.Evidence[0].Facts["truncated"]; ok {
		t.Fatal("失败状态被写成未截断")
	}
}

func TestRecordClaimsCannotBorrowParentFromAnotherEvent(t *testing.T) {
	messages := []Message{{Role: "tool", Content: `{"status":"ok","items":[{"event_id":"first","process_guid":"child-a","parent_process_guid":"parent-a"},{"event_id":"second","process_guid":"child-b"}]}`}}
	for _, tc := range []struct {
		name, id, field string
		value           any
		valid           bool
	}{
		{"匹配", "query-1/items-1", "parent_process_guid", "parent-a", true},
		{"不同父进程", "query-1/items-1", "parent_process_guid", "parent-b", false},
		{"借用上一条关系", "query-1/items-2", "parent_process_guid", "parent-a", false},
		{"未知不是无父进程", "query-1/items-2", "parent_process_guid", nil, false},
		{"伪造首次出现", "query-1/items-1", "first_seen", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claim, _ := json.Marshal(map[string]any{"evidence_id": tc.id, "field": tc.field, "value": tc.value})
			answer := strings.TrimSuffix(validVerdict, "}") + `,"evidence_claims":[` + string(claim) + `]}`
			out, err := bindEvidence(Message{Content: answer}, messages)
			if (err == nil) != tc.valid {
				t.Fatalf("out=%s err=%v", out, err)
			}
		})
	}
}

func TestEvidenceWithoutToolsDoesNotInventReferences(t *testing.T) {
	for _, suffix := range []string{"", `,"evidence_claims":[]`} {
		answer := strings.TrimSuffix(validVerdict, "}") + suffix + "}"
		if _, err := bindEvidence(Message{Content: answer}, nil); err != nil {
			t.Fatal(err)
		}
	}
	answer := strings.TrimSuffix(validVerdict, "}") + `,"evidence_claims":[{"evidence_id":"query-1","field":"status","value":"ok"}]}`
	if _, err := bindEvidence(Message{Content: answer}, nil); err == nil {
		t.Fatal("未调用工具不能虚构引用")
	}
}

func TestMissingEvidenceClaimsRepairOnce(t *testing.T) {
	for _, repair := range []string{"", `,"evidence_claims":[{"evidence_id":"query-1","field":"status","value":"error"}]`} {
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			answer := strings.TrimSuffix(validVerdict, "}") + repair + "}"
			json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": Message{Content: answer}}}})
		}))
		e := Engine{LLM: NewLLM(srv.URL, "test", "", time.Second)}
		_, err := e.finishVerdict(context.Background(), []Message{{Role: "tool", Content: `{"status":"error","coverage":"unknown"}`}}, Message{Content: validVerdict})
		srv.Close()
		if calls != 1 || (err == nil) != (repair != "") {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	}
}
