package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSnapshotUsesProductionPolicyWithoutTools(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req struct {
			Messages []Message `json:"messages"`
			Tools    []Tool    `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if len(req.Tools) != 0 || len(req.Messages) < 2 || req.Messages[0].Content != investigationPrompt() {
			t.Error("快照评测不应注册工具或复制另一份提示词")
		}
		content := `{"verdict":"suspicious","confidence":60,"summary":"来源待核实","kill_chain":[],"action_codes":["verify_source"]}`
		if calls == 1 {
			content = "broken json"
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": Message{Role: "assistant", Content: content}}}})
	}))
	defer srv.Close()
	raw, err := EvaluateSnapshot(context.Background(), NewLLM(srv.URL, "test", "", time.Second), "只有 DNS 证据")
	if err != nil || calls != 2 || !json.Valid(raw) || len(EvidencePromptHash()) != 64 {
		t.Fatal(calls, string(raw), err)
	}
}

func TestSnapshotReplaysEvidenceThroughProductionValidation(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req struct {
			Messages []Message `json:"messages"`
			Tools    []Tool    `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		sawResult, sawLedger := false, false
		for _, msg := range req.Messages {
			if msg.Role == "tool" || len(msg.ToolCalls) > 0 {
				t.Error("离线回放不能伪造历史工具调用")
			}
			if msg.Role == "user" && strings.Contains(msg.Content, "离线工具结果快照") {
				sawResult = true
			}
			if msg.Role == "system" && strings.Contains(msg.Content, "query-1") {
				sawLedger = true
			}
		}
		if !sawResult || !sawLedger || len(req.Tools) > 0 {
			t.Error("必须回放快照及台账，不能执行工具")
		}
		value := "false"
		if calls > 1 {
			value = "true"
		}
		answer := strings.TrimSuffix(validVerdict, "}") + `,"evidence_claims":[{"evidence_id":"query-1","field":"truncated","value":` + value + `}]}`
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": Message{Role: "assistant", Content: answer}}}})
	}))
	defer srv.Close()
	llm := NewLLM(srv.URL, "test", "", time.Second)
	result, attempts, err := EvaluateSnapshotDetailed(context.Background(), llm, "离线记录", EvidenceSnapshot{Tool: "query_events", Result: json.RawMessage(`{"status":"ok","truncated":true}`)})
	if err != nil || calls != 2 || !strings.Contains(string(result), `"query_evidence"`) {
		t.Fatalf("calls=%d result=%s err=%v", calls, result, err)
	}
	if len(attempts) != 2 || attempts[0].StructuralValid || !attempts[1].StructuralValid || attempts[0].FinishReason != "stop" || !strings.Contains(attempts[0].Message.Content, `"value":false`) || !strings.Contains(attempts[1].Message.Content, `"value":true`) {
		t.Fatalf("首次错误与修正结果未完整保留: %+v", attempts)
	}
	for _, snapshot := range []EvidenceSnapshot{{Tool: "exec", Result: json.RawMessage(`{}`)}, {Tool: "query_events", Result: json.RawMessage(`null`)}} {
		if _, err := EvaluateSnapshot(context.Background(), llm, "invalid", snapshot); err == nil {
			t.Fatal("无效快照被接受")
		}
	}
	if calls != 2 {
		t.Fatal("无效快照不应调用模型")
	}
}

func TestSnapshotDetailedRetainsRejectedAttempts(t *testing.T) {
	llm, calls := verdictLLM(t, []Message{{Role: "assistant", Content: "首次残缺", FinishReason: "length"}, {Role: "assistant", Content: "修正仍错误", FinishReason: "stop"}})
	answer, attempts, err := EvaluateSnapshotDetailed(context.Background(), llm, "脱敏快照")
	if err == nil || answer != nil || *calls != 2 || len(attempts) != 2 || attempts[0].StructuralValid || attempts[1].StructuralValid || attempts[0].Message.Content != "首次残缺" || attempts[1].Message.Content != "修正仍错误" || attempts[0].FinishReason != "length" {
		t.Fatalf("失败后丢失输出: answer=%s attempts=%+v calls=%d err=%v", answer, attempts, *calls, err)
	}
}
