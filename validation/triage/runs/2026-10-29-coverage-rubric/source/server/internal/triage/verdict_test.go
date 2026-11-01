package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

const validVerdict = `{"verdict":"benign","confidence":88,"summary":"系统维护","kill_chain":[],"action_codes":["monitor"]}`

func verdictLLM(t *testing.T, answers []Message) (*LLM, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []Message         `json:"messages"`
			Tools    []json.RawMessage `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if calls > 0 && (len(req.Tools) != 0 || len(req.Messages) < 4) {
			t.Error("修正应复用上下文且不提供工具")
		}
		msg := answers[min(calls, len(answers)-1)]
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": msg, "finish_reason": msg.FinishReason}}})
	}))
	t.Cleanup(srv.Close)
	return NewLLM(srv.URL, "m", "", 5*time.Second), &calls
}

func TestVerdictCorrection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		first     Message
		corrected string
		wantErr   bool
		calls     int
	}{
		{"valid", Message{Content: validVerdict}, validVerdict, false, 1},
		{"invalid escape", Message{Content: `{"verdict":"benign","confidence":88,"summary":"expr \(.*\)"}`}, validVerdict, false, 2},
		{"length even with valid JSON", Message{Content: validVerdict, FinishReason: "length"}, validVerdict, false, 2},
		{"invalid after correction", Message{Content: "不完整"}, "仍然不完整", true, 2},
		{"missing fields", Message{Content: `{}`}, validVerdict, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			llm, calls := verdictLLM(t, []Message{tc.first, {Role: "assistant", Content: tc.corrected}})
			e := &Engine{LLM: llm}
			got, err := e.investigate(context.Background(), "调查证据")
			if (err != nil) != tc.wantErr || *calls != tc.calls {
				t.Fatalf("calls=%d err=%v", *calls, err)
			}
			if !tc.wantErr {
				var actual, expected map[string]any
				if err := json.Unmarshal([]byte(got), &actual); err != nil {
					t.Fatal(err)
				}
				_ = json.Unmarshal([]byte(validVerdict), &expected)
				ledger, ok := actual["query_evidence"].([]any)
				if !ok || len(ledger) != 0 {
					t.Fatalf("没有执行工具却出现查询证据: %s", got)
				}
				delete(actual, "query_evidence")
				observations, ok := actual["evidence_observations"].([]any)
				if !ok || len(observations) != 0 {
					t.Fatalf("没有工具引用却出现证据摘录: %s", got)
				}
				delete(actual, "evidence_observations")
				if actions, ok := actual["actions"].([]any); !ok || len(actions) != 1 {
					t.Fatalf("缺少服务端建议: %s", got)
				}
				delete(actual, "actions")
				if !reflect.DeepEqual(actual, expected) {
					t.Fatalf("结论=%s", got)
				}
			}
		})
	}
}

func TestValidateVerdict(t *testing.T) {
	for _, raw := range []string{
		`{"verdict":"unknown","confidence":80,"summary":"x"}`,
		`{"verdict":"benign","confidence":101,"summary":"x"}`,
		`{"verdict":"benign","confidence":null,"summary":"x"}`,
		`{"verdict":"benign","confidence":80,"summary":" "}`,
		`{"verdict":"benign","confidence":80,"summary":"x","actions":"关闭"}`,
		`{"verdict":"benign","confidence":80,"summary":"x","error":"unparseable"}`,
	} {
		if err := validateVerdict(Message{Content: raw}); err == nil {
			t.Errorf("不应接受 %s", raw)
		}
	}
}

func TestParseVerdictUTF8Excerpt(t *testing.T) {
	var got struct {
		Raw string `json:"raw"`
	}
	if err := json.Unmarshal(parseVerdict("t", strings.Repeat("中", 1000)), &got); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(got.Raw, '\ufffd') || len(got.Raw) > 2000 {
		t.Fatalf("截断破坏中文或超限: %d", len(got.Raw))
	}
}
