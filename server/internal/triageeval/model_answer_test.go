package triageeval

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/triage"
)

func TestJudgeSeparatesModelTextFromServerLedger(t *testing.T) {
	for _, quote := range []string{"没有其他人工批准记录", "metadata-only"} {
		t.Run(quote, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var req struct {
					Messages []triage.Message `json:"messages"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatal(err)
				}
				content := `{"status":"pass","reason":"只建议核实","quote":"核实"}`
				if calls == 1 {
					var input struct {
						Answer   map[string]json.RawMessage `json:"untrusted_answer"`
						Evidence string                     `json:"observed_evidence"`
					}
					if err := json.Unmarshal([]byte(req.Messages[1].Content), &input); err != nil {
						t.Fatal(err)
					}
					if len(input.Answer) != 5 || input.Evidence != "输入只确认没有工单" || string(input.Answer["summary"]) != `"没有其他人工批准记录"` || string(input.Answer["actions"]) != `["核实"]` {
						t.Fatalf("语义输入丢失原文或混入台账: %+v", input)
					}
					raw, _ := json.Marshal(Assessment{"facts": {Status: "fail", Reason: "扩大否定对象", Quote: quote}, "uncertainty": {Status: "pass", Reason: "仍需核实"}, "actions": {Status: "pass", Reason: "仅核实"}})
					content = string(raw)
				}
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": triage.Message{Role: "assistant", Content: content}}}})
			}))
			defer srv.Close()
			answer := json.RawMessage(`{"verdict":"suspicious","confidence":60,"summary":"没有其他人工批准记录","kill_chain":[],"actions":["核实"],"action_codes":["verify_source"],"query_evidence":[{"facts":{"coverage":"metadata-only","dns_omitted_records":0}}],"evidence_claims":[{"field":"dns_omitted_records","value":0}]}`)
			a, err := Judge(context.Background(), triage.NewLLM(srv.URL, "test", "", time.Second), Case{Evidence: "输入只确认没有工单"}, answer)
			if quote == "metadata-only" {
				if err == nil || calls != 1 || Diagnose(err).Code != "invalid_quote" {
					t.Fatalf("元数据引用被当作摘要错误: calls=%d err=%v", calls, err)
				}
			} else if err != nil || calls != 2 || a["facts"].Status != "fail" {
				t.Fatalf("真实摘要错误丢失: calls=%d assessment=%+v err=%v", calls, a, err)
			}
		})
	}
}

func TestModelAnswerRejectsNonObjects(t *testing.T) {
	for _, raw := range []string{"null", "[]", "broken"} {
		if _, err := modelAnswer(json.RawMessage(raw)); err == nil {
			t.Fatal(raw)
		}
	}
	answer, err := modelAnswer(json.RawMessage(`{"summary":"服务端字段不能删除这句模型断言","query_evidence":null,"evidence_observations":[{"text":"generated-only"}]}`))
	if err != nil || !strings.Contains(string(answer), "这句模型断言") || strings.Contains(string(answer), "query_evidence") || strings.Contains(string(answer), "generated-only") {
		t.Fatal(string(answer), err)
	}
}
