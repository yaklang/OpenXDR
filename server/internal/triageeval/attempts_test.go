package triageeval

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"openxdr/server/internal/triage"
)

func TestJudgeDetailedPreservesRejectedResponses(t *testing.T) {
	fullPass := `{"facts":{"status":"pass","reason":"一致"},"uncertainty":{"status":"pass","reason":"范围明确"},"actions":{"status":"pass","reason":"仅核实"}}`
	fullBadQuote := `{"facts":{"status":"fail","reason":"测试无效引文","quote":"not-in-answer"},"uncertainty":{"status":"pass","reason":"范围明确"},"actions":{"status":"pass","reason":"仅核实"}}`
	for _, tc := range []struct {
		name, first, second, finish string
		want                        int
	}{
		{"完整评分引文错误", fullBadQuote, "", "stop", 1},
		{"完整评分截断", fullPass, "", "length", 1},
		{"完整评分非JSON", "not-json", "", "stop", 1},
		{"建议评分引文错误", fullPass, `{"status":"fail","reason":"测试无效引文","quote":"not-in-answer"}`, "stop", 2},
		{"建议评分截断", fullPass, `{"status":"pass","reason":"仅核实"}`, "length", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				content, finish := tc.first, "stop"
				if calls == tc.want {
					finish = tc.finish
				}
				if calls == 2 {
					content = tc.second
				}
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": finish, "message": triage.Message{Role: "assistant", Content: content}}}})
			}))
			defer srv.Close()
			_, attempts, err := JudgeDetailed(context.Background(), triage.NewLLM(srv.URL, "test", "", time.Second), Case{}, json.RawMessage(`{"summary":"待核实","actions":["核实"]}`))
			if err == nil || len(attempts) != tc.want || calls != tc.want {
				t.Fatalf("未保留失败且不得重试: calls=%d attempts=%+v err=%v", calls, attempts, err)
			}
			if attempts[0].Stage != "full_review" || attempts[0].Message.Content != tc.first {
				t.Fatalf("完整评分原文丢失: %+v", attempts)
			}
			if tc.want == 2 && (attempts[1].Stage != "actions_review" || attempts[1].Message.Content != tc.second) {
				t.Fatalf("建议评分原文丢失: %+v", attempts)
			}
			if attempts[tc.want-1].FinishReason != tc.finish {
				t.Fatalf("终止原因丢失: %+v", attempts)
			}
		})
	}
}

func TestJudgeDetailedDoesNotArchiveHTTPErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "sensitive-upstream-body", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, attempts, err := JudgeDetailed(context.Background(), triage.NewLLM(srv.URL, "test", "", time.Second), Case{}, json.RawMessage(`{"summary":"待核实"}`))
	if err == nil || len(attempts) != 0 || Diagnose(err).HTTPStatus != 429 {
		t.Fatalf("传输失败不应当作模型响应存档: attempts=%+v err=%v", attempts, err)
	}
}
