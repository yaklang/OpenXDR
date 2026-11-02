package triageeval

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/triage"
)

func TestJudgeFailureDiagnostics(t *testing.T) {
	full := `{"facts":{"status":"pass","reason":"已核对"},"uncertainty":{"status":"pass","reason":"已核对"},"actions":{"status":"pass","reason":"已核对"}}`
	for _, tc := range []struct {
		name, stage, finish, content, code string
		status                             int
	}{
		{"完整评分截断", "full_review", "length", full, "incomplete_output", 0},
		{"完整评分坏JSON", "full_review", "stop", "broken", "invalid_json", 0},
		{"完整评分缺字段", "full_review", "stop", `{}`, "invalid_schema", 0},
		{"独立评分截断", "actions_review", "length", `{}`, "incomplete_output", 0},
		{"独立评分伪造引用", "actions_review", "stop", `{"status":"fail","reason":"错","quote":"不存在的句子"}`, "invalid_quote", 0},
		{"请求被限流", "full_review", "", "", "http_error", 429},
		{"完成原因不可信", "full_review", "secret-canary", "", "incomplete_output", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if tc.status != 0 {
					w.WriteHeader(tc.status)
					fmt.Fprint(w, "secret-canary")
					return
				}
				finish, content := tc.finish, tc.content
				if tc.stage == "actions_review" && calls == 1 {
					finish, content = "stop", full
				}
				json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": finish, "message": triage.Message{Role: "assistant", Content: content}}}})
			}))
			defer srv.Close()
			result, err := Judge(context.Background(), triage.NewLLM(srv.URL, "test", "", time.Second), Case{Evidence: "观察记录", Rubric: map[string]string{"actions": "核实"}}, json.RawMessage(`{"summary":"观察记录","actions":["核实来源"]}`))
			if err == nil {
				t.Fatal("未返回评分错误")
			}
			d := Diagnose(err)
			if d.Stage != tc.stage || d.Code != tc.code || d.HTTPStatus != tc.status {
				t.Fatalf("%+v", d)
			}
			if tc.finish == "length" && d.FinishReason != "length" {
				t.Fatal(d)
			}
			if tc.stage == "actions_review" && (len(result) != 3 || calls != 2) {
				t.Fatalf("丢失完整评分：%v calls=%d", result, calls)
			}
			raw, _ := json.Marshal(d)
			if strings.Contains(string(raw), "secret-canary") || strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("不可信原文进入诊断")
			}
		})
	}
}

func TestDiagnosticDoesNotExposeWrappedErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{fmt.Errorf("secret-canary: %w", context.DeadlineExceeded), "timeout"},
		{fmt.Errorf("secret-canary: %w", context.Canceled), "canceled"},
		{fmt.Errorf("secret-canary: %w", &triage.LLMHTTPError{StatusCode: 503}), "http_error"},
		{fmt.Errorf("https://secret-canary.invalid/?key=secret-canary"), "generation_or_format"},
	} {
		d := Diagnose(tc.err)
		raw, _ := json.Marshal(d)
		if d.Code != tc.code || strings.Contains(string(raw), "secret-canary") {
			t.Fatal(string(raw))
		}
	}
}
