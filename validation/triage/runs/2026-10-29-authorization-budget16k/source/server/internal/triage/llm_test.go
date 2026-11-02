package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// GLM 的模板参数不发给其他模型；输出上限对所有端点生效
func TestNoThinkingOnlyForGLM(t *testing.T) {
	for _, c := range []struct {
		model string
		want  bool
	}{{"GLM-5.3-Flash", true}, {"zai/glm-4.6", true}, {"qwen3", false}, {"gpt-glmish", false}} {
		var got map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&got)
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{}"}}]}`))
		}))
		l := NewLLM(srv.URL, c.model, "", time.Second)
		l.NoThinking, l.MaxTokens = true, 2048
		if _, err := l.Chat(context.Background(), []Message{{Role: "user", Content: "x"}}, nil); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		if _, ok := got["chat_template_kwargs"]; ok != c.want || got["max_tokens"] != float64(2048) {
			t.Errorf("%s: kwargs=%v max_tokens=%v", c.model, got["chat_template_kwargs"], got["max_tokens"])
		}
	}
}

// 控制台覆盖模型后，关闭思考仍使用实际模型对应的协议。
func TestDeepSeekNoThinking(t *testing.T) {
	for _, model := range []string{"deepseek-flash", "deepseek-v4-flash", "deepseek-v4-pro", "deepseek/deepseek-flash", "deepseek-r1", "qwen3"} {
		for _, disabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", model, disabled), func(t *testing.T) {
				var got map[string]any
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Error(err)
					}
					_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{}"}}]}`))
				}))
				defer srv.Close()
				l := NewLLM(srv.URL, "GLM-5.3-Flash", "", time.Second)
				l.Endpoint = func() (string, string, string) { return srv.URL, model, "" }
				l.NoThinking = disabled
				if _, err := l.Chat(context.Background(), []Message{{Role: "user", Content: "x"}}, nil); err != nil {
					t.Fatal(err)
				}
				want := disabled && model != "deepseek-r1" && model != "qwen3"
				thinking, ok := got["thinking"].(map[string]any)
				if ok != want || (want && thinking["type"] != "disabled") {
					t.Errorf("thinking=%v, want disabled=%t", got["thinking"], want)
				}
				if _, ok := got["chat_template_kwargs"]; ok {
					t.Fatal("DeepSeek 请求不应携带 GLM 模板参数")
				}
			})
		}
	}
}
