//go:build integration

package triage

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

// 狩猎闭环：模型用 query_events 查库，拿到真实数据后用自然语言作答，
// 调查过程作为 steps 返回，供人复核。
func TestHuntUsesTools(t *testing.T) {
	ctx, client := testdb.New(t)

	if err := client.Event.Create().
		SetTs(time.Now()).SetClassUID(4001).SetSource("sensor").
		SetConnTuple("tcp:10.0.0.5:4000>203.0.113.9:443").
		SetRaw(json.RawMessage(`{"dst_endpoint":{"ip":"203.0.113.9","port":443}}`)).
		Exec(ctx); err != nil {
		t.Fatal(err)
	}

	var turns int
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		turns++
		if turns == 1 {
			if req.Messages[0].Role != "system" || !strings.Contains(req.Messages[0].Content, "狩猎") {
				t.Errorf("首条应为狩猎 system prompt：%+v", req.Messages[0])
			}
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"",
				"tool_calls":[{"id":"c1","type":"function",
				"function":{"name":"query_events","arguments":"{\"keyword\":\"203.0.113.9\"}"}}]}}]}`))
			return
		}
		last := req.Messages[len(req.Messages)-1]
		if !strings.Contains(last.Content, "203.0.113.9") {
			t.Errorf("工具结果应带回真实事件：%s", last.Content)
		}
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"有一台主机在 24 小时内连过该 IP。"}}]}`))
	}))
	t.Cleanup(llmSrv.Close)

	e := &Engine{DB: client, LLM: NewLLM(llmSrv.URL, "m", "", 10*time.Second)}
	answer, steps, err := e.Hunt(ctx, "最近有主机连过 203.0.113.9 吗？")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(answer, "连过该 IP") {
		t.Errorf("回答不对：%s", answer)
	}
	if len(steps) != 1 || steps[0].Tool != "query_events" {
		t.Fatalf("应记录一次 query_events 调查：%+v", steps)
	}
}

// 未配置模型时明确报错，不是静默返回空答案。
func TestHuntWithoutModel(t *testing.T) {
	ctx, client := testdb.New(t)
	e := &Engine{DB: client, LLM: NewLLM("http://unused", "", "", time.Second)}
	if _, _, err := e.Hunt(ctx, "问题"); !errors.Is(err, ErrLLMDisabled) {
		t.Fatalf("应返回 ErrLLMDisabled，实际 %v", err)
	}
}
