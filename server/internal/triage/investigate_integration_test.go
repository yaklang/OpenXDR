//go:build integration

package triage

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

// 工具调用研判闭环：模型第一轮要求 query_events，server 真查库并把结果
// 喂回去，第二轮模型给出结论。验证工具执行、消息回传、verdict 落库全链路。
func TestInvestigateWithTools(t *testing.T) {
	ctx, client := testdb.New(t)

	// 库里放一条含目标 IP 的事件，工具查询应能带回它
	if err := client.Event.Create().
		SetTs(time.Now()).SetClassUID(4001).SetSource("sensor").
		SetRaw(json.RawMessage(`{"dst_endpoint":{"ip":"6.6.6.6","port":443}}`)).
		Exec(ctx); err != nil {
		t.Fatal(err)
	}

	var turns int
	var sawToolResult string
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []Message `json:"messages"`
			Tools    []Tool    `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("请求体解析失败: %v", err)
		}
		turns++
		switch turns {
		case 1:
			if len(req.Tools) != 3 {
				t.Errorf("第一轮应带 3 个工具，实际 %d", len(req.Tools))
			}
			// 模型要求调查 6.6.6.6
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"",
				"tool_calls":[{"id":"call-1","type":"function",
				"function":{"name":"query_events","arguments":"{\"keyword\":\"6.6.6.6\"}"}}]}}]}`))
		default:
			// 第二轮应收到 tool 角色消息，内容是真实查询结果
			last := req.Messages[len(req.Messages)-1]
			if last.Role != "tool" || last.ToolCallID != "call-1" {
				t.Errorf("第二轮末条消息应为 tool 结果，实际 %+v", last)
			}
			sawToolResult = last.Content
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant",
				"content":"{\"verdict\":\"malicious\",\"confidence\":90,\"summary\":\"C2 外连\"}"}}]}`))
		}
	}))
	t.Cleanup(llmSrv.Close)

	e := &Engine{
		DB:  client,
		LLM: NewLLM(llmSrv.URL, "test-model", "", 10*time.Second),
	}
	answer, err := e.investigate(ctx, "# 事件: 可疑外连")
	if err != nil {
		t.Fatal(err)
	}
	if turns != 2 {
		t.Fatalf("应恰好两轮对话，实际 %d", turns)
	}
	if !strings.Contains(sawToolResult, "6.6.6.6") {
		t.Errorf("工具结果应包含库里的事件，实际 %s", sawToolResult)
	}
	var v struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(parseVerdict("t", answer), &v); err != nil || v.Verdict != "malicious" {
		t.Errorf("最终结论解析失败：%s", answer)
	}
}

// 模型不调用工具时一轮出结论——不支持 tool calling 的模型走同一条路径。
func TestInvestigateWithoutTools(t *testing.T) {
	ctx, client := testdb.New(t)

	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"verdict\":\"benign\"}"}}]}`))
	}))
	t.Cleanup(llmSrv.Close)

	e := &Engine{DB: client, LLM: NewLLM(llmSrv.URL, "m", "", 10*time.Second)}
	answer, err := e.investigate(ctx, "ctx")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(answer, "benign") {
		t.Errorf("应直接返回结论：%s", answer)
	}
}
