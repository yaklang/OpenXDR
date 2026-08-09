//go:build integration

package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

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

// batch 主循环端到端：open 状态 incident → 研判 → verdict 落库、状态推进 triaged、
// OnVerdict 钩子触发；重新研判会覆盖旧 verdict。
func TestBatchTriagesAndPersistsVerdict(t *testing.T) {
	ctx, client := testdb.New(t)

	inc, err := client.Incident.Create().
		SetStatus("open").SetGraph(json.RawMessage(`{"nodes":[]}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var onVerdict atomic.Int32
	e := &Engine{DB: client}
	e.LLM = oneShotLLM(t, `{"verdict":"malicious","confidence":88,"summary":"确认外连"}`)
	e.OnVerdict = func(_ context.Context, id uuid.UUID, v json.RawMessage) {
		onVerdict.Add(1)
	}

	if err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}

	got, err := client.Incident.Get(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "triaged" {
		t.Errorf("status 应为 triaged，实际 %q", got.Status)
	}
	if onVerdict.Load() != 1 {
		t.Errorf("OnVerdict 应触发 1 次，实际 %d", onVerdict.Load())
	}
	var v struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(got.AiVerdict, &v); err != nil || v.Verdict != "malicious" {
		t.Errorf("ai_verdict 落库异常: %s (%v)", got.AiVerdict, err)
	}

	// 二次 batch 不应再处理已 triaged 的 incident（状态过滤 open）
	if err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	got2, _ := client.Incident.Get(ctx, inc.ID)
	if got2.Status != "triaged" {
		t.Errorf("已研判的 incident 不应被重复处理，status = %q", got2.Status)
	}
}

// toolProcessLineage：按 process_guid 追祖先链与直接子进程。
func TestToolProcessLineage(t *testing.T) {
	ctx, client := testdb.New(t)
	grandparent := uuid.New()
	parent := uuid.New()
	child := uuid.New()

	// 祖先链：child → parent → grandparent
	if err := client.Event.Create().
		SetTs(time.Now()).SetClassUID(1007).SetSource("agent").
		SetProcessGUID(grandparent).SetRaw(json.RawMessage(`{"process":{"name":"init"}}`)).
		Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Event.Create().
		SetTs(time.Now()).SetClassUID(1007).SetSource("agent").
		SetProcessGUID(parent).SetParentProcessGUID(grandparent).
		SetRaw(json.RawMessage(`{"process":{"name":"bash"}}`)).Save(ctx); err != nil {
		t.Fatal(err)
	}
	// 两个子进程指向 parent
	if _, err := client.Event.Create().
		SetTs(time.Now()).SetClassUID(1007).SetSource("agent").
		SetProcessGUID(child).SetParentProcessGUID(parent).
		SetRaw(json.RawMessage(`{"process":{"name":"evil"}}`)).Save(ctx); err != nil {
		t.Fatal(err)
	}

	e := &Engine{DB: client}
	out, err := e.toolProcessLineage(ctx, `{"process_guid":"`+child.String()+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(out)
	s := string(got)

	// self_and_ancestors 应含 child，parent，grandparent 三级（以进程名断言）
	for _, want := range []string{"evil", "bash", "init"} {
		if !strings.Contains(s, want) {
			t.Errorf("血缘链应含 %s，实际 %s", want, s)
		}
	}

	// 非法 UUID → 错误
	if _, err := e.toolProcessLineage(ctx, `{"process_guid":"not-a-uuid"}`); err == nil {
		t.Error("非法 UUID 应返回错误")
	}
}

// toolHostAlerts：按 asset 查告警，规则标题回填。
func TestToolHostAlerts(t *testing.T) {
	ctx, client := testdb.New(t)
	asset, err := client.Asset.Create().SetHostname("web01").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(time.Now()).SetRuleID("r-1").SetSeverity(4).SetAssetID(asset.ID).
		Save(ctx); err != nil {
		t.Fatal(err)
	}

	e := &Engine{DB: client}
	out, err := e.toolHostAlerts(ctx, `{"asset_id":"`+asset.ID.String()+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(out)
	if !strings.Contains(string(got), "r-1") {
		t.Errorf("告警历史应含 rule r-1：%s", got)
	}
	// 非法 asset id → 错误
	if _, err := e.toolHostAlerts(ctx, `{"asset_id":"nope"}`); err == nil {
		t.Error("非法 asset id 应返回错误")
	}
}

func oneShotLLM(t *testing.T, content string) *LLM {
	t.Helper()
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, _ := json.Marshal(map[string]any{"choices": []map[string]any{
			{"message": map[string]any{"role": "assistant", "content": content}},
		}})
		w.Write(resp)
	}))
	t.Cleanup(llmSrv.Close)
	return NewLLM(llmSrv.URL, "m", "", 10*time.Second)
}
