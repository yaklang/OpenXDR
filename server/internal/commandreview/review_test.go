package commandreview

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"openxdr/server/internal/modelroute"
	"openxdr/server/internal/triage"
)

// 回复里认 JSON 结论；拿不到结论按出错处理，由闸门记为拒绝
func TestVerdict(t *testing.T) {
	ok, reason, err := Verdict("好的。\n```json\n{\"approve\": true, \"reason\": \"只读核对 sudoers 语法\"}\n```")
	if err != nil || !ok || reason != "只读核对 sudoers 语法" {
		t.Fatalf("应批准: %v %q %v", ok, reason, err)
	}
	if ok, _, err := Verdict(`{"approve": false, "reason": "会改配置但没有备份"}`); err != nil || ok {
		t.Fatalf("应拒绝: %v %v", ok, err)
	}
	for _, bad := range []string{"可以执行", `{"reason": "没有结论"}`, `{"approve": "yes"}`} {
		if _, _, err := Verdict(bad); err == nil {
			t.Errorf("拿不到结论应出错: %q", bad)
		}
	}
	if _, reason, _ := Verdict(`{"approve": true}`); reason == "" {
		t.Error("没给理由也要留一句说明")
	}
}

// 只取消息里的文字，工具调用不算
func TestText(t *testing.T) {
	parts := json.RawMessage(`{"role":"assistant","content":[{"type":"text","text":"先备份再改"},{"type":"toolCall","name":"exec"},{"type":"text","text":"然后用 visudo 校验"}]}`)
	if got := text(parts); got != "先备份再改\n然后用 visudo 校验" {
		t.Fatalf("文字部分: %q", got)
	}
	if got := text(json.RawMessage(`{"role":"user","content":"帮我修 sudoers"}`)); got != "帮我修 sudoers" {
		t.Fatalf("字符串内容: %q", got)
	}
}

// 验证 session.Model 属于备用端点时，直接路由到备用端点的地址与密钥，绝不拿主端点去调备用模型。
func TestBuildLLMMatchesBackupEndpointAndFallback(t *testing.T) {
	var primaryHits, backupHits atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits.Add(1)
		http.Error(w, "primary should not receive backup model", http.StatusNotFound)
	}))
	defer primary.Close()

	var gotAuth, gotModel string
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backupHits.Add(1)
		gotAuth = r.Header.Get("Authorization")
		var body struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotModel = body.Model
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": `{"approve": true, "reason": "ok"}`}, "finish_reason": "stop"}},
		})
	}))
	defer backup.Close()

	rev := &Reviewer{
		Endpoint:       func() (string, string) { return primary.URL, "primary-key" },
		FallbackModels: func() string { return "primary-fallback" },
		FallbackEndpoints: func() []modelroute.Endpoint {
			return []modelroute.Endpoint{{BaseURL: backup.URL, APIKey: "backup-key", Model: "backup-model"}}
		},
		Timeout: 5 * time.Second,
	}

	llm := rev.buildLLM("backup-model")
	reply, err := llm.Chat(context.Background(), []triage.Message{{Role: "user", Content: "check"}}, nil)
	if err != nil {
		t.Fatalf("命中备用端点应成功: %v", err)
	}
	if primaryHits.Load() != 0 {
		t.Fatalf("会话模型属于备用端点时不应打到主端点，primaryHits=%d", primaryHits.Load())
	}
	if backupHits.Load() != 1 || gotModel != "backup-model" || gotAuth != "Bearer backup-key" {
		t.Fatalf("备用端点路由信息不对: hits=%d model=%q auth=%q", backupHits.Load(), gotModel, gotAuth)
	}
	if ok, _, err := Verdict(reply.Content); err != nil || !ok {
		t.Fatalf("回复解析失败: ok=%v err=%v", ok, err)
	}

	// 主端点 503 时自动回退到备用端点
	var failoverHits atomic.Int32
	failingPrimary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failoverHits.Add(1)
		http.Error(w, "upstream down", http.StatusServiceUnavailable)
	}))
	defer failingPrimary.Close()

	rev2 := &Reviewer{
		Endpoint: func() (string, string) { return failingPrimary.URL, "primary-key" },
		FallbackEndpoints: func() []modelroute.Endpoint {
			return []modelroute.Endpoint{{BaseURL: backup.URL, APIKey: "backup-key", Model: "backup-model"}}
		},
		Timeout: 5 * time.Second,
	}
	llm2 := rev2.buildLLM("primary-model")
	if _, err := llm2.Chat(context.Background(), []triage.Message{{Role: "user", Content: "check"}}, nil); err != nil {
		t.Fatalf("主端点 503 时应自动回退到备用端点: %v", err)
	}
	if failoverHits.Load() != 1 || backupHits.Load() != 2 {
		t.Fatalf("回退次数异常: primary=%d backup=%d", failoverHits.Load(), backupHits.Load())
	}

	// 可配置 Timeout 生效
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()
	revSlow := &Reviewer{
		Endpoint: func() (string, string) { return slow.URL, "" },
		Timeout:  50 * time.Millisecond,
	}
	if _, err := revSlow.buildLLM("slow-model").Chat(context.Background(), []triage.Message{{Role: "user", Content: "hi"}}, nil); err == nil {
		t.Fatal("超时配置未生效")
	}
}
