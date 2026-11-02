package triage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

func TestBrief(t *testing.T) {
	ts := time.Date(2026, 8, 8, 14, 30, 0, 0, time.UTC)
	long := strings.Repeat("x", 400)
	ev := &ent.Event{Ts: ts, ClassUID: 1001, Source: "agent", Raw: []byte(long)}
	b := brief(ev)

	if b.Class != 1001 || b.Source != "agent" {
		t.Errorf("brief 基础字段错误: %+v", b)
	}
	if b.Ts != "2026-08-08T14:30:00Z" {
		t.Errorf("brief Ts = %q", b.Ts)
	}
	if len(b.Raw) != 303 {
		t.Errorf("过长 raw 应截断到 300+省略号，实际 %d 字符", len(b.Raw))
	}
	if b.AssetID != "" || b.Host != "" {
		t.Errorf("无资产的事件不应带主机字段: %+v", b)
	}

	id := uuid.New()
	ev.AssetID = &id
	ev.Edges.Asset = &ent.Asset{ID: id, Hostname: "pve1"}
	if b := brief(ev); b.AssetID != id.String() || b.Host != "pve1" {
		t.Errorf("brief 应带资产 ID 与主机名: %+v", b)
	}
}

func TestMakeTool(t *testing.T) {
	tool := makeTool("query_events", "检索事件", `{"type":"object"}`)
	if tool.Type != "function" || tool.Function.Name != "query_events" {
		t.Errorf("makeTool 基础字段错误: %+v", tool)
	}
	if tool.Function.Description != "检索事件" {
		t.Errorf("description 未保留: %q", tool.Function.Description)
	}
	var params map[string]string
	if err := json.Unmarshal(tool.Function.Parameters, &params); err != nil || params["type"] != "object" {
		t.Errorf("parameters 解析错误: %v", err)
	}
}

func TestLLMEnabled(t *testing.T) {
	if NewLLM("", "", "", time.Second).Enabled() {
		t.Error("Model 为空时 Enabled 应为 false")
	}
	if !NewLLM("", "llama3", "", time.Second).Enabled() {
		t.Error("Model 非空时 Enabled 应为 true")
	}
}

// Chat 请求组装与响应解析。
func TestLLMChat(t *testing.T) {
	var gotBody map[string]any
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("请求路径 = %q", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer srv.Close()

	l := NewLLM(srv.URL, "llama3", "secret", time.Second)
	got, err := l.Chat(context.Background(),
		[]Message{{Role: "user", Content: "hi"}},
		[]Tool{makeTool("t", "d", `{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if got.Content != "ok" {
		t.Errorf("Content = %q", got.Content)
	}
	if gotAuth != "Bearer secret" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	for _, k := range []string{"model", "messages", "temperature"} {
		if _, ok := gotBody[k]; !ok {
			t.Errorf("请求缺少 %q", k)
		}
	}
	if _, ok := gotBody["tools"]; !ok {
		t.Error("带 tools 时应包含 tools 字段")
	}
}

func TestLLMChatErrors(t *testing.T) {
	// 非 200 → 错误
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	l := NewLLM(srv.URL, "llama3", "", time.Second)
	if _, err := l.Chat(context.Background(), []Message{{Role: "user", Content: "x"}}, nil); err == nil {
		t.Error("500 应返回错误")
	}

	// 空 choices → 错误
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[]}`))
	}))
	defer srv2.Close()
	l2 := NewLLM(srv2.URL, "llama3", "", time.Second)
	if _, err := l2.Chat(context.Background(), []Message{{Role: "user", Content: "x"}}, nil); err == nil {
		t.Error("空 choices 应返回错误")
	}
}

func TestBriefUsesNormalizedProcessIdentity(t *testing.T) {
	id, asset, process, parent := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ev := &ent.Event{ID: id, AssetID: &asset, ProcessGUID: &process, ParentProcessGUID: &parent, Raw: []byte(`{"process_guid":"forged","parent_process_guid":"forged"}`)}
	b := briefLimit(ev, 4)
	if b.EventID != id.String() || b.ProcessGUID != process.String() || b.ParentProcessGUID != parent.String() || !b.RawTruncated {
		t.Fatalf("%+v", b)
	}
	ev.ParentProcessGUID = nil
	b = brief(ev)
	if b.ParentProcessGUID != "" {
		t.Fatal("不能从 raw 补写父进程")
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["parent_process_guid"]; exists {
		t.Fatal("未知父进程必须保持缺失")
	}
}
