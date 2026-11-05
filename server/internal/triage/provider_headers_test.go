package triage

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type providerTransport func(*http.Request) (*http.Response, error)

func (f providerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGoSubscriptionAttributionAndToolRoundtrip(t *testing.T) {
	l := NewLLM("https://opencode.ai/inference/go/v1", "glm-5.3-flash", "test-key", time.Second)
	var first string
	calls := 0
	l.http = &http.Client{Transport: providerTransport(func(r *http.Request) (*http.Response, error) {
		sid := r.Header.Get("x-opencode-session")
		if _, err := uuid.Parse(sid); err != nil {
			t.Fatal("缺少真实会话UUID")
		}
		if first == "" {
			first = sid
		} else if first != sid {
			t.Fatal("工具往返丢失会话归属")
		}
		if r.Header.Get("x-opencode-client") != "pi" {
			t.Fatal("缺少客户端归属")
		}
		calls++
		body := `{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`
		if calls == 1 {
			body = `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"probe","arguments":"{}"}}]}}]}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	tool := makeTool("probe", "只读探测", `{"type":"object","properties":{}}`)
	msgs := []Message{{Role: "user", Content: "调用probe"}}
	answer, err := l.Chat(context.Background(), msgs, []Tool{tool})
	if err != nil || len(answer.ToolCalls) != 1 {
		t.Fatal(err)
	}
	msgs = append(msgs, answer, Message{Role: "tool", ToolCallID: "call-1", Content: `{"ok":true}`})
	answer, err = l.Chat(context.Background(), msgs, []Tool{tool})
	if err != nil || answer.Content != "OK" || calls != 2 {
		t.Fatal("工具回执往返失败", err)
	}
	other := NewLLM(l.BaseURL, l.Model, "test-key", time.Second)
	if other.sessionID == first {
		t.Fatal("不同调用会话共享归属ID")
	}
}

func TestProviderHeadersDoNotLeakToOtherHosts(t *testing.T) {
	for _, host := range []string{"https://api.deepseek.com/v1", "https://opencode.ai.example.invalid/v1", "http://127.0.0.1:8080/v1"} {
		l := NewLLM(host, "model", "", time.Second)
		l.http = &http.Client{Transport: providerTransport(func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("x-opencode-session") != "" || r.Header.Get("x-opencode-client") != "" {
				t.Fatal("非供应商端点收到专用header")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"choices":[{"message":{"content":"OK"}}]}`)), Header: make(http.Header)}, nil
		})}
		if _, err := l.Chat(context.Background(), nil, nil); err != nil {
			t.Fatal(err)
		}
	}
}
