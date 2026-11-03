package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// 失败原因不能带出 webhook 地址里的 token
func TestReasonStripsURL(t *testing.T) {
	err := &url.Error{Op: "Post", URL: "https://open.feishu.cn/hook/secret-token", Err: errors.New("dial tcp: i/o timeout")}
	if got := reason(err); strings.Contains(got, "secret-token") || got != "dial tcp: i/o timeout" {
		t.Errorf("原因应去掉地址：%q", got)
	}
	if got := []rune(reason(errors.New(strings.Repeat("长", 300)))); len(got) != 201 {
		t.Errorf("过长原因应截断到 200 字加省略号，got %d", len(got))
	}
}

// 接口字段平铺：前端按 status / pendingIncidents / lastSuccessAt / lastError 读
func TestHealthJSON(t *testing.T) {
	now := time.Now()
	b, _ := json.Marshal(Health{Status: "failing", PendingIncidents: 2, sendState: sendState{LastSuccessAt: &now, LastError: "x", ConsecutiveFailures: 3}})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"status", "pendingIncidents", "lastSuccessAt", "lastError", "consecutiveFailures"} {
		if _, ok := m[k]; !ok {
			t.Errorf("缺字段 %s：%s", k, b)
		}
	}
}

// 发送失败返回给调用方的错误不能带地址：推送日志、任务报告、审批回退都会原样打出来
func TestSendErrorRedactsURL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, u := range []string{
		"http://127.0.0.1:1/hook/secret-token?access_token=secret-token", // 请求失败
		"http://[::1/secret-token",                                       // 地址解析失败
	} {
		err := send(ctx, http.DefaultClient, u, "dingtalk", []byte(`{}`))
		if err == nil || strings.Contains(err.Error(), "secret-token") {
			t.Errorf("错误应去掉地址：%v", err)
		}
	}
	h := &Webhook{Client: http.DefaultClient}
	if err := h.SendTo(ctx, Target{URL: "http://127.0.0.1:1/hook/secret-token"}, "t", "b", ""); err == nil ||
		strings.Contains(err.Error(), "secret-token") || !errors.Is(err, context.Canceled) {
		t.Errorf("应去掉地址并保留取消原因：%v", err)
	}
}
