package notify

import (
	"encoding/json"
	"errors"
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
