package ueba

import (
	"encoding/json"
	"testing"
)

// ueba 的纯逻辑单测不带 integration tag：首次出现检测的判定依赖 DB（见
// engine_integration_test.go），但 exePath 只是从 JSON 里取路径，先锤炼它。

func TestExePath(t *testing.T) {
	raw := json.RawMessage(`{"process":{"file":{"path":"/usr/bin/ls"}}}`)
	if got := exePath(raw); got != "/usr/bin/ls" {
		t.Errorf("exePath 应提取出 /usr/bin/ls，实际 %q", got)
	}

	// 缺失、结构不符、非法 JSON 一律返回空串，不 panic
	if got := exePath(json.RawMessage(`{}`)); got != "" {
		t.Errorf("空文档应返回空串，实际 %q", got)
	}
	if got := exePath(json.RawMessage(`{"process":123}`)); got != "" {
		t.Errorf("process 非对象应返回空串，实际 %q", got)
	}
	if got := exePath(json.RawMessage(`not-json`)); got != "" {
		t.Errorf("非法 JSON 应返回空串，实际 %q", got)
	}
}
