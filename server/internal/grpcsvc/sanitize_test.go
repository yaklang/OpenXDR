package grpcsvc

import (
	"encoding/json"
	"testing"
)

func TestSanitizeRawJSON_strips_nul(t *testing.T) {
	// 采集端带上来的 cmdline 可能带结尾 NUL（Windows UNICODE_STRING 长度计入终止符）
	in := json.RawMessage(`{"process":{"cmd_line":"cmd.exe /c whoami\u0000","pid":1}}`)
	out := sanitizeRawJSON(in)
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("产物应是合法 JSON: %v", err)
	}
	cmd := v["process"].(map[string]any)["cmd_line"].(string)
	if cmd != "cmd.exe /c whoami" {
		t.Fatalf("NUL 未被剥掉: %q", cmd)
	}
}

func TestSanitizeRawJSON_nested_and_array(t *testing.T) {
	in := json.RawMessage(`{"a":[{"b":"x\u0000y"}],"c":"d\u0000"}`)
	out := sanitizeRawJSON(in)
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("产物应是合法 JSON: %v", err)
	}
	if v["a"].([]any)[0].(map[string]any)["b"].(string) != "xy" {
		t.Fatal("嵌套数组里的 NUL 未被剥掉")
	}
	if v["c"].(string) != "d" {
		t.Fatal("顶层字符串里的 NUL 未被剥掉")
	}
}

func TestSanitizeRawJSON_keeps_valid_json(t *testing.T) {
	in := json.RawMessage(`{"process":{"cmd_line":"uname -a","pid":42}}`)
	out := sanitizeRawJSON(in)
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("合法输入被破坏: %v", err)
	}
	if v["process"].(map[string]any)["cmd_line"].(string) != "uname -a" {
		t.Fatal("正常内容被改动")
	}
}

func TestSanitizeRawJSON_bad_json_returns_empty(t *testing.T) {
	out := sanitizeRawJSON(json.RawMessage(`{not json`))
	if string(out) != "{}" {
		t.Fatalf("坏 JSON 应降级为 {}，实际 %s", out)
	}
}
