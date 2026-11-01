package triage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
)

func TestParseVerdictValidJSON(t *testing.T) {
	raw := `{"verdict":"malicious","confidence":95,"summary":"ok"}`
	out := parseVerdict("inc-1", raw)
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("输出应为合法 JSON，得到 %s: %v", out, err)
	}
	if got["verdict"] != "malicious" {
		t.Errorf("verdict = %v", got["verdict"])
	}
}

// LLM 常输出 markdown 围栏，内容夹在 ```json ... ``` 里，应能提取出 JSON 块。
func TestParseVerdictExtractsFromSurroundingText(t *testing.T) {
	answer := "以下是分析：\n```json\n{\"verdict\":\"suspicious\",\"confidence\":60}\n```\n完毕"
	out := parseVerdict("inc-1", answer)
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("应提取出 JSON 块，得到 %s: %v", out, err)
	}
	if got["confidence"] != float64(60) {
		t.Errorf("confidence = %v", got["confidence"])
	}
}

func TestParseVerdictInvalidJSON(t *testing.T) {
	out := parseVerdict("inc-1", "这不是 JSON")
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("回退输出也应为合法 JSON，得到 %s: %v", out, err)
	}
	if got["error"] != "unparseable" {
		t.Errorf("非法输入应标记 error=unparseable，得到 %v", got["error"])
	}
	if _, ok := got["raw"]; !ok {
		t.Error("回退应保留原始 raw")
	}
}

// 输出里夹着非法大括号（如未闭合），不应误提取，应走回退。
func TestParseVerdictBraceTrap(t *testing.T) {
	out := parseVerdict("inc-1", "某处不完整 {未闭合")
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("应回退为合法 JSON，得到 %s: %v", out, err)
	}
	if got["error"] != "unparseable" {
		t.Errorf("未闭合大括号应判为非法，得到 %v", got)
	}
}

// 超长非法输出应被截断，避免污染数据库。
func TestParseVerdictTruncatesLongAnswer(t *testing.T) {
	long := strings.Repeat("x", 5000)
	out := parseVerdict("inc-1", long)
	if len(out) > 2100 {
		t.Errorf("回退输出应截断到合理长度，实际 %d", len(out))
	}
}

func TestExecToolUnknownTool(t *testing.T) {
	e := &Engine{}
	got := e.execTool(context.Background(), "no_such_tool", "{}")
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("未知工具应返回 JSON 错误让模型继续，实际 %q", got)
	}
	if _, ok := m["error"]; !ok {
		t.Fatalf("错误应含 error 键：%v", m)
	}
	if !strings.Contains(m["error"].(string), "未知工具 no_such_tool") {
		t.Errorf("未知工具错误文本应明确，实际 %q", got)
	}
}

func TestWithModelRecordsTriageModel(t *testing.T) {
	got := withModel(json.RawMessage(`{"verdict":"benign","confidence":80}`), "glm-4.6")
	var v map[string]any
	if err := json.Unmarshal(got, &v); err != nil || v["model"] != "glm-4.6" || v["verdict"] != "benign" {
		t.Fatalf("应记下模型且保留原字段: %s", got)
	}
	// 没有模型名、或结论不是对象时原样返回
	for _, raw := range []string{`{"verdict":"benign"}`, `"x"`, `[1]`} {
		model := "m"
		if raw == `{"verdict":"benign"}` {
			model = ""
		}
		if out := withModel(json.RawMessage(raw), model); string(out) != raw {
			t.Errorf("%s 应原样返回，得到 %s", raw, out)
		}
	}
}

func TestIPFacts(t *testing.T) {
	now := time.Now()
	r := &ent.IPInfo{IP: "203.0.113.7", IpdbAsn: 64500, IpdbOrg: "Example", IpdbAt: &now, Domains: []string{"a.example", "b.example"}}
	if got := ipFacts(r); got != "离线库 AS64500 Example，国家 -；历史解析域名 a.example, b.example" {
		t.Fatalf("得到 %q", got)
	}
	if got := ipFacts(&ent.IPInfo{IP: "203.0.113.8", IpdbAt: &now}); got != "已查过，没有归属信息" {
		t.Fatalf("得到 %q", got)
	}
}
