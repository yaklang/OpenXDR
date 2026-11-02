//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// eventsResponseRaw 对象契约的宽松解码：字段值按 map 取，断言写起来直接。
type eventsResponseRaw struct {
	Items     []map[string]any `json:"items"`
	Truncated bool             `json:"truncated"`
	Coverage  eventsCoverage   `json:"coverage"`
}

// GET /api/events：时间窗默认 24h、关键词全文匹配、来源过滤、通配符转义。
// 响应是对象契约 {items, truncated, coverage}（P5），断言主要落在 items 上。
func TestAPIEventSearch(t *testing.T) {
	ts, _ := seed(t) // seed 里有一条 syslog 事件，raw 含 "ssh failed"

	var rows []map[string]any
	fetch := func(query string) []map[string]any {
		t.Helper()
		resp, body := get(t, ts, "/api/events?"+query)
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d: %s", resp.StatusCode, body)
		}
		rows = nil
		var out eventsResponseRaw
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		rows = out.Items
		return rows
	}

	if got := fetch(""); len(got) != 1 {
		t.Fatalf("无条件应返回 24h 内全部事件，实际 %d", len(got))
	}
	for _, value := range []string{"not-a-uuid", " ", "0190d7b0-0000-7000-8000-00000000000z"} {
		resp, body := get(t, ts, "/api/events?assetId="+url.QueryEscape(value))
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("非法 assetId %q 应返回 400，实际 %d: %s", value, resp.StatusCode, body)
		}
	}
	if got := fetch("assetId="); len(got) != 1 {
		t.Errorf("空筛选应保持未筛选行为，实际 %d", len(got))
	}
	if got := fetch("assetId=0190d7b0-0000-7000-8000-000000000000"); len(got) != 0 {
		t.Errorf("合法但不存在的资产不应返回其他事件，实际 %d", len(got))
	}
	// 取满 limit 才提示截断
	if resp, _ := get(t, ts, "/api/events?limit=1"); resp.Header.Get("X-Truncated") != "1" {
		t.Error("取满 limit 应带 X-Truncated")
	}
	if resp, _ := get(t, ts, "/api/events?limit=2"); resp.Header.Get("X-Truncated") != "" {
		t.Error("未取满 limit 不应带 X-Truncated")
	}
	if got := fetch("q=" + url.QueryEscape("ssh failed")); len(got) != 1 {
		t.Errorf("关键词应命中，实际 %d", len(got))
	}
	if got := fetch("q=nonexistent-keyword"); len(got) != 0 {
		t.Errorf("不存在的关键词不应命中，实际 %d", len(got))
	}
	if got := fetch("source=syslog&classUid=100001"); len(got) != 1 {
		t.Errorf("来源 + class 过滤应命中，实际 %d", len(got))
	}
	if got := fetch("source=agent"); len(got) != 0 {
		t.Errorf("来源不符不应命中，实际 %d", len(got))
	}
	// % 是字面量不是通配符
	if got := fetch("q=" + url.QueryEscape("%")); len(got) != 0 {
		t.Errorf("%% 应按字面量匹配不命中，实际 %d", len(got))
	}
}
