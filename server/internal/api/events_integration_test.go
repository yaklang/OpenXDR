//go:build integration

package api

import (
	"encoding/json"
	"net/url"
	"testing"
)

// GET /api/events：时间窗默认 24h、关键词全文匹配、来源过滤、通配符转义。
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
		if err := json.Unmarshal(body, &rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}

	if got := fetch(""); len(got) != 1 {
		t.Fatalf("无条件应返回 24h 内全部事件，实际 %d", len(got))
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
