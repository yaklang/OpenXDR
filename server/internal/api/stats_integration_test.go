//go:build integration

package api

import (
	"encoding/json"
	"testing"
)

// GET /api/stats 概览统计：漏斗计数、状态分布、趋势分桶、Top 规则、资产在线。
func TestAPIStats(t *testing.T) {
	ts, _ := seed(t)
	resp, body := get(t, ts, "/api/stats")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	var s struct {
		Events24h         int            `json:"events24h"`
		Alerts24h         int            `json:"alerts24h"`
		OpenIncidents     int            `json:"openIncidents"`
		IncidentsByStatus map[string]int `json:"incidentsByStatus"`
		AlertTrend        []struct {
			Count int `json:"count"`
		} `json:"alertTrend"`
		TopRules []struct {
			RuleID    string  `json:"ruleId"`
			RuleTitle *string `json:"ruleTitle"`
			Count     int     `json:"count"`
		} `json:"topRules"`
		AssetsTotal  int `json:"assetsTotal"`
		AssetsOnline int `json:"assetsOnline"`
	}
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatal(err)
	}

	if s.Events24h != 1 || s.Alerts24h != 1 || s.OpenIncidents != 1 {
		t.Errorf("漏斗计数不对：events=%d alerts=%d open=%d", s.Events24h, s.Alerts24h, s.OpenIncidents)
	}
	if s.IncidentsByStatus["open"] != 1 {
		t.Errorf("状态分布不对：%v", s.IncidentsByStatus)
	}
	if len(s.AlertTrend) != 24 {
		t.Fatalf("趋势应为 24 桶，实际 %d", len(s.AlertTrend))
	}
	var sum int
	for _, b := range s.AlertTrend {
		sum += b.Count
	}
	if sum != 1 {
		t.Errorf("趋势总和应为 1，实际 %d", sum)
	}
	if len(s.TopRules) != 1 || s.TopRules[0].Count != 1 {
		t.Fatalf("Top 规则不对：%+v", s.TopRules)
	}
	if s.TopRules[0].RuleTitle == nil || *s.TopRules[0].RuleTitle != "Sample Rule" {
		t.Errorf("规则标题应解析为 Sample Rule，实际 %v", s.TopRules[0].RuleTitle)
	}
	// last_seen 默认为创建时间，刚建的资产在 5 分钟在线窗口内
	if s.AssetsTotal != 1 || s.AssetsOnline != 1 {
		t.Errorf("资产计数不对：total=%d online=%d", s.AssetsTotal, s.AssetsOnline)
	}
}
