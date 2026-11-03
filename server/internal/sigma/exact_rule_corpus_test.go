package sigma

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// 按规则 ID 对拍正反例（validation/exact-rule-cases.json），不让已有宽泛规则替被测规则掩盖漏报。
func TestExactRuleCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	engine, report := LoadDirReport(filepath.Join(root, "rules"))
	if report.Loaded != report.Total {
		t.Fatalf("规则加载不完整: %+v", report)
	}
	data, err := os.ReadFile(filepath.Join(root, "validation", "exact-rule-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name   string         `json:"name"`
		Rule   string         `json:"rule"`
		Class  int            `json:"class"`
		OS     string         `json:"os"`
		Event  map[string]any `json:"event"`
		Hit    bool           `json:"hit"`
		Signal bool           `json:"signal"`
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 100 {
		t.Fatal("缺少正负语料")
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			hits := engine.Evaluate(tc.Class, tc.OS, tc.Event)
			if tc.Signal {
				for _, r := range hits {
					if r.ID == tc.Rule {
						t.Fatal("信号不应直接告警")
					}
				}
				hits = engine.EvaluateSignals(tc.Class, tc.OS, tc.Event)
			}
			found := false
			for _, r := range hits {
				if r.ID == tc.Rule {
					found = true
				}
			}
			if found != tc.Hit {
				t.Fatalf("规则 %s 命中=%v，期望=%v", tc.Rule, found, tc.Hit)
			}
		})
	}
}
