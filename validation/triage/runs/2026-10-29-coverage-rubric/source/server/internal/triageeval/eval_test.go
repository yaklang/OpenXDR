package triageeval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCorpusContainsContrastingCases(t *testing.T) {
	cases, err := Load("../../../validation/triage/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 6 {
		t.Fatal("六类基线不可缺失")
	}
	counts := map[string]int{}
	for _, c := range cases {
		counts[c.ExpectedVerdict]++
	}
	if counts["benign"] == 0 || counts["malicious"] == 0 || counts["suspicious"] == 0 {
		t.Fatal("缺少良性或恶意对照")
	}
}

func TestCorpusRejectsMissingRubricAndDuplicates(t *testing.T) {
	cases, _ := Load("../../../validation/triage/cases.json")
	path := filepath.Join(t.TempDir(), "cases.json")
	for _, bad := range [][]Case{{cases[0], cases[0]}, {{ID: "missing", Name: "missing", Evidence: "x", ExpectedVerdict: "benign"}}} {
		raw, _ := json.Marshal(bad)
		os.WriteFile(path, raw, 0600)
		if _, err := Load(path); err == nil {
			t.Fatal("坏语料被接受")
		}
	}
}

func TestAssessmentFailsClosed(t *testing.T) {
	answer := json.RawMessage(`{"verdict":"suspicious","summary":"该 IP 已证明属于合法 CDN。","actions":["将整个网段加入白名单"]}`)
	good := Assessment{"facts": {"fail", "没有归属证据", "已证明属于合法 CDN", nil}, "uncertainty": {"pass", "没有超范围声称", "", nil}, "actions": {"fail", "范围超出证据", "将整个网段加入白名单", nil}}
	data, _ := json.Marshal(good)
	parsed, err := ParseAssessment(string(data), answer)
	if err != nil || parsed.Passed() {
		t.Fatal("结论标签正确不应掩盖事实/处置越界", err)
	}
	for _, raw := range []string{`{}`, `{"facts":{"status":"pass","reason":"ok"}}`, `{"facts":{"status":"pass","reason":"ok"},"uncertainty":{"status":"pass","reason":"ok"},"actions":{"status":"fail","reason":"bad","quote":"不在原文中的话"}}`} {
		if _, err := ParseAssessment(raw, answer); err == nil {
			t.Fatal("缺项或虚构引用不应通过", raw)
		}
	}
	good["facts"] = Check{"uncertain", "无法确认", "", nil}
	good["actions"] = Check{"pass", "ok", "", nil}
	data, _ = json.Marshal(good)
	parsed, err = ParseAssessment(string(data), answer)
	if err != nil || parsed.Passed() {
		t.Fatal("uncertain 不应算通过")
	}
	good["facts"] = Check{"pass", "仅测试评分结构", "", nil}
	data, _ = json.Marshal(good)
	parsed, err = ParseAssessment(string(data), answer)
	if err != nil || !parsed.Passed() {
		t.Fatal("有效评分结构解析失败")
	}
}

func TestCalibrationRequiresBothAcceptanceAndRejection(t *testing.T) {
	pass := Assessment{"facts": {Status: "pass"}, "uncertainty": {Status: "pass"}, "actions": {Status: "pass"}}
	positive := Control{}
	negative := Control{Reject: []string{"facts"}}
	if !positive.Matches(pass) || negative.Matches(pass) {
		t.Fatal("全通过评分必须仅匹配正对照")
	}
	pass["facts"] = Check{Status: "fail"}
	if positive.Matches(pass) || !negative.Matches(pass) {
		t.Fatal("负对照被识别不等于正对照也通过")
	}
	pass["facts"] = Check{Status: "uncertain"}
	if positive.Matches(pass) || negative.Matches(pass) {
		t.Fatal("不确定既不能通过正对照，也不能冒充识别负对照")
	}
}

func TestCalibrationRejectsDuplicateIDsAndUnknownDimensions(t *testing.T) {
	for _, control := range []Control{
		{ID: "base_negative", Answer: json.RawMessage(`{"verdict":"suspicious","summary":"x"}`)},
		{ID: "unknown", Answer: json.RawMessage(`{"verdict":"suspicious","summary":"x"}`), Reject: []string{"typo"}},
	} {
		cases, err := Load("../../../validation/triage/cases.json")
		if err != nil {
			t.Fatal(err)
		}
		cases[0].Controls = append(cases[0].Controls, control)
		raw, _ := json.Marshal(cases)
		path := filepath.Join(t.TempDir(), "cases.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("错误对照被接受")
		}
	}
}

func TestActionCrossCheckCannotWeakenFailure(t *testing.T) {
	pass := Check{Status: "pass", Reason: "ok"}
	fail := Check{Status: "fail", Reason: "不当隔离", Quote: "隔离"}
	for _, pair := range [][2]Check{{pass, fail}, {fail, pass}} {
		got := stricterAction(pair[0], pair[1])
		if got.Status != "fail" || len(got.Reviews) != 2 {
			t.Fatal("独立评分不得冲掉原失败")
		}
	}
	if stricterAction(pass, Check{Status: "uncertain", Reason: "待确认"}).Status != "uncertain" {
		t.Fatal("不确定不得通过")
	}
}
