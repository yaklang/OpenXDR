package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestStructuredActionsRejectUnsupportedAdvice(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		valid        bool
	}{
		{"缺失", ``, false},
		{"空数组", `,"action_codes":[]`, false},
		{"伪造工具参数", `,"action_codes":[{"code":"trace_process","hours":1}]`, false},
		{"未知能力", `,"action_codes":["remove_raw_limit"]`, false},
		{"重复代码", `,"action_codes":["monitor","monitor"]`, false},
		{"自由文本绕过", `,"action_codes":["monitor"],"actions":["放宽 limit 获取全文"]`, false},
		{"可疑不能结案", `,"action_codes":["review_closure"]`, false},
		{"可疑不能申请响应", `,"action_codes":["review_response"]`, false},
		{"合法调查", `,"action_codes":["verify_source","collect_original_records","monitor"]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer := `{"verdict":"suspicious","confidence":60,"summary":"待核实","kill_chain":[]` + tc.fields + `}`
			out, err := bindEvidence(Message{Content: answer}, nil)
			if (err == nil) != tc.valid {
				t.Fatalf("out=%s err=%v", out, err)
			}
			if !tc.valid {
				return
			}
			var result struct {
				Actions []string `json:"actions"`
			}
			if json.Unmarshal([]byte(out), &result) != nil || len(result.Actions) != 3 {
				t.Fatal(out)
			}
			if !strings.Contains(result.Actions[1], "不能取消正文裁剪") {
				t.Fatal("建议未使用服务端固定文案")
			}
		})
	}
}

func TestActionVerdictScopes(t *testing.T) {
	for _, tc := range []struct{ verdict, code string }{{"benign", "review_closure"}, {"malicious", "review_response"}, {"malicious", "hunt_related"}} {
		v := map[string]any{"verdict": tc.verdict, "action_codes": []any{tc.code}}
		if err := bindActions(v); err != nil {
			t.Fatal(err)
		}
		if len(v["actions"].([]string)) != 1 {
			t.Fatal(v)
		}
	}
	// 历史 JSON 仅解析和展示，不要求升级为新格式。
	historical := `{"verdict":"benign","confidence":80,"summary":"旧结论","actions":["历史建议"]}`
	if string(parseVerdict("history", historical)) != historical {
		t.Fatal("历史结论被重写")
	}
}

func TestActionCorrectionHasSingleAttempt(t *testing.T) {
	invalid := `{"verdict":"suspicious","confidence":60,"summary":"待核实","action_codes":["remove_raw_limit"]}`
	valid := `{"verdict":"suspicious","confidence":60,"summary":"待核实","action_codes":["collect_original_records"]}`
	for _, repaired := range []bool{true, false} {
		t.Run(fmt.Sprint(repaired), func(t *testing.T) {
			correction := invalid
			if repaired {
				correction = valid
			}
			llm, calls := verdictLLM(t, []Message{{Role: "assistant", Content: invalid}, {Role: "assistant", Content: correction}})
			answer, err := (&Engine{LLM: llm}).investigate(context.Background(), "调查结果正文被裁剪")
			if *calls != 2 || (err == nil) != repaired {
				t.Fatalf("calls=%d err=%v", *calls, err)
			}
			if repaired && !strings.Contains(answer, "不能取消正文裁剪") {
				t.Fatal(answer)
			}
		})
	}
}
