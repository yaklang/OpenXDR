package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"openxdr/server/internal/triage"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFailedControlPreservesAllAttempts(t *testing.T) {
	t.Run("默认评分思考模式", func(t *testing.T) { checkFailedControl(t, false) })
	t.Run("仅评分请求关闭思考", func(t *testing.T) { checkFailedControl(t, true) })
}

func checkFailedControl(t *testing.T, disableThinking bool) {
	expectedThinking := ""
	if disableThinking {
		expectedThinking = `{"type":"disabled"}`
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req struct {
			MaxTokens int             `json:"max_tokens"`
			Thinking  json.RawMessage `json:"thinking"`
			Messages  []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if strings.Contains(req.Messages[0].Content, "逐条审查") {
			var input struct {
				Contract string `json:"tool_contract"`
			}
			if json.Unmarshal([]byte(req.Messages[1].Content), &input) != nil || input.Contract != triage.InvestigationContract() {
				t.Error("评分器缺少实际工具能力说明")
			}
		} else if !strings.Contains(req.Messages[0].Content, triage.InvestigationContract()) {
			t.Error("生成器缺少实际工具能力说明")
		}

		content := `{"verdict":"suspicious","confidence":60,"summary":"来源未知，需要核实","kill_chain":[],"action_codes":["monitor"]}`
		if strings.Contains(req.Messages[0].Content, "逐条审查处置建议") {
			if req.MaxTokens != 8192 || string(req.Thinking) != expectedThinking {
				t.Error("独立建议评分配置错误")
			}
			content = `{"status":"pass","reason":"模拟错误评分器","quote":""}`
		} else if strings.Contains(req.Messages[0].Content, "逐条审查") {
			if req.MaxTokens != 8192 || string(req.Thinking) != expectedThinking {
				t.Error("评分配置错误")
			}
			content = `{"facts":{"status":"pass","reason":"模拟错误评分器"},"uncertainty":{"status":"pass","reason":"模拟错误评分器"},"actions":{"status":"pass","reason":"模拟错误评分器"}}`
		} else if req.MaxTokens != 0 || len(req.Thinking) != 0 {
			t.Error("快照生成应沿用生产默认参数")
		}
		if strings.Contains(req.Messages[len(req.Messages)-1].Content, "以下为离线回放的服务端证据台账") {
			content = strings.TrimSuffix(content, "}") + `,"evidence_claims":[{"evidence_id":"query-1","field":"status","value":"ok"}]}`
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": content}}}})
	}))
	defer srv.Close()
	t.Setenv("AI_BASE_URL", srv.URL)
	t.Setenv("AI_MODEL", "deepseek-flash")
	t.Setenv("AI_API_KEY", "")
	t.Setenv("TRIAGE_EVAL_JUDGE_MODEL", "deepseek-flash")
	oldFlags, oldArgs := flag.CommandLine, os.Args
	defer func() { flag.CommandLine, os.Args = oldFlags, oldArgs }()
	report := filepath.Join(t.TempDir(), "report.jsonl")
	invoke := func() int {
		flag.CommandLine = flag.NewFlagSet("triagecheck", flag.ContinueOnError)
		os.Args = []string{"triagecheck", "-live", "-cases", "../../../validation/triage/cases.json", "-out", report, "-revision", "test", "-repeats", "2"}
		if disableThinking {
			os.Args = append(os.Args, "-judge-no-thinking")
		}
		return run()
	}
	if code := invoke(); code != 1 {
		t.Fatalf("负对照失效必须失败，实际 %d", code)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(rows) != 41 || calls != 90 {
		t.Fatalf("未保留所有尝试：rows=%d calls=%d", len(rows), calls)
	}
	for _, line := range rows {
		var row struct {
			Kind    string `json:"kind"`
			Reviews []struct {
				Stage   string `json:"stage"`
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"judge_attempts"`
			Attempts []struct {
				Valid   bool `json:"structural_valid"`
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"generation_attempts"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row.Kind == "evaluation" || row.Kind == "calibration" {
			if len(row.Reviews) != 2 || row.Reviews[0].Stage != "full_review" || row.Reviews[1].Stage != "actions_review" || row.Reviews[0].Message.Content == "" || row.Reviews[1].Message.Content == "" {
				t.Fatalf("评分原文未写入报告: %s", line)
			}
		}
		if row.Kind == "evaluation" && (len(row.Attempts) != 1 || !row.Attempts[0].Valid || row.Attempts[0].Message.Content == "") {
			t.Fatalf("生成输出未写入报告: %s", line)
		}
	}
	var metadata struct {
		Judge      bool `json:"judge_no_thinking"`
		Actions    bool `json:"action_review_no_thinking"`
		Generation bool `json:"generation_no_thinking"`
	}
	if err := json.Unmarshal([]byte(rows[0]), &metadata); err != nil || metadata.Judge != disableThinking || metadata.Actions != disableThinking || metadata.Generation {
		t.Fatalf("报告未记录实际评分配置或改变了生成配置: %s", rows[0])
	}
	var summary struct {
		Complete    bool `json:"complete"`
		Evaluations int  `json:"evaluations"`
		Passed      bool `json:"automated_pass"`
		Controls    int  `json:"calibration_controls"`
		Failed      int  `json:"failed_checks"`
	}
	if err := json.Unmarshal([]byte(rows[len(rows)-1]), &summary); err != nil || !summary.Complete || summary.Evaluations != 12 || summary.Passed || summary.Controls != 27 || summary.Failed != 22 {
		t.Fatalf("错误汇总：%s", rows[len(rows)-1])
	}
	if code := invoke(); code != 2 {
		t.Fatalf("重复报告必须拒绝覆盖，实际 %d", code)
	}
	after, _ := os.ReadFile(report)
	if string(after) != string(data) || calls != 90 {
		t.Fatal("重复执行覆盖了历史结果或调用模型")
	}
}

func TestFailureReportContainsSafeDiagnostics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("secret-canary"))
	}))
	defer srv.Close()
	t.Setenv("AI_BASE_URL", srv.URL)
	t.Setenv("AI_MODEL", "test")
	t.Setenv("AI_API_KEY", "secret-canary")
	oldFlags, oldArgs := flag.CommandLine, os.Args
	defer func() { flag.CommandLine, os.Args = oldFlags, oldArgs }()
	flag.CommandLine = flag.NewFlagSet("triagecheck", flag.ContinueOnError)
	report := filepath.Join(t.TempDir(), "errors.jsonl")
	os.Args = []string{"triagecheck", "-live", "-cases", "../../../validation/triage/cases.json", "-out", report, "-revision", "test", "-repeats", "1"}
	if code := run(); code != 1 {
		t.Fatal(code)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-canary") {
		t.Fatal("报告泄露原始错误或凭据")
	}
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var row struct {
			Kind   string `json:"kind"`
			Detail struct {
				Stage  string `json:"stage"`
				Code   string `json:"code"`
				Status int    `json:"http_status"`
			} `json:"error_detail"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row.Kind != "evaluation" && row.Kind != "calibration" {
			continue
		}
		stage := "full_review"
		if row.Kind == "evaluation" {
			stage = "generation"
		}
		if row.Detail.Stage != stage || row.Detail.Code != "http_error" || row.Detail.Status != 429 {
			t.Fatalf("缺失精确诊断：%s", line)
		}
		checked++
	}
	if checked != 33 {
		t.Fatalf("失败尝试未完整保留：%d", checked)
	}
}
