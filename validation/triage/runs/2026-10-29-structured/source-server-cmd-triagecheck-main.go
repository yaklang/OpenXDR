// triagecheck 默认仅校验脱敏回归集；-live 显式调用模型，逐次留证，不接数据库或主机工具。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"openxdr/server/internal/triage"
	"openxdr/server/internal/triageeval"
)

type usage struct {
	Input  int `json:"input_tokens"`
	Output int `json:"output_tokens"`
}

func (u *usage) record(_ string, input, output int) { u.Input += input; u.Output += output }

func main() { os.Exit(run()) }
func run() int {
	casesPath := flag.String("cases", "../validation/triage/cases.json", "脱敏回归集")
	live := flag.Bool("live", false, "显式调用真实模型（产生费用）")
	output := flag.String("out", "", "新建 JSONL 报告路径，拒绝覆盖")
	repeats := flag.Int("repeats", 2, "每个样本重复次数（1–10）")
	revision := flag.String("revision", "", "记录待测代码版本")
	flag.Parse()
	cases, err := triageeval.Load(*casesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if !*live {
		fmt.Printf("已离线校验 %d 类样本及正反对照；未调用模型，未评估模型质量。\n", len(cases))
		return 0
	}
	base, model, key := os.Getenv("AI_BASE_URL"), os.Getenv("AI_MODEL"), os.Getenv("AI_API_KEY")
	if base == "" || model == "" || *output == "" || *revision == "" || *repeats < 1 || *repeats > 10 {
		fmt.Fprintln(os.Stderr, "需配置 AI_BASE_URL/AI_MODEL，并提供 -out/-revision 与 1–10 次 repeats；密钥仅从 AI_API_KEY 读取")
		return 2
	}
	judgeModel := os.Getenv("TRIAGE_EVAL_JUDGE_MODEL")
	if judgeModel == "" {
		judgeModel = model
	}
	f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "无法新建报告，拒绝覆盖已有结果")
		return 2
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	write := func(v any) bool {
		if enc.Encode(v) != nil || f.Sync() != nil {
			fmt.Fprintln(os.Stderr, "报告写入失败，停止评测")
			return false
		}
		return true
	}
	raw, err := os.ReadFile(*casesPath)
	if err != nil {
		return 2
	}
	sum := sha256.Sum256(raw)
	if !write(map[string]any{
		"kind":                      "metadata",
		"started_at":                time.Now().UTC(),
		"revision":                  *revision,
		"prompt_sha256":             triage.EvidencePromptHash(),
		"judge_prompt_sha256":       triageeval.PromptHash(),
		"action_prompt_sha256":      triageeval.ActionPromptHash(),
		"action_review_no_thinking": false,
		"action_review_max_tokens":  8192,
		"cases_sha256":              hex.EncodeToString(sum[:]),
		"model":                     model,
		"judge_model":               judgeModel,
		"same_model_judge":          model == judgeModel,
		"repeats":                   *repeats,
		"cases":                     len(cases),
		"manual_review":             "pending",
		"scope":                     "evidence_snapshot_only",
		"generation_no_thinking":    false,
		"generation_max_tokens":     0,
		"judge_no_thinking":         false,
		"judge_max_tokens":          8192,
	}) {
		return 2
	}
	llm := triage.NewLLM(base, model, key, 120*time.Second)
	// 与生产 newLLM 一致，不覆盖供应商思考和输出预算。
	judge := triage.NewLLM(base, judgeModel, key, 120*time.Second)
	judge.MaxTokens = 8192
	failed := 0
	completed := 0
	controls := 0
	for _, c := range cases {
		for _, control := range c.Calibration() {
			var used usage
			judge.OnUsage = used.record
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
			assessment, judgeErr := triageeval.Judge(ctx, judge, c, control.Answer)
			cancel()
			passed := judgeErr == nil && control.Matches(assessment)
			row := map[string]any{"kind": "calibration", "case": c.ID, "control": control.ID, "expected_reject": control.Reject, "passed": passed, "answer": control.Answer, "assessment": assessment, "usage": used}
			if judgeErr != nil {
				row["error_stage"] = "calibration"
			}
			if !passed {
				failed++
			}
			controls++
			if !write(row) {
				return 2
			}
		}

		for repeat := 1; repeat <= *repeats; repeat++ {
			var generatedUsage, judgeUsage usage
			llm.OnUsage = generatedUsage.record
			judge.OnUsage = judgeUsage.record
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			answer, genErr := triage.EvaluateSnapshot(ctx, llm, c.Evidence, c.ToolSnapshots...)
			cancel()
			genMS := time.Since(start).Milliseconds()
			row := map[string]any{"kind": "evaluation", "case": c.ID, "repeat": repeat, "answer": answer, "expected_verdict": c.ExpectedVerdict, "generation_ms": genMS, "generation_usage": generatedUsage, "manual_review": "pending"}
			passed := false
			if genErr != nil {
				row["error_stage"] = "generation_or_format"
			} else {
				got, err := triageeval.Verdict(answer)
				row["verdict_match"] = err == nil && got == c.ExpectedVerdict
				start = time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
				assessment, judgeErr := triageeval.Judge(ctx, judge, c, answer)
				cancel()
				row["assessment"] = assessment
				row["judge_ms"] = time.Since(start).Milliseconds()
				row["judge_usage"] = judgeUsage
				if judgeErr != nil {
					row["error_stage"] = "assessment"
				}
				passed = err == nil && got == c.ExpectedVerdict && judgeErr == nil && assessment.Passed()
			}
			row["automated_pass"] = passed
			completed++
			if !passed {
				failed++
			}
			if !write(row) {
				return 2
			}
			fmt.Printf("%s 第 %d 次：自动检查通过=%v（仍需人工复核）\n", c.ID, repeat, passed)
		}
	}
	if !write(map[string]any{"kind": "summary", "finished_at": time.Now().UTC(), "complete": true, "evaluations": completed, "calibration_controls": controls, "failed_checks": failed, "automated_pass": failed == 0, "manual_review": "pending"}) {
		return 2
	}
	if failed > 0 {
		return 1
	}
	return 0
}
