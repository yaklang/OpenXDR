package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"openxdr/server/internal/triage"
	"openxdr/server/internal/triageeval"
	"os"
	"strings"
	"time"
)

func main()                  { os.Exit(run()) }
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func run() int {
	if len(os.Args) == 4 && os.Args[1] == "--probe" {
		return probe(os.Args[2], os.Args[3])
	}
	if len(os.Args) != 4 {
		return 2
	}
	source, err := os.ReadFile(os.Args[1])
	if err != nil {
		return 2
	}
	rawCases, err := os.ReadFile(os.Args[2])
	if err != nil {
		return 2
	}
	cases, err := triageeval.Load(os.Args[2])
	if err != nil {
		return 2
	}
	byID := map[string]triageeval.Case{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	rows := []map[string]json.RawMessage{}
	for _, line := range strings.Split(strings.TrimSpace(string(source)), "\n") {
		var r map[string]json.RawMessage
		if json.Unmarshal([]byte(line), &r) != nil {
			return 2
		}
		rows = append(rows, r)
	}
	if len(rows) < 2 {
		return 2
	}
	val := func(r map[string]json.RawMessage, k string) string { var s string; json.Unmarshal(r[k], &s); return s }
	meta := rows[0]
	if val(meta, "kind") != "metadata" || val(rows[len(rows)-1], "kind") != "summary" || string(rows[len(rows)-1]["complete"]) != "true" {
		return 2
	}
	if val(meta, "cases_sha256") != digest(rawCases) || val(meta, "prompt_sha256") != triage.EvidencePromptHash() || val(meta, "judge_prompt_sha256") != triageeval.PromptHash() || val(meta, "judge_model") != os.Getenv("AI_MODEL") {
		return 2
	}
	// 只接受完整生成的原始执行；已有评分错误需明确记录并单独重试，不能冒充新生成。
	seen := map[string]bool{}
	evals, controls := 0, 0
	for _, r := range rows[1 : len(rows)-1] {
		kind, cid := val(r, "kind"), val(r, "case")
		if _, ok := byID[cid]; !ok {
			return 2
		}
		if r["error_stage"] != nil && val(r, "error_stage") != "assessment" && val(r, "error_stage") != "calibration" {
			return 2
		}
		key := kind + "/" + cid + "/" + string(r["repeat"]) + val(r, "control")
		if seen[key] {
			return 2
		}
		seen[key] = true
		switch kind {
		case "evaluation":
			evals++
		case "calibration":
			controls++
		default:
			return 2
		}
		var a triageeval.Assessment
		if (json.Unmarshal(r["assessment"], &a) != nil || len(a) != 3) && val(r, "error_stage") != "assessment" && val(r, "error_stage") != "calibration" {
			return 2
		}
	}
	var repeats int
	json.Unmarshal(meta["repeats"], &repeats)
	expectedControls := 0
	for _, c := range cases {
		for i := 1; i <= repeats; i++ {
			if !seen[fmt.Sprintf("evaluation/%s/%d", c.ID, i)] {
				return 2
			}
		}
		for _, control := range c.Calibration() {
			expectedControls++
			if !seen["calibration/"+c.ID+"/"+control.ID] {
				return 2
			}
		}
	}
	if evals != len(cases)*repeats || controls != expectedControls {
		return 2
	}
	f, err := os.OpenFile(os.Args[3], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 2
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	put := func(r map[string]json.RawMessage, k string, v any) { b, _ := json.Marshal(v); r[k] = b }
	write := func(v any) bool { return enc.Encode(v) == nil && f.Sync() == nil }
	put(meta, "source_run_sha256", digest(source))
	put(meta, "review_method", "reuse_valid_full_reviews_retry_errors_add_independent_actions")
	put(meta, "action_prompt_sha256", triageeval.ActionPromptHash())
	put(meta, "action_review_no_thinking", false)
	put(meta, "action_review_max_tokens", 8192)
	put(meta, "action_review_started_at", time.Now().UTC())
	if !write(meta) {
		return 2
	}
	llm := triage.NewLLM(os.Getenv("AI_BASE_URL"), os.Getenv("AI_MODEL"), os.Getenv("AI_API_KEY"), 120*time.Second)
	failures := 0
	for _, r := range rows[1 : len(rows)-1] {
		var a triageeval.Assessment
		json.Unmarshal(r["assessment"], &a)
		in, out := 0, 0
		llm.OnUsage = func(_ string, i, o int) { in += i; out += o }
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		var updated triageeval.Assessment
		var err error
		if val(r, "error_stage") == "assessment" || val(r, "error_stage") == "calibration" {
			put(r, "source_error_stage", val(r, "error_stage"))
			put(r, "full_review_retried", true)
			llm.MaxTokens = 8192
			updated, err = triageeval.Judge(ctx, llm, byID[val(r, "case")], r["answer"])
			delete(r, "error_stage")
		} else {
			updated, err = triageeval.CrossCheckActions(ctx, llm, byID[val(r, "case")], r["answer"], a)
		}
		cancel()
		put(r, "assessment", updated)
		put(r, "additional_review_usage", map[string]int{"input_tokens": in, "output_tokens": out})
		passed := err == nil
		if err != nil {
			put(r, "error_stage", "action_review")
		}
		if val(r, "kind") == "evaluation" {
			passed = passed && string(r["verdict_match"]) == "true" && updated.Passed()
			put(r, "automated_pass", passed)
		} else {
			matched := false
			for _, c := range byID[val(r, "case")].Calibration() {
				if c.ID == val(r, "control") {
					matched = c.Matches(updated)
				}
			}
			passed = passed && matched
			put(r, "passed", passed)
		}
		if !passed {
			failures++
		}
		if !write(r) {
			return 2
		}
		fmt.Println(val(r, "case"), val(r, "control"), string(r["repeat"]), passed)
	}
	if !write(map[string]any{"kind": "summary", "complete": true, "evaluations": evals, "calibration_controls": controls, "failed_checks": failures, "automated_pass": failures == 0, "manual_review": "pending", "finished_at": time.Now().UTC()}) {
		return 2
	}
	if failures > 0 {
		return 1
	}
	return 0
}

func probe(path, out string) int {
	cases, err := triageeval.Load(path)
	if err != nil {
		return 2
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 2
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	llm := triage.NewLLM(os.Getenv("AI_BASE_URL"), os.Getenv("AI_MODEL"), os.Getenv("AI_API_KEY"), 120*time.Second)
	failed := 0
	for _, c := range cases {
		for _, control := range c.Calibration() {
			expected := "pass"
			for _, d := range control.Reject {
				if d == "actions" {
					expected = "fail"
				}
			}
			initial := triageeval.Assessment{"facts": {Status: "pass"}, "uncertainty": {Status: "pass"}, "actions": {Status: "pass", Reason: "只用于独立建议检查，其他维度未评测"}}
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
			result, err := triageeval.CrossCheckActions(ctx, llm, c, control.Answer, initial)
			cancel()
			ok := err == nil && result["actions"].Status == expected
			if !ok {
				failed++
			}
			if enc.Encode(map[string]any{"case": c.ID, "control": control.ID, "expected_actions": expected, "passed": ok, "actions": result["actions"]}) != nil || f.Sync() != nil {
				return 2
			}
		}
	}
	enc.Encode(map[string]any{"scope": "actions_only_calibration_probe", "failed": failed})
	fmt.Println("独立建议校准失败数", failed)
	if failed > 0 {
		return 1
	}
	return 0
}
