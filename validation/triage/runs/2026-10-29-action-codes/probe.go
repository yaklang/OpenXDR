package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"openxdr/server/internal/triage"
	"openxdr/server/internal/triageeval"
)

func main() { os.Exit(run()) }
func run() int {
	if len(os.Args) != 3 {
		return 2
	}
	cases, err := triageeval.Load(os.Args[1])
	if err != nil {
		return 2
	}
	input, err := os.ReadFile(os.Args[1])
	if err != nil {
		return 2
	}
	f, err := os.OpenFile(os.Args[2], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 2
	}
	defer f.Close()
	write := func(v any) bool { return json.NewEncoder(f).Encode(v) == nil && f.Sync() == nil }
	digest := func(s []byte) string { h := sha256.Sum256(s); return hex.EncodeToString(h[:]) }
	model := os.Getenv("AI_MODEL")
	if !write(map[string]any{"kind": "metadata", "started_at": time.Now().UTC(), "model": model, "prompt_sha256": triage.EvidencePromptHash(), "cases_sha256": digest(input), "actions_sha256": digest([]byte(triage.ActionContract())), "tool_contract_sha256": digest([]byte(triage.InvestigationContract())), "scope": "generation_and_server_validation_only", "calibration_run": false, "semantic_judge_run": false, "repeats": 2, "cases": len(cases), "no_thinking": false, "max_tokens": 0}) {
		return 2
	}
	llm := triage.NewLLM(os.Getenv("AI_BASE_URL"), model, os.Getenv("AI_API_KEY"), 120*time.Second)
	failures := 0
	for _, c := range cases {
		for repeat := 1; repeat <= 2; repeat++ {
			responses, inputTokens, outputTokens := 0, 0, 0
			llm.OnUsage = func(_ string, input, output int) { responses++; inputTokens += input; outputTokens += output }
			started := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			answer, err := triage.EvaluateSnapshot(ctx, llm, c.Evidence, c.ToolSnapshots...)
			cancel()
			row := map[string]any{"kind": "evaluation", "case": c.ID, "repeat": repeat, "answer": answer, "structural_valid": err == nil, "elapsed_ms": time.Since(started).Milliseconds(), "model_responses": responses, "input_tokens": inputTokens, "output_tokens": outputTokens, "manual_review": "pending"}
			if err != nil {
				failures++
				row["error_detail"] = triageeval.Diagnose(err)
			} else {
				got, _ := triageeval.Verdict(answer)
				row["verdict_match"] = got == c.ExpectedVerdict
			}
			if !write(row) {
				return 2
			}
			fmt.Printf("%s/%d structure=%v\n", c.ID, repeat, err == nil)
		}
	}
	if !write(map[string]any{"kind": "summary", "complete": true, "evaluations": len(cases) * 2, "structural_failures": failures, "semantic_acceptance": "not_evaluated", "finished_at": time.Now().UTC()}) {
		return 2
	}
	if failures > 0 {
		return 1
	}
	return 0
}
