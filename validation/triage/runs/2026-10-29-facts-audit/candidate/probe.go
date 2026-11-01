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
	"time"
)

type item struct {
	Case    triageeval.Case    `json:"case"`
	Control triageeval.Control `json:"control"`
}

func main() { os.Exit(run()) }
func run() int {
	if len(os.Args) != 3 {
		return 2
	}
	input, err := os.ReadFile(os.Args[1])
	if err != nil {
		return 2
	}
	var items []item
	if json.Unmarshal(input, &items) != nil || len(items) != 4 {
		return 2
	}
	f, err := os.OpenFile(os.Args[2], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 2
	}
	defer f.Close()
	write := func(v any) bool { return json.NewEncoder(f).Encode(v) == nil && f.Sync() == nil }
	sum := sha256.Sum256(input)
	if !write(map[string]any{"kind": "metadata", "started_at": time.Now().UTC(), "inputs_sha256": hex.EncodeToString(sum[:]), "judge_prompt_sha256": triageeval.PromptHash(), "actions_prompt_sha256": triageeval.ActionPromptHash(), "tool_contract": triage.InvestigationContract(), "model": os.Getenv("AI_MODEL"), "repeats": 2, "max_tokens": 8192, "no_thinking": false, "scope": "fixed_answer_grading_only"}) {
		return 2
	}
	llm := triage.NewLLM(os.Getenv("AI_BASE_URL"), os.Getenv("AI_MODEL"), os.Getenv("AI_API_KEY"), 120*time.Second)
	llm.MaxTokens = 8192
	failed := 0
	for _, it := range items {
		for repeat := 1; repeat <= 2; repeat++ {
			calls, in, out := 0, 0, 0
			llm.OnUsage = func(_ string, i, o int) { calls++; in += i; out += o }
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			started := time.Now()
			assessment, err := triageeval.Judge(ctx, llm, it.Case, it.Control.Answer)
			cancel()
			matched := err == nil && it.Control.Matches(assessment)
			if !matched {
				failed++
			}
			row := map[string]any{"kind": "assessment", "control": it.Control.ID, "repeat": repeat, "assessment": assessment, "matched": matched, "model_responses": calls, "input_tokens": in, "output_tokens": out, "elapsed_ms": time.Since(started).Milliseconds()}
			if err != nil {
				row["error_detail"] = triageeval.Diagnose(err)
			}
			if !write(row) {
				return 2
			}
			fmt.Printf("%s/%d matched=%v\n", it.Control.ID, repeat, matched)
		}
	}
	if !write(map[string]any{"kind": "summary", "complete": true, "checks": 8, "failed": failed, "finished_at": time.Now().UTC()}) {
		return 2
	}
	if failed > 0 {
		return 1
	}
	return 0
}
