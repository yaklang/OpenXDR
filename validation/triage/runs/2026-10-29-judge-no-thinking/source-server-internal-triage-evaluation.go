package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
)

// EvidencePromptHash 标记离线评测实际使用的生产提示词，不包含模型配置或密钥。
func EvidencePromptHash() string {
	sum := sha256.Sum256([]byte(investigationPrompt()))
	return hex.EncodeToString(sum[:])
}

// EvaluateSnapshot 仅评测给定证据快照的结论，不查生产库、不注册工具、不触发处置或通知。
// 复用生产提示词与格式修复；调查工具和采集覆盖由单独的集成/实机测试验收。
func EvaluateSnapshot(ctx context.Context, llm *LLM, evidence string, snapshots ...EvidenceSnapshot) (json.RawMessage, error) {
	return evaluateSnapshot(ctx, llm, evidence, nil, snapshots...)
}

// VerdictAttempt 仅供显式离线评测存档；结构通过不代表语义通过，不写入生产日志或事件。
type VerdictAttempt struct {
	Message         Message `json:"message"`
	FinishReason    string  `json:"finish_reason"`
	StructuralValid bool    `json:"structural_valid"`
}

// EvaluateSnapshotDetailed 保留首次输出与唯一一次修正，即使最终失败也返回已收到的输出。
func EvaluateSnapshotDetailed(ctx context.Context, llm *LLM, evidence string, snapshots ...EvidenceSnapshot) (json.RawMessage, []VerdictAttempt, error) {
	var attempts []VerdictAttempt
	observe := func(msg Message, err error) {
		attempts = append(attempts, VerdictAttempt{Message: msg, FinishReason: msg.FinishReason, StructuralValid: err == nil})
	}
	answer, err := evaluateSnapshot(ctx, llm, evidence, observe, snapshots...)
	return answer, attempts, err
}

func evaluateSnapshot(ctx context.Context, llm *LLM, evidence string, observe func(Message, error), snapshots ...EvidenceSnapshot) (json.RawMessage, error) {
	if err := ValidateEvidenceSnapshots(snapshots); err != nil {
		return nil, err
	}
	e := &Engine{LLM: llm}
	messages := []Message{{Role: "system", Content: investigationPrompt()}, {Role: "user", Content: "以下为离线证据快照，已附可用的调查结果。无法再查询；按现有证据和缺失范围作最终判断，不假设已经执行任何建议。\n" + evidence}}
	var evidenceMessages []Message
	for i, snapshot := range snapshots {
		call := ToolCall{ID: fmt.Sprintf("snapshot-%d", i+1), Type: "function"}
		call.Function.Name = snapshot.Tool
		call.Function.Arguments = "{}"
		evidenceMessages = append(evidenceMessages, Message{Role: "assistant", ToolCalls: []ToolCall{call}}, Message{Role: "tool", ToolCallID: call.ID, Content: string(snapshot.Result)})
	}
	if len(snapshots) > 0 {
		raw, _ := json.Marshal(snapshots)
		messages = append(messages, Message{Role: "user", Content: "离线工具结果快照：" + string(raw)})
		ledger, _ := json.Marshal(queryEvidenceFrom(evidenceMessages))
		messages = append(messages, Message{Role: "system", Content: "以下为离线回放的服务端证据台账，工具结果来自测试夹具，不代表本次实际执行。可引用其字段：" + string(ledger)})
	}
	msg, err := e.chat(ctx, messages, nil)
	if err != nil {
		return nil, err
	}
	answer, err := e.finishVerdictObserved(ctx, messages, msg, evidenceMessages, observe)
	if err != nil {
		return nil, err
	}
	return parseVerdict("offline-evaluation", answer), nil
}

// EvidenceSnapshot 是离线回放夹具，不是可由生产接口提交的工具结果。
type EvidenceSnapshot struct {
	Tool   string          `json:"tool"`
	Result json.RawMessage `json:"result"`
}

func ValidateEvidenceSnapshots(snapshots []EvidenceSnapshot) error {
	if len(snapshots) > 24 {
		return fmt.Errorf("离线工具快照过多")
	}
	for _, snapshot := range snapshots {
		if !slices.Contains([]string{"query_events", "process_lineage", "host_alerts", "process_baseline"}, snapshot.Tool) {
			return fmt.Errorf("未知离线工具")
		}
		var result map[string]any
		if len(snapshot.Result) > 128*1024 || json.Unmarshal(snapshot.Result, &result) != nil || result == nil {
			return fmt.Errorf("离线工具结果必须是有界 JSON 对象")
		}
	}
	return nil
}
