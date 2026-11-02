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
	sum := sha256.Sum256([]byte(systemPrompt))
	return hex.EncodeToString(sum[:])
}

// EvaluateSnapshot 仅评测给定证据快照的结论，不查生产库、不注册工具、不触发处置或通知。
// 复用生产提示词与格式修复；调查工具和采集覆盖由单独的集成/实机测试验收。
func EvaluateSnapshot(ctx context.Context, llm *LLM, evidence string, snapshots ...EvidenceSnapshot) (json.RawMessage, error) {
	if err := ValidateEvidenceSnapshots(snapshots); err != nil {
		return nil, err
	}
	e := &Engine{LLM: llm}
	messages := []Message{{Role: "system", Content: systemPrompt}, {Role: "user", Content: "以下为离线证据快照，已附可用的调查结果。无法再查询；按现有证据和缺失范围作最终判断，不假设已经执行任何建议。\n" + evidence}}
	for i, snapshot := range snapshots {
		call := ToolCall{ID: fmt.Sprintf("snapshot-%d", i+1), Type: "function"}
		call.Function.Name = snapshot.Tool
		call.Function.Arguments = "{}"
		messages = append(messages, Message{Role: "assistant", ToolCalls: []ToolCall{call}}, Message{Role: "tool", ToolCallID: call.ID, Content: string(snapshot.Result)})
	}
	if len(snapshots) > 0 {
		ledger, _ := json.Marshal(queryEvidenceFrom(messages))
		messages = append(messages, Message{Role: "system", Content: "以下为离线回放的服务端证据台账，工具结果来自测试夹具，不代表本次实际执行。可引用其字段：" + string(ledger)})
	}
	msg, err := e.chat(ctx, messages, nil)
	if err != nil {
		return nil, err
	}
	answer, err := e.finishVerdict(ctx, messages, msg)
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
