package triage

import (
	"context"
	"errors"
)

const huntPrompt = `你是安全狩猎助手，帮分析师在 XDR 数据里找答案。
用工具查证后回答，不要凭空推测；查不到就直说没有找到相关数据。
回答用中文，简洁到点，先给结论再给证据（时间、主机、进程、IP 等具体值）。
不要输出 JSON，用自然语言和必要的列表。`

// ErrLLMDisabled 未配置模型时的狩猎请求。
var ErrLLMDisabled = errors.New("AI 未启用")

// Hunt 自然语言狩猎：模型用与研判相同的只读工具查数据后作答。
//
// 刻意不做自然语言到 SQL 的翻译——那等于把任意查询权交给模型。
// 工具的参数空间是受限且转义过的，模型再怎么发挥也越不出这个边界。
func (e *Engine) Hunt(ctx context.Context, question string) (string, []Step, error) {
	if !e.LLM.Enabled() {
		return "", nil, ErrLLMDisabled
	}
	return e.toolLoop(ctx, []Message{
		{Role: "system", Content: huntPrompt},
		{Role: "user", Content: question},
	}, "调查轮数已用尽，基于以上已查到的信息直接回答分析师的问题。")
}
