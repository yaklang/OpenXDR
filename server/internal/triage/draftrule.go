package triage

import (
	"context"
	"fmt"
	"strings"

	"openxdr/server/internal/sigma"
)

const draftRulePrompt = `你是检测工程师，把一次威胁狩猎的发现转写成一条 Sigma 检测规则。
只输出 YAML 规则本身，不要 markdown 代码块，不要任何解释文字。

本引擎的 Sigma 方言限制：
- 单事件匹配，不支持聚合条件（count/near 等）与跨事件逻辑
- logsource.category 只支持：process_creation、file_event、registry_set、
  authentication、network_connection、dns_query、application
- 字段名用 Sigma 标准名（CommandLine、Image、TargetFilename、DestinationIp、
  DestinationPort、query、User、TargetObject 等），或直接写 OCSF 原始事件的
  dot path（如 process.cmd_line、tls.sni、status_id）
- 修饰符支持 contains / startswith / endswith / re / all

必填：id（新的 UUID v4）、title、description、tags（attack.战术名 与
attack.tXXXX 技术编号）、logsource、detection、level。

规则要抓"行为"而不是本次狩猎的具体值：IP、主机名、时间这类一次性指标
不要写死，命令行模式、路径特征、技术手法才值得沉淀为规则。`

// 编译失败回喂模型的重试上限。两轮修不好的草稿，人也该亲自看看了
const draftAttempts = 3

// DraftRule 把一轮狩猎问答转写为 Sigma 规则草稿。
// 产出必须通过引擎编译器校验，编译错误回喂模型重试——
// 交给分析师的草稿至少保证"保存后真的能生效"。
func (e *Engine) DraftRule(ctx context.Context, question, answer string) (string, error) {
	if !e.LLM.Enabled() {
		return "", ErrLLMDisabled
	}
	msgs := []Message{
		{Role: "system", Content: draftRulePrompt},
		{Role: "user", Content: fmt.Sprintf("狩猎问题：%s\n\n狩猎结论：%s", question, answer)},
	}
	var lastErr error
	for i := 0; i < draftAttempts; i++ {
		reply, err := e.LLM.Chat(ctx, msgs, nil)
		if err != nil {
			return "", err
		}
		draft := stripFence(reply.Content)
		if _, err := sigma.Compile([]byte(draft)); err != nil {
			lastErr = err
			msgs = append(msgs, reply, Message{Role: "user",
				Content: "规则编译失败：" + err.Error() + "\n修正后重新输出完整 YAML。"})
			continue
		}
		return draft, nil
	}
	return "", fmt.Errorf("规则草稿始终无法通过编译: %w", lastErr)
}

// stripFence 剥掉模型偶尔不听话包上的 markdown 代码块。
func stripFence(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	s = strings.TrimPrefix(s, "```yaml")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	return strings.TrimSpace(s)
}
