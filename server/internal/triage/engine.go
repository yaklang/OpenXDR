// Package triage AI 研判引擎：对关联引擎产出的 incident 做 LLM 定性，
// 结论写回 incidents.ai_verdict，状态推进到 triaged。
package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
)

const systemPrompt = `你是资深安全分析师，负责研判 XDR 平台聚合出的安全事件。
输入包含事件的实体关系图（主机/进程/告警）和按时间排序的告警明细。
你可以调用工具主动调查：检索原始事件、追进程血缘、查主机告警前科。
证据不足时先调查再下结论，证据已经充分时直接给结论，不要为了调查而调查。
最终结论只输出一个 JSON 对象，不要输出任何其他文字，结构如下：
{
  "verdict": "malicious | suspicious | benign",
  "confidence": 0 到 100 的整数,
  "summary": "一段话说清这个事件是什么、为什么这样判定",
  "kill_chain": ["按时间顺序还原的攻击链步骤，非攻击事件则为空数组"],
  "actions": ["建议的处置动作，按优先级排序"]
}
研判要克制：单一低危告警、常见运维行为倾向 benign；有明确攻击链证据才给 malicious。`

type Engine struct {
	DB       *ent.Client
	LLM      *LLM
	Interval time.Duration
	// Rules 用于把上下文里的规则 UUID 翻译成标题，模型看得懂才判得准
	Rules interface{ TitleOf(id string) string }
}

func (e *Engine) Run(ctx context.Context) {
	if !e.LLM.Enabled() {
		slog.Warn("AI 研判未启用：未配置 AI_MODEL")
		return
	}
	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.batch(ctx); err != nil {
				slog.Error("研判批次失败", "err", err)
			}
		}
	}
}

func (e *Engine) batch(ctx context.Context) error {
	// 只看 status：重开的 incident（带新证据）会被重新研判，旧 verdict 被覆盖
	incidents, err := e.DB.Incident.Query().
		Where(incident.StatusEQ("open")).
		Order(ent.Asc(incident.FieldCreatedAt)).
		Limit(5).
		All(ctx)
	if err != nil {
		return err
	}

	for _, inc := range incidents {
		context_, err := e.buildContext(ctx, inc)
		if err != nil {
			return err
		}
		answer, err := e.investigate(ctx, context_)
		if err != nil {
			return err
		}
		// LLM 调用慢，逐个落库，中途挂了不丢已完成的研判
		if err := e.DB.Incident.UpdateOneID(inc.ID).
			SetAiVerdict(parseVerdict(inc.ID.String(), answer)).
			SetStatus("triaged").
			Exec(ctx); err != nil {
			return err
		}
		slog.Info("incident 研判完成", "id", inc.ID)
	}
	return nil
}

// 工具调用轮数上限：防模型在调查里打转。用尽后强制收结论。
const maxToolTurns = 6

// investigate 带工具的研判循环。模型不调用工具时第一轮就返回结论，
// 不支持工具的模型也走同一条路径，天然退化为单轮研判。
func (e *Engine) investigate(ctx context.Context, incidentContext string) (string, error) {
	msgs := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: incidentContext},
	}
	for turn := 0; turn < maxToolTurns; turn++ {
		msg, err := e.LLM.Chat(ctx, msgs, investigationTools)
		if err != nil {
			return "", err
		}
		if len(msg.ToolCalls) == 0 {
			return msg.Content, nil
		}
		msgs = append(msgs, msg)
		for _, tc := range msg.ToolCalls {
			result := e.execTool(ctx, tc.Function.Name, tc.Function.Arguments)
			slog.Info("研判调查", "tool", tc.Function.Name, "args", tc.Function.Arguments)
			msgs = append(msgs, Message{Role: "tool", ToolCallID: tc.ID, Content: result})
		}
	}
	// 轮数用尽：收走工具，强制给结论
	msgs = append(msgs, Message{Role: "user", Content: "调查轮数已用尽，基于以上全部信息立即输出最终 JSON 结论。"})
	msg, err := e.LLM.Chat(ctx, msgs, nil)
	if err != nil {
		return "", err
	}
	return msg.Content, nil
}

func parseVerdict(incidentID, answer string) json.RawMessage {
	if start, end := strings.Index(answer, "{"), strings.LastIndex(answer, "}"); start >= 0 && end > start {
		candidate := answer[start : end+1]
		if json.Valid([]byte(candidate)) {
			return json.RawMessage(candidate)
		}
	}
	slog.Warn("研判输出不是合法 JSON，原样存档", "incident", incidentID)
	if len(answer) > 2000 {
		answer = answer[:2000]
	}
	fallback, _ := json.Marshal(map[string]string{"error": "unparseable", "raw": answer})
	return fallback
}

func (e *Engine) buildContext(ctx context.Context, inc *ent.Incident) (string, error) {
	alerts, err := e.DB.Alert.Query().
		Where(alert.IncidentIDEQ(inc.ID)).
		Order(ent.Asc(alert.FieldTs)).
		Limit(50).
		WithEvent().
		All(ctx)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	title := ""
	if inc.Title != nil {
		title = *inc.Title
	}
	fmt.Fprintf(&sb, "# 事件: %s\n创建时间: %s\n", title, inc.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(&sb, "## 实体关系图\n%s\n", inc.Graph)
	fmt.Fprintf(&sb, "## 告警明细（%d 条，按时间排序）\n", len(alerts))
	for _, a := range alerts {
		raw := "{}"
		if a.Edges.Event != nil {
			raw = string(a.Edges.Event.Raw)
			if len(raw) > 500 {
				raw = raw[:500] + "…"
			}
		}
		rule := a.RuleID
		if e.Rules != nil {
			if title := e.Rules.TitleOf(a.RuleID); title != "" {
				rule = title
			}
		}
		fmt.Fprintf(&sb, "- [%s] severity=%d count=%d rule=%s event=%s\n",
			a.Ts.Format("15:04:05"), a.Severity, a.Count, rule, raw)
	}
	return sb.String(), nil
}
