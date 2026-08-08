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

	"github.com/google/uuid"

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
	// OnVerdict 结论落库后的钩子（自动响应挂在这里），nil 表示无人关心
	OnVerdict func(ctx context.Context, incidentID uuid.UUID, verdict json.RawMessage)
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
		verdict := parseVerdict(inc.ID.String(), answer)
		// LLM 调用慢，逐个落库，中途挂了不丢已完成的研判
		if err := e.DB.Incident.UpdateOneID(inc.ID).
			SetAiVerdict(verdict).
			SetStatus("triaged").
			Exec(ctx); err != nil {
			return err
		}
		slog.Info("incident 研判完成", "id", inc.ID)
		if e.OnVerdict != nil {
			e.OnVerdict(ctx, inc.ID, verdict)
		}
	}
	return nil
}

// 工具调用轮数上限：防模型在调查里打转。用尽后强制收结论。
const maxToolTurns = 6

// Step 一次工具调用的记录。调查过程要能给人看——
// 无从复核的 AI 结论在安全场景里没有价值。
type Step struct {
	Tool string `json:"tool"`
	Args string `json:"args"`
}

// toolLoop 带工具的对话循环，研判与狩猎共用。模型不调用工具时第一轮
// 就返回答案，不支持工具的模型也走同一条路径，天然退化为单轮问答。
func (e *Engine) toolLoop(ctx context.Context, msgs []Message, nudge string) (string, []Step, error) {
	var steps []Step
	for turn := 0; turn < maxToolTurns; turn++ {
		msg, err := e.LLM.Chat(ctx, msgs, investigationTools)
		if err != nil {
			return "", steps, err
		}
		if len(msg.ToolCalls) == 0 {
			return msg.Content, steps, nil
		}
		msgs = append(msgs, msg)
		for _, tc := range msg.ToolCalls {
			result := e.execTool(ctx, tc.Function.Name, tc.Function.Arguments)
			slog.Info("调查", "tool", tc.Function.Name, "args", tc.Function.Arguments)
			steps = append(steps, Step{Tool: tc.Function.Name, Args: tc.Function.Arguments})
			msgs = append(msgs, Message{Role: "tool", ToolCallID: tc.ID, Content: result})
		}
	}
	// 轮数用尽：收走工具，强制收口
	msgs = append(msgs, Message{Role: "user", Content: nudge})
	msg, err := e.LLM.Chat(ctx, msgs, nil)
	if err != nil {
		return "", steps, err
	}
	return msg.Content, steps, nil
}

func (e *Engine) investigate(ctx context.Context, incidentContext string) (string, error) {
	answer, _, err := e.toolLoop(ctx, []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: incidentContext},
	}, "调查轮数已用尽，基于以上全部信息立即输出最终 JSON 结论。")
	return answer, err
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
	e.appendFalsePositiveHistory(ctx, &sb, alerts)
	return sb.String(), nil
}

// appendFalsePositiveHistory 把分析师的历史判断喂回模型：同样规则最近被
// 人工判为误报的案例。人的反馈是最贵的信号，不用等于白扔。
func (e *Engine) appendFalsePositiveHistory(ctx context.Context, sb *strings.Builder, alerts []*ent.Alert) {
	ruleIDs := make([]string, 0, len(alerts))
	for _, a := range alerts {
		ruleIDs = append(ruleIDs, a.RuleID)
	}
	fpAlerts, err := e.DB.Alert.Query().
		Where(
			alert.RuleIDIn(ruleIDs...),
			alert.TsGTE(time.Now().AddDate(0, 0, -90)),
			alert.HasIncidentWith(incident.StatusEQ("false_positive")),
		).
		WithIncident().
		Order(ent.Desc(alert.FieldTs)).
		Limit(20).
		All(ctx)
	if err != nil || len(fpAlerts) == 0 {
		return
	}

	seen := map[string]bool{}
	var lines []string
	for _, a := range fpAlerts {
		if a.Edges.Incident == nil || len(lines) >= 5 {
			continue
		}
		rule := a.RuleID
		if e.Rules != nil {
			if title := e.Rules.TitleOf(a.RuleID); title != "" {
				rule = title
			}
		}
		caseTitle := ""
		if t := a.Edges.Incident.Title; t != nil {
			caseTitle = *t
		}
		key := rule + "|" + caseTitle
		if seen[key] {
			continue
		}
		seen[key] = true
		lines = append(lines, fmt.Sprintf("- 规则「%s」曾于 %s 被分析师判为误报（案例: %s）",
			rule, a.Ts.Format("2006-01-02"), caseTitle))
	}
	if len(lines) == 0 {
		return
	}
	sb.WriteString("## 历史误报参考（分析师人工判断，仅供权衡，本次证据不同则不适用）\n")
	sb.WriteString(strings.Join(lines, "\n"))
	sb.WriteString("\n")
}
