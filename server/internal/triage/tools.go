package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	entalert "openxdr/server/ent/alert"
	entevent "openxdr/server/ent/event"
	"openxdr/server/ent/predicate"
)

// 调查工具集：模型像分析师一样主动查证，而不是只看摘要。
// 三个就够——检索、血缘、前科，对应人工研判的三个基本动作。
var investigationTools = []Tool{
	makeTool("query_events",
		"按关键词检索原始事件（对整个事件体做子串匹配）。可用于追查某个 IP、域名、命令行、文件路径出现在哪些事件里。",
		`{"type":"object","properties":{
			"keyword":{"type":"string","description":"要搜索的子串，如 IP、域名、命令片段"},
			"hours":{"type":"integer","description":"回溯小时数，默认 24，最大 168"}
		},"required":["keyword"]}`),
	makeTool("process_lineage",
		"查询进程的血缘：祖先链与直接子进程。用于还原攻击链的来龙去脉。",
		`{"type":"object","properties":{
			"process_guid":{"type":"string","description":"事件里的进程 GUID（process.uid）"}
		},"required":["process_guid"]}`),
	makeTool("host_alerts",
		"查询某主机最近的告警历史（含已关闭事件）。用于判断该主机是初犯还是惯犯、当前事件是否是更大活动的一部分。",
		`{"type":"object","properties":{
			"asset_id":{"type":"string","description":"主机的 asset ID（图里 asset 节点的 id 后缀）"},
			"days":{"type":"integer","description":"回溯天数，默认 7"}
		},"required":["asset_id"]}`),
}

// execTool 执行一次工具调用。错误以文本返回给模型而不是中断研判——
// 模型能理解"查询失败"并继续，半途而废的研判什么都留不下。
func (e *Engine) execTool(ctx context.Context, name, args string) string {
	out, err := func() (any, error) {
		switch name {
		case "query_events":
			return e.toolQueryEvents(ctx, args)
		case "process_lineage":
			return e.toolProcessLineage(ctx, args)
		case "host_alerts":
			return e.toolHostAlerts(ctx, args)
		default:
			return nil, fmt.Errorf("未知工具 %s", name)
		}
	}()
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err.Error())
	}
	b, _ := json.Marshal(out)
	return string(b)
}

type eventBrief struct {
	Ts     string `json:"ts"`
	Class  int    `json:"class"`
	Source string `json:"source"`
	Raw    string `json:"raw"`
}

func (e *Engine) toolQueryEvents(ctx context.Context, args string) (any, error) {
	var in struct {
		Keyword string `json:"keyword"`
		Hours   int    `json:"hours"`
	}
	if json.Unmarshal([]byte(args), &in) != nil || in.Keyword == "" {
		return nil, fmt.Errorf("keyword 必填")
	}
	if in.Hours <= 0 || in.Hours > 168 {
		in.Hours = 24
	}
	pattern := "%" + escapeLike(in.Keyword) + "%"
	rows, err := e.DB.Event.Query().
		Where(
			entevent.TsGTE(time.Now().Add(-time.Duration(in.Hours)*time.Hour)),
			predicate.Event(func(s *sql.Selector) {
				s.Where(sql.P(func(b *sql.Builder) {
					b.WriteString(s.C(entevent.FieldRaw)).WriteString("::text ILIKE ").Arg(pattern)
				}))
			}),
		).
		Order(ent.Desc(entevent.FieldTs)).
		Limit(15).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]eventBrief, len(rows))
	for i, ev := range rows {
		out[i] = brief(ev)
	}
	return out, nil
}

func (e *Engine) toolProcessLineage(ctx context.Context, args string) (any, error) {
	var in struct {
		ProcessGUID string `json:"process_guid"`
	}
	if json.Unmarshal([]byte(args), &in) != nil {
		return nil, fmt.Errorf("process_guid 必填")
	}
	guid, err := uuid.Parse(in.ProcessGUID)
	if err != nil {
		return nil, fmt.Errorf("process_guid 不是合法 UUID")
	}

	var ancestors []eventBrief
	cur := guid
	for depth := 0; depth < 10; depth++ {
		ev, err := e.DB.Event.Query().
			Where(entevent.ProcessGUIDEQ(cur)).
			First(ctx)
		if err != nil {
			break
		}
		ancestors = append(ancestors, brief(ev))
		if ev.ParentProcessGUID == nil {
			break
		}
		cur = *ev.ParentProcessGUID
	}

	children, _ := e.DB.Event.Query().
		Where(entevent.ParentProcessGUIDEQ(guid)).
		Limit(10).
		All(ctx)
	childOut := make([]eventBrief, len(children))
	for i, ev := range children {
		childOut[i] = brief(ev)
	}
	return map[string]any{"self_and_ancestors": ancestors, "children": childOut}, nil
}

func (e *Engine) toolHostAlerts(ctx context.Context, args string) (any, error) {
	var in struct {
		AssetID string `json:"asset_id"`
		Days    int    `json:"days"`
	}
	if json.Unmarshal([]byte(args), &in) != nil {
		return nil, fmt.Errorf("asset_id 必填")
	}
	assetID, err := uuid.Parse(in.AssetID)
	if err != nil {
		return nil, fmt.Errorf("asset_id 不是合法 UUID")
	}
	if in.Days <= 0 || in.Days > 90 {
		in.Days = 7
	}
	rows, err := e.DB.Alert.Query().
		Where(
			entalert.AssetIDEQ(assetID),
			entalert.TsGTE(time.Now().AddDate(0, 0, -in.Days)),
		).
		Order(ent.Desc(entalert.FieldTs)).
		Limit(20).
		All(ctx)
	if err != nil {
		return nil, err
	}
	type alertBrief struct {
		Ts       string `json:"ts"`
		Rule     string `json:"rule"`
		Severity int16  `json:"severity"`
		Count    int    `json:"count"`
	}
	out := make([]alertBrief, len(rows))
	for i, a := range rows {
		rule := a.RuleID
		if e.Rules != nil {
			if title := e.Rules.TitleOf(a.RuleID); title != "" {
				rule = title
			}
		}
		out[i] = alertBrief{Ts: a.Ts.Format(time.RFC3339), Rule: rule, Severity: a.Severity, Count: a.Count}
	}
	return out, nil
}

func brief(ev *ent.Event) eventBrief {
	raw := string(ev.Raw)
	if len(raw) > 300 {
		raw = raw[:300] + "…"
	}
	return eventBrief{
		Ts:     ev.Ts.Format(time.RFC3339),
		Class:  ev.ClassUID,
		Source: ev.Source,
		Raw:    raw,
	}
}

// escapeLike 关键词是字面量，% _ \ 要转义，不能让模型输出变成通配符。
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
