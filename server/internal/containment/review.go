package containment

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/internal/triage"
)

// maxLease 租约最长活多久：到了不再问 AI，直接解除。模型一直说续期也不能把一台主机永远封着
const maxLease = 7 * 24 * time.Hour

// reviewRetry 复核出错（模型不可用、输出认不出）时续期多久再问
const reviewRetry = time.Hour

// baseline 租约开始前这段时间里就在主机上报过的规则算背景活动（cron、logrotate 之类），不当作攻击仍在继续的迹象。
// 紧挨租约的一天不算基线：那可能就是这次攻击的前奏
const baselineFrom, baselineTo = 7 * 24 * time.Hour, 24 * time.Hour

const reviewPrompt = `你是自主响应的复核员。平台在没有人参与的情况下自动做了一条封锁或隔离，现在租约到期，你决定解除还是续期。
只依据给出的事实判断，now 是当前时间，告警只统计本租约期（periodStart 起）、已去掉租约前就在例行出现的规则：
- 解除（lift）：租约期间来源与被处置主机上都没有新的攻击迹象，或事实表明这是误报、来源已经清理（容器已不在活动）；
- 续期（extend）：攻击还在继续、来源仍在活动，或事实不足以判断。拿不准一律续期。
你只能二选一，不能建议更重的动作。只输出一个 JSON 对象，不要其他文字：
{"decision":"lift 或 extend","reason":"不超过 80 字的依据"}`

// reviewFacts 喂给模型的事实。只给计数与摘要，告警原文不给：模型输出要当不可信输入，喂得越少越不容易被诱导
type reviewFacts struct {
	Lease struct {
		Kind    string    `json:"kind"`
		Target  string    `json:"target"`
		Role    string    `json:"role"`
		Host    string    `json:"host"`
		Signal  string    `json:"signal"`
		Reason  string    `json:"reason"`
		Since   time.Time `json:"since"`
		Reviews int       `json:"previousExtensions"`
	} `json:"lease"`
	Now          time.Time    `json:"now"`
	PeriodStart  time.Time    `json:"periodStart"`
	HostAlerts   []alertBrief `json:"alertsOnHostThisPeriod"`
	SourceAlerts []alertBrief `json:"alertsOnSourceThisPeriod,omitempty"`
	// 来源最近 24 小时还在别的纳管主机上留下的喷洒证据数
	SourceSpray24h *int `json:"sourceSprayEvidence24h,omitempty"`
	// 被隔离的容器最近一小时还有没有事件（隔离后进程仍在跑说明容器还在）
	ContainerActive *bool `json:"containerActiveLastHour,omitempty"`
}

type alertBrief struct {
	Rule     string    `json:"rule"`
	Severity int16     `json:"severity"`
	Count    int       `json:"count"`
	Last     time.Time `json:"last"`
}

// verdict 复核结论。没拿到有效结论（出错、输出认不出）时 lift 为 false、retry 为 true：按续期处理但尽快再问
type verdict struct {
	lift, retry bool
	why         string
}

// review 问模型这条到期的租约解除还是续期
func (e *Engine) review(ctx context.Context, c *ent.Containment) verdict {
	facts, err := e.reviewFacts(ctx, c)
	if err != nil {
		return verdict{retry: true, why: "整理复核事实失败：" + err.Error()}
	}
	body, _ := json.Marshal(facts)
	reply, err := e.LLM.Chat(ctx, []triage.Message{
		{Role: "system", Content: reviewPrompt},
		{Role: "user", Content: string(body)},
	}, nil)
	if err != nil {
		return verdict{retry: true, why: "模型调用失败：" + err.Error()}
	}
	return parseReview(reply.Content)
}

// parseReview 模型输出不可信：取第一个 JSON 对象，decision 只认 lift / extend，其余按续期并尽快再问
func parseReview(answer string) verdict {
	start, end := strings.Index(answer, "{"), strings.LastIndex(answer, "}")
	var v struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if start < 0 || end <= start || json.Unmarshal([]byte(answer[start:end+1]), &v) != nil {
		return verdict{retry: true, why: "模型输出认不出，按续期处理"}
	}
	reason := []rune(strings.TrimSpace(v.Reason))
	if len(reason) > 120 {
		reason = reason[:120]
	}
	switch v.Decision {
	case "lift":
		return verdict{lift: true, why: string(reason)}
	case "extend":
		return verdict{why: string(reason)}
	}
	return verdict{retry: true, why: "模型给出的决定无效，按续期处理"}
}

func (e *Engine) reviewFacts(ctx context.Context, c *ent.Containment) (reviewFacts, error) {
	var f reviewFacts
	host, err := e.DB.Asset.Get(ctx, c.AssetID)
	if err != nil {
		return f, err
	}
	f.Lease.Kind, f.Lease.Target, f.Lease.Role, f.Lease.Host = c.Kind, c.Target, string(c.Role), host.Hostname
	f.Lease.Signal, f.Lease.Reason, f.Lease.Since, f.Lease.Reviews = c.Signal, c.Reason, c.CreatedAt, c.Reviews
	// 只看本租约期：上一期的告警上一次复核已经看过，一直带着会让一次性的命中永远像是刚发生
	f.Now = e.now()
	f.PeriodStart = c.CreatedAt
	if p := f.Now.Add(-e.TTL); p.After(f.PeriodStart) {
		f.PeriodStart = p
	}
	if f.HostAlerts, err = e.briefs(ctx, c, c.AssetID, f.PeriodStart); err != nil {
		return f, err
	}
	if c.SourceAssetID != nil {
		if f.SourceAlerts, err = e.briefs(ctx, c, *c.SourceAssetID, f.PeriodStart); err != nil {
			return f, err
		}
		var n int
		if err := e.SQL.QueryRowContext(ctx, `SELECT count(*) FROM lateral_evidence WHERE src_asset=$1 AND ts>$2`,
			*c.SourceAssetID, e.now().Add(-24*time.Hour)).Scan(&n); err != nil {
			return f, err
		}
		f.SourceSpray24h = &n
	}
	if c.Kind == "isolate_container" {
		var active bool
		if err := e.SQL.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE asset_id=$1 AND ts>$2 AND raw->'container'->>'uid'=$3)`,
			c.AssetID, e.now().Add(-time.Hour), c.Target).Scan(&active); err != nil {
			return f, err
		}
		f.ContainerActive = &active
	}
	return f, nil
}

// briefs 某台主机 since 以来 3 级及以上的告警摘要，最多 20 条；平台指令与已知自动化的不算，
// 租约前就在这台主机上例行出现的规则也不算（触发这条处置的信号规则除外）
func (e *Engine) briefs(ctx context.Context, c *ent.Containment, asset uuid.UUID, since time.Time) ([]alertBrief, error) {
	background, err := e.DB.Alert.Query().
		Where(alert.AssetIDEQ(asset), alert.RuleIDNEQ(c.Signal),
			alert.TsGTE(c.CreatedAt.Add(-baselineFrom)), alert.TsLT(c.CreatedAt.Add(-baselineTo))).
		Unique(true).Select(alert.FieldRuleID).Strings(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := e.DB.Alert.Query().
		Where(alert.AssetIDEQ(asset), alert.SeverityGTE(3), alert.CommandIDIsNil(), alert.AutomationIDIsNil(),
			alert.RuleIDNotIn(background...), alert.Or(alert.LastTsGTE(since), alert.TsGTE(since))).
		Order(ent.Desc(alert.FieldSeverity)).Limit(20).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]alertBrief, len(rows))
	for i, a := range rows {
		last := a.Ts
		if a.LastTs != nil {
			last = *a.LastTs
		}
		out[i] = alertBrief{Rule: a.RuleID, Severity: a.Severity, Count: a.Count, Last: last}
	}
	return out, nil
}
