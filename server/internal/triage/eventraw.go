package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	entevent "openxdr/server/ent/event"
)

const eventRawLimitBytes = 4096
const eventRawWindow = 168 * time.Hour

func (e *Engine) toolEventRaw(ctx context.Context, args string) (any, error) {
	var in struct {
		EventID string `json:"event_id"`
	}
	if json.Unmarshal([]byte(args), &in) != nil {
		return nil, fmt.Errorf("event_id 必须是事件 UUID")
	}
	id, err := uuid.Parse(in.EventID)
	if err != nil || id == uuid.Nil {
		return nil, fmt.Errorf("event_id 必须是事件 UUID")
	}
	scope, err := e.incidentEventScope(ctx, e.investigationID)
	if err != nil {
		return nil, err
	}
	until := time.Now().UTC()
	since := until.Add(-eventRawWindow)
	ev, err := e.DB.Event.Query().Where(entevent.IDEQ(id), entevent.TsGTE(since), entevent.TsLTE(until), scope).WithAsset().Only(ctx)
	if ent.IsNotFound(err) {
		return nil, fmt.Errorf("事件不存在、不在本事件资产组内或已超出最近 168 小时热表范围；不代表未发生")
	}
	if err != nil {
		return nil, err
	}
	if err := e.rememberInvestigationAssets(ctx, ev.Edges.Asset); err != nil {
		return nil, err
	}
	limit := eventRawLimitBytes
	if len(ev.Raw) > limit {
		limit -= len("…")
	}
	item := briefLimit(ev, limit)
	// 原文按同一预算返回；不额外复制 DNS 字段来绕过单条正文上限。
	item.DNS, item.DNSOmitted = nil, nil
	return map[string]any{
		"status": "ok", "items": []eventBrief{item}, "limit": 1, "returned": 1, "truncated": false,
		"raw_excerpt_limit_bytes": eventRawLimitBytes, "from": since, "to": until,
		"coverage": "仅返回本事件资产组内最近 168 小时、已采集且仍保留在热表的这一条记录；raw_truncated 表示原文仍未读全。未查询冷归档、端点文件或未采集日志，不能证明来源合法或其他记录不存在",
	}, nil
}
