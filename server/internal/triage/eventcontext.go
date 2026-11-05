package triage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/event"
	"openxdr/server/internal/eventsearch"
)

// 以留存事件为锚点，只查同一主机事发前后 15 分钟；模型不能扩大时间窗或改选主机。
func (e *Engine) toolEventContext(ctx context.Context, args string) (any, error) {
	var in struct {
		EventID string `json:"event_id"`
		Keyword string `json:"keyword"`
	}
	dec := json.NewDecoder(strings.NewReader(args))
	dec.DisallowUnknownFields()
	if len(args) > 2048 || dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF {
		return nil, errors.New("query_event_context 仅接受 event_id 和 keyword")
	}
	id, err := uuid.Parse(in.EventID)
	if err != nil || id == uuid.Nil || strings.TrimSpace(in.Keyword) == "" || len(in.Keyword) > 256 {
		return nil, errors.New("需要合法事件 UUID 与 1–256 字节的非空 keyword")
	}
	scope, err := e.incidentEventScope(ctx, e.investigationID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	hotFrom := now.Add(-eventRawWindow)
	anchor, err := e.DB.Event.Query().Where(event.IDEQ(id), event.TsGTE(hotFrom), event.TsLTE(now), scope).WithAsset().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New("锚点事件不存在、不在本事件资产组内或超出最近 168 小时热表；不代表未发生")
		}
		return nil, err
	}
	if anchor.AssetID == nil || anchor.Edges.Asset == nil {
		return nil, errors.New("锚点事件无可确认资产归属")
	}
	linked, err := e.DB.Alert.Query().Where(alert.IncidentIDEQ(e.investigationID), alert.AssetIDEQ(*anchor.AssetID)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if !linked {
		return nil, errors.New("锚点主机不是本事件关联告警主机")
	}
	if err := e.rememberInvestigationAssets(ctx, anchor.Edges.Asset); err != nil {
		return nil, err
	}
	since, until := anchor.Ts.UTC().Add(-15*time.Minute), anchor.Ts.UTC().Add(15*time.Minute)
	if since.Before(hotFrom) {
		since = hotFrom
	}
	if until.After(now) {
		until = now
	}
	query := func() *ent.EventQuery {
		return e.DB.Event.Query().Where(scope, event.AssetIDEQ(*anchor.AssetID), event.TsGTE(since), event.TsLTE(until)).WithAsset()
	}
	rows, complete, err := eventsearch.Search(ctx, query, eventsearch.RawKeyword(in.Keyword), 16)
	if err != nil {
		return nil, err
	}
	truncated := !complete || len(rows) > 15
	rows = rows[:min(len(rows), 15)]
	if err := e.rememberInvestigationAssets(ctx, anchor.Edges.Asset); err != nil {
		return nil, err
	}
	items := make([]eventBrief, len(rows))
	for i, row := range rows {
		items[i] = brief(row)
	}
	return map[string]any{
		"status": "ok", "anchor_event_id": id, "anchor_ts": anchor.Ts, "asset_id": *anchor.AssetID,
		"from": since, "to": until, "limit": 15, "returned": len(items), "truncated": truncated,
		"mode": "raw", "raw_mode_scope": "search_only", "raw_excerpt_limit_bytes": eventExcerptBytes, "items": items,
		"coverage": "仅搜索锚点事件所属关联主机在事发前后 15 分钟且仍在最近 168 小时热表内的记录；不跨主机、不查冷归档或端点日志。每条正文最多 300 字节，需以返回 event_id 再调用 query_event_raw 精查。未命中不证明未发生，截断或超时不能声称覆盖完整时间窗；结果不证明业务授权。",
	}, nil
}
