package assetmap

import (
	"context"
	"database/sql"

	"openxdr/server/ent"
)

// 待办行锁与图谱提交、删除待办共用事务。节点切换时即使旧工作者尚在退出，
// 也不能重复领取同一事件；回滚后仍可重新领取。
func queuedEvents(ctx context.Context, tx *sql.Tx) ([]*ent.Event, error) {
	rows, err := tx.QueryContext(ctx, `WITH pending AS MATERIALIZED (
 SELECT event_id,event_ts,enqueued_at FROM assetmap_queue
 ORDER BY enqueued_at,event_id LIMIT $1 FOR UPDATE SKIP LOCKED
)
SELECT e.id,e.ts,e.class_uid,e.source,e.asset_id,e.process_guid,e.conn_tuple,e.raw
FROM pending q JOIN events e ON e.id=q.event_id AND e.ts=q.event_ts
ORDER BY q.enqueued_at,q.event_id`, batchLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []*ent.Event
	for rows.Next() {
		e := &ent.Event{}
		if err := rows.Scan(&e.ID, &e.Ts, &e.ClassUID, &e.Source, &e.AssetID, &e.ProcessGUID, &e.ConnTuple, &e.Raw); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
