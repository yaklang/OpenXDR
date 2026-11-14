package suppress

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/event"
)

// MaxLineageHops 沿 parent_process_guid 最多向上追几跳祖先进程
const MaxLineageHops = 8

// RowQuerier 支持 *sql.DB 与 *sql.Tx 的最小查询接口
type RowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ResolveLineage 在 SQL 事务或连接上回溯进程祖先链（[父进程, 祖父进程, ...]）。
// 查不到或出错时退回事件内嵌的单跳 parent_process：宁可因缺祖先不命中抑制，绝不拼假血缘。
func ResolveLineage(ctx context.Context, q RowQuerier, assetID, parentGUID *uuid.UUID, ts time.Time, raw map[string]any) []map[string]any {
	embedded := DefaultLineage(raw)
	if q == nil || assetID == nil || parentGUID == nil || *parentGUID == uuid.Nil {
		return embedded
	}
	return walkLineage(embedded, *parentGUID, func(guid uuid.UUID) (*uuid.UUID, []byte, bool) {
		var next uuid.NullUUID
		var rawBytes []byte
		err := q.QueryRowContext(ctx, `SELECT parent_process_guid, raw FROM events
WHERE asset_id = $1 AND process_guid = $2 AND class_uid = 1007 AND ts <= $3
ORDER BY ts ASC LIMIT 1`, *assetID, guid, ts).Scan(&next, &rawBytes)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return nil, nil, false
			}
			return nil, nil, false
		}
		var parent *uuid.UUID
		if next.Valid && next.UUID != uuid.Nil {
			u := next.UUID
			parent = &u
		}
		return parent, rawBytes, true
	})
}

// ResolveLineageEnt 通过 Ent 客户端回溯进程祖先链，口径与 ResolveLineage 一致
func ResolveLineageEnt(ctx context.Context, db *ent.Client, assetID, parentGUID *uuid.UUID, ts time.Time, raw map[string]any) []map[string]any {
	embedded := DefaultLineage(raw)
	if db == nil || assetID == nil || parentGUID == nil || *parentGUID == uuid.Nil {
		return embedded
	}
	return walkLineage(embedded, *parentGUID, func(guid uuid.UUID) (*uuid.UUID, []byte, bool) {
		ev, err := db.Event.Query().
			Where(
				event.AssetIDEQ(*assetID),
				event.ProcessGUIDEQ(guid),
				event.ClassUIDEQ(1007),
				event.TsLTE(ts),
			).
			Order(ent.Asc(event.FieldTs)).
			First(ctx)
		if err != nil {
			return nil, nil, false
		}
		return ev.ParentProcessGUID, ev.Raw, true
	})
}

func walkLineage(embedded []map[string]any, firstGUID uuid.UUID, fetch func(uuid.UUID) (*uuid.UUID, []byte, bool)) []map[string]any {
	seen := map[uuid.UUID]bool{}
	var out []map[string]any
	var lastRaw map[string]any
	cur := &firstGUID

	for hop := 0; hop < MaxLineageHops && cur != nil && *cur != uuid.Nil && !seen[*cur]; hop++ {
		seen[*cur] = true
		next, rawBytes, ok := fetch(*cur)
		if !ok {
			break
		}
		var evMap map[string]any
		if json.Unmarshal(rawBytes, &evMap) != nil {
			break
		}
		proc, ok := evMap["process"].(map[string]any)
		if !ok || len(proc) == 0 {
			break
		}
		if hop == 0 && len(embedded) > 0 {
			proc = mergeProc(proc, embedded[0])
		}
		out = append(out, proc)
		lastRaw = evMap
		cur = next
	}

	if len(out) == 0 {
		return embedded
	}
	// 最顶一跳的父守护进程可能早于事件保留期启动（events 里已无 1007 行），补上它上报时内嵌的 parent_process
	if tail := DefaultLineage(lastRaw); len(tail) > 0 {
		out = append(out, tail[0])
	}
	return out
}

func mergeProc(primary, fallback map[string]any) map[string]any {
	merged := maps.Clone(fallback)
	if merged == nil {
		merged = map[string]any{}
	}
	maps.Copy(merged, primary)
	return merged
}
