package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/eventpart"
)

// eventColumns 与 events 的公共列一一对应，顺序与 scanEvent 一致。
const eventColumns = "id, ts, class_uid, source, asset_id, process_guid, parent_process_guid, username, conn_tuple, raw"

// scanBatch 是每次向服务端取的候选行数：游标式分页（ORDER BY ts, id + LIMIT），
// 内存里最多只有一批事件加上正在封的块。
const scanBatch = 1000

// plan 是影子构建与对拍共用的固定口径：日期闭区间、类别、来源与封块阈值。
// 对拍时完全按 run 行里存下的这份口径重查，不读调用方的参数。
type plan struct {
	from, to                time.Time // UTC 日零点，闭区间
	classes                 []int32
	sources                 []string
	chunkEvents, chunkBytes int
}

// upper 是扫描上界（不含）：to 当日 24 点。
func (p plan) upper() time.Time { return p.to.AddDate(0, 0, 1) }

// group 是一个 (class_uid, source) 分组。冷块按它切分，块上的 class_uid / source 才不混。
type group struct {
	class  int32
	source string
}

// groups 按 (类别, 来源) 升序枚举分组。影子构建与对拍都按这个顺序扫，
// 块序号 seq 与事件顺序因此完全可复现。
func (p plan) groups() []group {
	out := make([]group, 0, len(p.classes)*len(p.sources))
	for _, c := range p.classes {
		for _, s := range p.sources {
			out = append(out, group{class: c, source: s})
		}
	}
	return out
}

// scanStats 是一次候选扫描的计数：候选总数（含被钉住与超大）、其中被钉住的条数，
// 以及候选的 ts 跨度（用于对拍时判断「候选集是否已变化」）。
type scanStats struct {
	Scanned, Pinned int64
	First, Last     time.Time
}

// statSQL 一次扫出候选总数、被钉住的条数与 ts 跨度。口径与分组扫描完全一致。
const statSQL = `SELECT count(*), count(*) FILTER (WHERE id IN (` + eventpart.PinnedIDs + `)), min(ts), max(ts)
 FROM events WHERE ts >= $1 AND ts < $2 AND class_uid = ANY($3) AND source = ANY($4)`

// groupSQL 取一个分组里、位于 keyset 位置之后的候选事件。被钉住的事件在这里就排除，
// 不进入归档判定——判定顺序是「先 pin，再超限，最后封块」。
const groupSQL = `SELECT ` + eventColumns + ` FROM events
 WHERE ts >= $1 AND ts < $2 AND class_uid = $3 AND source = $4
 AND id NOT IN (` + eventpart.PinnedIDs + `)`

// scanCandidates 在同一个只读 REPEATABLE READ 事务里先数、再按 (类别, 来源, ts, id) 顺序流式取出候选事件。
// 整个扫描固定在一个快照上：计数与逐行读取不会因并发写入而互相矛盾，也不需要给 events 加任何锁。
// fn 返回错误即中止扫描。
func scanCandidates(ctx context.Context, db *sql.DB, p plan, fn func(Event) error) (scanStats, error) {
	var st scanStats
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return st, fmt.Errorf("开启只读快照: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var first, last sql.NullTime
	if err := tx.QueryRowContext(ctx, statSQL, p.from, p.upper(), p.classes, p.sources).
		Scan(&st.Scanned, &st.Pinned, &first, &last); err != nil {
		return st, fmt.Errorf("统计候选事件: %w", err)
	}
	st.First, st.Last = first.Time.UTC(), last.Time.UTC()

	for _, g := range p.groups() {
		if err := scanGroup(ctx, tx, p, g, fn); err != nil {
			return st, err
		}
	}
	// 只读事务的提交只是释放快照
	return st, tx.Commit()
}

// scanGroup 用 keyset 分页把一个分组读完：(ts, id) 严格递增，ORDER BY ts, id LIMIT n。
// 不用 DECLARE CURSOR：同一效果，但不依赖把参数写进 DDL 语句，批次之间也不会持有长事务里的游标状态。
func scanGroup(ctx context.Context, tx *sql.Tx, p plan, g group, fn func(Event) error) error {
	var lastTs time.Time
	var lastID uuid.UUID
	have := false
	for {
		query, args := groupSQL, []any{p.from, p.upper(), g.class, g.source}
		if have {
			query += ` AND (ts, id) > ($5::timestamptz, $6::uuid)`
			args = append(args, lastTs, lastID)
		}
		query += fmt.Sprintf(` ORDER BY ts, id LIMIT %d`, scanBatch)
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("扫描候选事件（class=%d source=%s）: %w", g.class, g.source, err)
		}
		n := 0
		for rows.Next() {
			e, err := scanEvent(rows)
			if err != nil {
				rows.Close()
				return fmt.Errorf("读取候选事件: %w", err)
			}
			if err := fn(e); err != nil {
				rows.Close()
				return err
			}
			lastTs, lastID, have = e.Ts, e.ID, true
			n++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return fmt.Errorf("扫描候选事件（class=%d source=%s）: %w", g.class, g.source, err)
		}
		if n < scanBatch {
			return nil
		}
	}
}

func scanEvent(rows *sql.Rows) (Event, error) {
	var e Event
	var asset, proc, parent uuid.NullUUID
	var user, conn sql.NullString
	var raw []byte
	if err := rows.Scan(&e.ID, &e.Ts, &e.ClassUID, &e.Source, &asset, &proc, &parent, &user, &conn, &raw); err != nil {
		return e, err
	}
	e.Ts = e.Ts.UTC()
	if asset.Valid {
		v := asset.UUID
		e.AssetID = &v
	}
	if proc.Valid {
		v := proc.UUID
		e.ProcessGUID = &v
	}
	if parent.Valid {
		v := parent.UUID
		e.ParentProcessGUID = &v
	}
	if user.Valid {
		v := user.String
		e.Username = &v
	}
	if conn.Valid {
		v := conn.String
		e.ConnTuple = &v
	}
	if raw == nil {
		// raw 列 NOT NULL，理论上到不了这里；真到了按 JSON null 记，不静默当空对象
		raw = []byte("null")
	}
	e.Raw = json.RawMessage(raw)
	return e, nil
}

// distinctSources 在没指定 -sources 时把范围内的来源固定下来：影子构建与对拍用同一份清单，
// 之后新增的来源属于「候选集变化」，由对拍如实报出来。
func distinctSources(ctx context.Context, db *sql.DB, p plan) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT source FROM events
 WHERE ts >= $1 AND ts < $2 AND class_uid = ANY($3) ORDER BY source`, p.from, p.upper(), p.classes)
	if err != nil {
		return nil, fmt.Errorf("列出来源: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("读取来源: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("列出来源: %w", err)
	}
	return out, nil
}
