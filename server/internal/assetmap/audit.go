package assetmap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
)

type graphReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type GraphDifference struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Process     string `json:"process"`
	Observed    int64  `json:"observed"`
	Stored      int64  `json:"stored"`
}

type GraphAudit struct {
	SnapshotAt         time.Time         `json:"snapshotAt"`
	Replica            bool              `json:"replica"`
	Since              time.Time         `json:"since"`
	Until              time.Time         `json:"until"`
	Events             int               `json:"events"`
	Pending            int               `json:"pending"`
	Contributing       int64             `json:"contributing"`
	ObservedLinks      int               `json:"observedLinks"`
	MissingLinks       int               `json:"missingLinks"`
	BelowObservedCount int               `json:"belowObservedCount"`
	Examples           []GraphDifference `json:"examples"`
}

// AuditGraph 在同一只读快照里核对原始事件、待办和图谱。窗口内观测数只是
// 已存累计计数的下界；不能据此判断窗口外的历史计数是否正确，也不修改计数。
func AuditGraph(ctx context.Context, db *sql.DB, since, until time.Time, maxEvents int, replicaOnly bool) (GraphAudit, error) {
	report := GraphAudit{Since: since, Until: until, Examples: []GraphDifference{}}
	if !since.Before(until) || maxEvents < 1 {
		return report, fmt.Errorf("无效的图谱核对窗口或事件上限")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, `SELECT current_timestamp, pg_is_in_recovery()`).Scan(&report.SnapshotAt, &report.Replica); err != nil {
		return report, err
	}
	if replicaOnly && !report.Replica {
		return report, fmt.Errorf("核对要求备库，但实际连接的是主库")
	}
	if _, err = tx.ExecContext(ctx, `SET LOCAL statement_timeout='30s'`); err != nil {
		return report, err
	}
	own, err := auditAssets(ctx, tx)
	if err != nil {
		return report, err
	}
	managed := map[netip.Addr]bool{}
	for _, ips := range own {
		for _, ip := range ips {
			managed[ip] = true
		}
	}
	observed := map[linkKey]int64{}
	report.Events, err = scanGraphEvents(ctx, tx, since, until, maxEvents, func(events []*ent.Event) error {
		pending, err := auditPending(ctx, tx, events)
		if err != nil {
			return err
		}
		eligible := events[:0]
		for _, ev := range events {
			if pending[ev.ID] {
				report.Pending++
				continue
			}
			eligible = append(eligible, ev)
		}
		names, err := processNamesFrom(ctx, tx, eligible)
		if err != nil {
			return fmt.Errorf("回查进程名称：%w", err)
		}
		for _, ev := range eligible {
			key, _, ok := eventLink(ev, own, names, managed)
			if !ok {
				continue
			}
			observed[key]++
			report.Contributing++
		}
		return nil
	})
	if err != nil {
		return report, err
	}

	report.ObservedLinks = len(observed)
	rows, err := tx.QueryContext(ctx, `SELECT src_ip,dst_ip,dst_port,proto,process,count FROM asset_links`)
	if err != nil {
		return report, err
	}
	stored := map[linkKey]int64{}
	for rows.Next() {
		var key linkKey
		var count int64
		if err = rows.Scan(&key.srcIP, &key.dstIP, &key.port, &key.proto, &key.process, &count); err != nil {
			rows.Close()
			return report, err
		}
		stored[key] = count
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return report, err
	}
	var differences []GraphDifference
	for key, count := range observed {
		previous, ok := stored[key]
		if !ok {
			report.MissingLinks++
		} else if previous < count {
			report.BelowObservedCount++
		}
		if !ok || previous < count {
			differences = append(differences, GraphDifference{key.srcIP, key.dstIP, key.port, key.proto, key.process, count, previous})
		}
	}
	sort.Slice(differences, func(i, j int) bool {
		a, b := differences[i], differences[j]
		if a.Observed-a.Stored != b.Observed-b.Stored {
			return a.Observed-a.Stored > b.Observed-b.Stored
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Destination != b.Destination {
			return a.Destination < b.Destination
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Process < b.Process
	})
	if len(differences) > 50 {
		differences = differences[:50]
	}
	report.Examples = append(report.Examples, differences...)
	return report, tx.Commit()
}

func auditAssets(ctx context.Context, db graphReader) (map[uuid.UUID][]netip.Addr, error) {
	rows, err := db.QueryContext(ctx, `SELECT id,ip_addrs FROM assets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	own := map[uuid.UUID][]netip.Addr{}
	for rows.Next() {
		var id uuid.UUID
		var raw []byte
		var ips []string
		if err = rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			if err = json.Unmarshal(raw, &ips); err != nil {
				return nil, err
			}
		}
		own[id] = parseIPs(ips)
	}
	return own, rows.Err()
}

func auditBatch(ctx context.Context, tx *sql.Tx) ([]*ent.Event, error) {
	rows, err := tx.QueryContext(ctx, `FETCH FORWARD 1000 FROM graph_audit`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []*ent.Event
	for rows.Next() {
		ev := &ent.Event{}
		if err = rows.Scan(&ev.ID, &ev.Ts, &ev.ClassUID, &ev.Source, &ev.AssetID, &ev.ProcessGUID, &ev.ConnTuple, &ev.Raw); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

func auditPending(ctx context.Context, tx *sql.Tx, events []*ent.Event) (map[uuid.UUID]bool, error) {
	ids := make([]uuid.UUID, len(events))
	for i, ev := range events {
		ids[i] = ev.ID
	}
	rows, err := tx.QueryContext(ctx, `SELECT event_id FROM assetmap_queue WHERE event_id=ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pending := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		pending[id] = true
	}
	return pending, rows.Err()
}

func scanGraphEvents(ctx context.Context, tx *sql.Tx, since, until time.Time, maxEvents int, visit func([]*ent.Event) error) (int, error) {
	count := 0
	// 保持同一个 MVCC 快照；按小时限制稀疏事件区间的扫描量。
	for windowStart := since; windowStart.Before(until); windowStart = windowStart.Add(time.Hour) {
		windowEnd := windowStart.Add(time.Hour)
		if until.Before(windowEnd) {
			windowEnd = until
		}
		if _, err := tx.ExecContext(ctx, `DECLARE graph_audit NO SCROLL CURSOR FOR
SELECT id,ts,class_uid,source,asset_id,process_guid,conn_tuple,raw FROM events
WHERE class_uid=4001 AND ts >= $1 AND ts < $2`, windowStart, windowEnd); err != nil {
			return count, err
		}
		for {
			events, err := auditBatch(ctx, tx)
			if err != nil {
				return count, fmt.Errorf("扫描网络事件 %s 至 %s：%w", windowStart.Format(time.RFC3339), windowEnd.Format(time.RFC3339), err)
			}
			if len(events) == 0 {
				break
			}
			count += len(events)
			if count > maxEvents {
				return count, fmt.Errorf("图谱核对超过 %d 条事件上限，未完成核对", maxEvents)
			}
			if err := visit(events); err != nil {
				return count, err
			}
		}
		if _, err := tx.ExecContext(ctx, `CLOSE graph_audit`); err != nil {
			return count, err
		}
	}

	return count, nil
}
