package assetmap

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/graphqueue"
)

type GraphRebuild struct {
	ID           uuid.UUID `json:"id"`
	Since        time.Time `json:"since"`
	SnapshotAt   time.Time `json:"snapshotAt"`
	Events       int       `json:"events"`
	Links        int       `json:"links"`
	Acknowledged int64     `json:"acknowledged"`
}

// RebuildGraph 以保留窗口内的原始网络事件重新建立计数。所有工作者必须已支持维护锁。
// 原图保存在同事务的备份表；新入库不被锁住，快照之后的待办留给正常消费者。
func RebuildGraph(ctx context.Context, db *sql.DB, since time.Time, maxEvents int) (GraphRebuild, error) {
	report := GraphRebuild{ID: uuid.New(), Since: since}
	if since.IsZero() || maxEvents < 1 {
		return report, fmt.Errorf("无效的重建窗口或事件上限")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return report, err
	}
	defer conn.Close()
	var locked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, graphMaintenanceLock).Scan(&locked); err != nil {
		return report, err
	}
	if !locked {
		return report, fmt.Errorf("图谱正在消费或维护，请稍后重试")
	}
	defer releaseGraphLock(conn)
	// 先持有会话锁，再建立快照，避免等待旧批次期间截取过早的快照。
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	var replica bool
	var mode string
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp(),pg_is_in_recovery(),(SELECT value #>> '{}' FROM settings WHERE id=$1)`, graphqueue.ModeKey).Scan(&report.SnapshotAt, &replica, &mode); err != nil {
		return report, err
	}
	if replica || mode != graphqueue.Queued || !since.Before(report.SnapshotAt) {
		return report, fmt.Errorf("重建需要队列模式的主库和早于快照的起点")
	}
	if _, err := tx.ExecContext(ctx, `SET LOCAL statement_timeout='30s'; SET LOCAL lock_timeout='5s'`); err != nil {
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
	links := map[linkKey]*linkAgg{}
	report.Events, err = scanGraphEvents(ctx, tx, since, report.SnapshotAt, maxEvents, func(events []*ent.Event) error {
		names, err := processNamesFrom(ctx, tx, events)
		if err != nil {
			return err
		}
		for _, ev := range events {
			key, asset, ok := eventLink(ev, own, names, managed)
			if !ok {
				continue
			}
			a := links[key]
			if a == nil {
				a = &linkAgg{srcAsset: asset, first: ev.Ts, last: ev.Ts}
				links[key] = a
			}
			a.count++
			if ev.Ts.Before(a.first) {
				a.first = ev.Ts
			}
			if ev.Ts.After(a.last) {
				a.last = ev.Ts
				a.srcAsset = asset
			}
		}
		return nil
	})
	if err != nil {
		return report, err
	}
	report.Links = len(links)
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS assetmap_rebuilds (
 id uuid PRIMARY KEY, since timestamptz NOT NULL, snapshot_at timestamptz NOT NULL,
 events bigint NOT NULL, links bigint NOT NULL, previous_links jsonb NOT NULL);
 CREATE TEMP TABLE graph_rebuilt (LIKE asset_links INCLUDING DEFAULTS) ON COMMIT DROP`); err != nil {
		return report, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO assetmap_rebuilds(id,since,snapshot_at,events,links,previous_links)
 SELECT $1,$2,$3,$4,$5,COALESCE(jsonb_agg(to_jsonb(l)),'[]'::jsonb) FROM asset_links l`, report.ID, since, report.SnapshotAt, report.Events, report.Links); err != nil {
		return report, err
	}
	for key, a := range links {
		if _, err := tx.ExecContext(ctx, `INSERT INTO graph_rebuilt(id,src_ip,src_asset_id,dst_ip,dst_port,proto,process,count,first_seen,last_seen)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, uuid.New(), key.srcIP, a.srcAsset, key.dstIP, key.port, key.proto, key.process, a.count, a.first, a.last); err != nil {
			return report, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM asset_links l WHERE NOT EXISTS(SELECT 1 FROM graph_rebuilt r
 WHERE (l.src_ip,l.dst_ip,l.dst_port,l.proto,l.process)=(r.src_ip,r.dst_ip,r.dst_port,r.proto,r.process));
 INSERT INTO asset_links SELECT * FROM graph_rebuilt
 ON CONFLICT(src_ip,dst_ip,dst_port,proto,process) DO UPDATE SET
 count=EXCLUDED.count,first_seen=EXCLUDED.first_seen,last_seen=EXCLUDED.last_seen,src_asset_id=EXCLUDED.src_asset_id`); err != nil {
		return report, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM assetmap_queue q USING events e WHERE q.event_id=e.id
 AND e.class_uid=4001 AND e.ts >= $1 AND e.ts < $2`, since, report.SnapshotAt)
	if err != nil {
		return report, err
	}
	report.Acknowledged, err = result.RowsAffected()
	if err != nil {
		return report, err
	}
	return report, tx.Commit()
}

func releaseGraphLock(conn *sql.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var unlocked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, graphMaintenanceLock).Scan(&unlocked); err != nil || !unlocked {
		// 不能把仍可能持有会话锁的连接归还连接池。
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	}
}
