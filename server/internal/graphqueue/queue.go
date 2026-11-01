// Package graphqueue 记录已入库但尚未物化到资产图谱的事件。
package graphqueue

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const ModeKey = "assetmap.delivery"
const Legacy = "legacy"
const Requested = "requested"
const Queued = "queue"

func EnsureSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS assetmap_queue (
 event_id uuid PRIMARY KEY,
 event_ts timestamptz NOT NULL,
 enqueued_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS assetmap_queue_pending ON assetmap_queue(enqueued_at,event_id);
INSERT INTO settings(id,value,updated_at)
SELECT 'assetmap.delivery', CASE WHEN EXISTS (SELECT 1 FROM settings WHERE id='assetmap.cursor')
 THEN '"legacy"'::jsonb ELSE '"requested"'::jsonb END, now()
ON CONFLICT(id) DO NOTHING;
CREATE OR REPLACE FUNCTION openxdr_assetmap_release() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF current_setting('openxdr.moving_rows',true) = 'on' THEN RETURN NULL; END IF;
 DELETE FROM assetmap_queue WHERE event_id=OLD.id;
 RETURN NULL;
END $$;
DO $$ BEGIN
 IF (SELECT relkind FROM pg_class WHERE oid=to_regclass('events'))='r'
 AND NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='openxdr_assetmap_release' AND tgrelid='events'::regclass) THEN
 CREATE TRIGGER openxdr_assetmap_release AFTER DELETE ON events FOR EACH ROW
 WHEN (OLD.class_uid IN (4001,5001,5020)) EXECUTE FUNCTION openxdr_assetmap_release();
 END IF;
END $$;`)
	return err
}

func Capture(ctx context.Context, tx *sql.Tx, id uuid.UUID, ts time.Time, class int) error {
	if class != 4001 && class != 5001 && class != 5020 {
		return nil
	}
	mode, err := readMode(ctx, tx)
	if err != nil {
		return err
	}
	if mode == Legacy {
		return nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO assetmap_queue(event_id,event_ts)
VALUES($1,$2) ON CONFLICT(event_id) DO NOTHING`, id, ts)
	return err
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func Mode(ctx context.Context, db *sql.DB) (string, error) {
	mode, err := readMode(ctx, db)
	if err == sql.ErrNoRows {
		return Legacy, nil
	}
	return mode, err
}

func readMode(ctx context.Context, db rowQuerier) (string, error) {
	var raw []byte
	if err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE id=$1`, ModeKey).Scan(&raw); err != nil {
		return "", err
	}
	return decodeMode(raw)
}

func decodeMode(raw []byte) (string, error) {
	var mode string
	if err := json.Unmarshal(raw, &mode); err != nil {
		return "", err
	}
	switch mode {
	case Legacy, Requested, Queued:
		return mode, nil
	}
	return "", fmt.Errorf("未知的图谱投递模式 %q", mode)
}

// Activate 由图谱单活工作者调用。短暂排空现有写事务，再衔接旧游标之后的记录。
// requested 期间的新入库已登记；旧工作者提交批次时删除对应待办，避免切换重计。
func Activate(ctx context.Context, db *sql.DB, cursor time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout='5s'`); err != nil {
		return err
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE id=$1 FOR UPDATE`, ModeKey).Scan(&raw); err != nil {
		return err
	}
	mode, err := decodeMode(raw)
	if err != nil {
		return err
	}
	if mode == Queued {
		return tx.Commit()
	}
	if mode != Requested {
		return fmt.Errorf("图谱切换尚未请求")
	}
	if _, err := tx.ExecContext(ctx, `LOCK TABLE events IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO assetmap_queue(event_id,event_ts)
SELECT id,ts FROM events WHERE ts>$1 AND class_uid IN (4001,5001,5020)
ON CONFLICT(event_id) DO NOTHING`, cursor); err != nil {
		return err
	}
	// 切换前若慢时钟主机的 5001/5020 清单因事件时间早于旧游标被跳过，补齐最近 24 小时内
	// 每台资产尚未物化的最新一条清单（清单按时间覆盖，不碰 4001 依赖边累计数）。
	if _, err := tx.ExecContext(ctx, `INSERT INTO assetmap_queue(event_id,event_ts)
SELECT s.id,s.ts FROM (
 SELECT DISTINCT ON (e.asset_id,e.class_uid) e.id,e.ts,e.class_uid,a.inventory_at,a.software_at
 FROM events e JOIN assets a ON a.id=e.asset_id
 WHERE e.ts>$1 AND e.ts<=$2 AND e.class_uid IN (5001,5020)
 ORDER BY e.asset_id,e.class_uid,e.ts DESC,e.id DESC
) s
WHERE (s.class_uid=5001 AND (s.inventory_at IS NULL OR s.inventory_at<s.ts))
   OR (s.class_uid=5020 AND (s.software_at IS NULL OR s.software_at<s.ts))
ON CONFLICT(event_id) DO NOTHING`, cursor.Add(-24*time.Hour), cursor); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE settings SET value='"queue"'::jsonb,updated_at=now() WHERE id=$1 AND value='"requested"'::jsonb`, ModeKey); err != nil {
		return err
	}
	return tx.Commit()
}

func Ack(ctx context.Context, tx *sql.Tx, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM assetmap_queue WHERE event_id=ANY($1::uuid[])`, "{"+strings.Join(ids, ",")+"}")
	return err
}
