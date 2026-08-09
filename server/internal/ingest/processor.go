package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

type Metrics interface {
	Processed(source string, duplicate bool, alerts int, elapsed time.Duration)
	Failed(stage string)
}

type Processor struct {
	DB          *sql.DB
	Rules       *sigma.Engine
	Suppress    *suppress.Store
	Intel       *intel.Store
	DedupWindow time.Duration
	Metrics     Metrics
}

// EnsureSchema 创建跨节点告警去重状态。它不是业务实体，而是可重建的处理状态，
// 因此不塞进 Ent schema，避免生成层污染。
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS alert_dedup_state (
  fingerprint text PRIMARY KEY,
  alert_id uuid NOT NULL,
  first_ts timestamptz NOT NULL,
  last_ts timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS alert_dedup_last_ts ON alert_dedup_state(last_ts);`)
	return err
}

func (p *Processor) Process(ctx context.Context, e Envelope) (err error) {
	started := time.Now()
	alerts := 0
	duplicate := false
	defer func() {
		if p.Metrics != nil {
			if err != nil {
				p.Metrics.Failed("process")
			} else {
				p.Metrics.Processed(e.Source, duplicate, alerts, time.Since(started))
			}
		}
	}()
	if err = e.Validate(); err != nil {
		return err
	}

	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, `INSERT INTO events
  (id, ts, class_uid, source, asset_id, process_guid, parent_process_guid, username, conn_tuple, raw)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
ON CONFLICT (id) DO NOTHING`, e.ID, e.Timestamp, e.ClassUID, e.Source,
		nullUUID(e.AssetID), nullUUID(e.ProcessGUID), nullUUID(e.ParentProcessGUID),
		nullString(e.Username), nullString(e.ConnTuple), string(e.Raw))
	if err != nil {
		return fmt.Errorf("事件落库: %w", err)
	}
	inserted, _ := result.RowsAffected()
	if inserted == 0 {
		duplicate = true
		return tx.Commit()
	}

	var raw map[string]any
	if json.Unmarshal(e.Raw, &raw) != nil {
		raw = map[string]any{}
	}
	hits := intel.Detections(p.Rules.Evaluate(e.ClassUID, e.AssetOS, raw), p.Intel.Match(raw, e.Timestamp))
	if e.ClassUID == 3002 && authStatus(raw) == 1 && e.AssetID != nil && e.Username != "" {
		var failures int
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM events
WHERE class_uid=3002 AND asset_id=$1 AND username=$2 AND ts >= $3
  AND raw->>'status_id'='2'`, *e.AssetID, e.Username, e.Timestamp.Add(-10*time.Minute)).Scan(&failures)
		if err != nil {
			return err
		}
		if failures >= 5 {
			hits = append(hits, intel.Hit{RuleID: sigma.RuleBruteforceSuccess, Severity: 5})
		}
	}
	for _, hit := range hits {
		if p.Suppress.Suppressed(hit.RuleID, e.AssetID, e.Timestamp) {
			continue
		}
		created, err := p.upsertAlert(ctx, tx, e, hit)
		if err != nil {
			return err
		}
		if created {
			alerts++
		}
	}
	return tx.Commit()
}

func (p *Processor) upsertAlert(ctx context.Context, tx *sql.Tx, e Envelope, hit intel.Hit) (bool, error) {
	fingerprint := hit.RuleID + "|" + e.PartitionKey + e.FingerprintSuffix
	if hit.RuleID == sigma.RuleBruteforceSuccess {
		fingerprint += "|" + e.Username
	}
	// 同一指纹的所有集群节点在事务内串行，窗口判断与告警计数不会竞争。
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, fingerprint); err != nil {
		return false, err
	}
	var alertID uuid.UUID
	var first time.Time
	err := tx.QueryRowContext(ctx, `SELECT alert_id, first_ts FROM alert_dedup_state WHERE fingerprint=$1`, fingerprint).
		Scan(&alertID, &first)
	if err == nil && !e.Timestamp.Before(first) && e.Timestamp.Sub(first) < p.DedupWindow {
		if _, err := tx.ExecContext(ctx, `UPDATE alerts SET count=count+1, last_ts=GREATEST(COALESCE(last_ts,ts),$2) WHERE id=$1`, alertID, e.Timestamp); err != nil {
			return false, err
		}
		_, err = tx.ExecContext(ctx, `UPDATE alert_dedup_state SET last_ts=GREATEST(last_ts,$2) WHERE fingerprint=$1`, fingerprint, e.Timestamp)
		return false, err
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}

	alertID = uuid.Must(uuid.NewV7())
	if _, err := tx.ExecContext(ctx, `INSERT INTO alerts
  (id, ts, rule_id, severity, event_id, asset_id, count, last_ts)
VALUES ($1,$2,$3,$4,$5,$6,1,$2)`, alertID, e.Timestamp, hit.RuleID, hit.Severity, e.ID, nullUUID(e.AssetID)); err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO alert_dedup_state(fingerprint,alert_id,first_ts,last_ts)
VALUES($1,$2,$3,$3) ON CONFLICT(fingerprint) DO UPDATE
SET alert_id=EXCLUDED.alert_id, first_ts=EXCLUDED.first_ts, last_ts=EXCLUDED.last_ts`, fingerprint, alertID, e.Timestamp)
	return true, err
}

func authStatus(raw map[string]any) int {
	v, _ := raw["status_id"].(float64)
	return int(v)
}

func nullUUID(id *uuid.UUID) any {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
