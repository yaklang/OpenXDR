package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"openxdr/server/internal/cmdorigin"
	"openxdr/server/internal/eventarchive"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/temporal"
)

// temporalAlert 告警绑定终点事件及其资产。账号维度命中可能跨资产，去重指纹按账号实体而非资产区分。
func (p *Processor) temporalAlert(ctx context.Context, tx *sql.Tx, match temporal.Match) (bool, error) {
	// R1 引用写入点：时序告警引用锚点事件（alerts.event_id），且下面的 UPDATE 让
	// temporal_detections 的锚点开始受保护（PinnedIDs 的第三支）。先取锚点日的共享生命
	// 周期锁（processor 入口已随 ±时序窗口 span 取齐，这里幂等补上独立调用场景），再
	// 锁内确认锚点热行——缺失时从冷层物化回热表（同事务），物化不了就让本事务失败，
	// 不提交悬空引用。放在读锚点行之前：否则「锚点刚被切走」会被下面的 SELECT 误报成
	// 「不存在」，连物化补链的机会都没有。
	if err := eventpart.LifecycleLockShared(ctx, tx, match.Time); err != nil {
		return false, err
	}
	if err := eventarchive.EnsureHotEvents(ctx, tx, match.Anchor); err != nil {
		return false, err
	}
	var asset uuid.UUID
	e := Envelope{ID: match.Anchor, AssetID: &asset, PartitionKey: match.Scope.Entity,
		FingerprintSuffix: "|temporal:" + match.Revision + "|group:" + match.Scope.Group.String()}
	var username sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT ts,class_uid,source,asset_id,username,raw FROM events WHERE id=$1 AND asset_id IS NOT NULL`, match.Anchor).
		Scan(&e.Timestamp, &e.ClassUID, &e.Source, &asset, &username, &e.Raw); err != nil {
		return false, err
	}
	if !temporal.IsAccountEntity(match.Scope.Entity) && match.Scope.Entity != asset.String() {
		return false, fmt.Errorf("时序终点 %s 不属于命中资产 %s", match.Anchor, match.Scope.Entity)
	}
	e.Username = username.String
	var raw map[string]any
	if err := json.Unmarshal(e.Raw, &raw); err != nil {
		return false, err
	}
	sigma.WithActor(raw, e.Username)
	if p.Suppress.Suppressed(match.RuleID, e.AssetID, raw, e.Timestamp) {
		return false, nil
	}
	command, err := cmdorigin.Of(ctx, tx, raw, e.AssetID, e.Timestamp)
	if err != nil {
		return false, err
	}
	hit := intel.Hit{RuleID: match.RuleID, Severity: match.Severity}
	created, err := p.upsertAlert(ctx, tx, e, hit, origin{command: command})
	if err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE temporal_detections SET alert_id=(SELECT alert_id FROM alert_dedup_state WHERE fingerprint=$1)
WHERE revision=$2 AND rule_id=$3 AND anchor_id=$4`, alertFingerprint(e, hit, origin{command: command}), match.Revision, match.RuleID, match.Anchor)
	return created, err
}
