package temporal

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/eventpart"
)

// EnsureSchema 创建可重启恢复的候选及命中证据。资产换组会清除候选，
// 即使先换到 B 再换回 A、期间没有事件，也不会复用旧 A 的序列状态。
// 事件列不建外键（分区表无法被单列引用），级联与证据保护见 eventpart。
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS temporal_rule_snapshots (
 revision text PRIMARY KEY, document jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS temporal_candidates (
 revision text NOT NULL, event_id uuid NOT NULL,
 asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 group_id uuid NOT NULL, ts timestamptz NOT NULL, rules jsonb NOT NULL,
 PRIMARY KEY(revision,event_id));
CREATE INDEX IF NOT EXISTS temporal_candidates_window ON temporal_candidates(revision,asset_id,group_id,ts);
ALTER TABLE temporal_candidates ADD COLUMN IF NOT EXISTS account text;
CREATE INDEX IF NOT EXISTS temporal_candidates_ts ON temporal_candidates(ts);
CREATE INDEX IF NOT EXISTS temporal_candidates_account ON temporal_candidates(revision,group_id,account,ts) WHERE account IS NOT NULL;
CREATE TABLE IF NOT EXISTS temporal_evaluation_gaps (
 revision text NOT NULL, event_id uuid NOT NULL,
 asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE, group_id uuid NOT NULL,
 reason text NOT NULL, candidate_count_lower_bound integer NOT NULL,
 window_from timestamptz NOT NULL, window_to timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(revision,event_id));
CREATE INDEX IF NOT EXISTS temporal_evaluation_gaps_scope ON temporal_evaluation_gaps(group_id,asset_id,created_at);
CREATE INDEX IF NOT EXISTS temporal_evaluation_gaps_asset ON temporal_evaluation_gaps(asset_id,created_at DESC,revision DESC,event_id DESC);
CREATE INDEX IF NOT EXISTS temporal_evaluation_gaps_created ON temporal_evaluation_gaps(created_at);
CREATE TABLE IF NOT EXISTS temporal_detections (
 revision text NOT NULL, rule_id text NOT NULL,
 anchor_id uuid NOT NULL,
 group_id uuid NOT NULL, entity text NOT NULL, evidence jsonb NOT NULL,
 PRIMARY KEY(revision,rule_id,anchor_id));
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='temporal_detections'::regclass AND attname='alert_id' AND NOT attisdropped) THEN
 ALTER TABLE temporal_detections ADD COLUMN alert_id uuid REFERENCES alerts(id) ON DELETE CASCADE;
 END IF;
END $$;
CREATE INDEX IF NOT EXISTS temporal_candidates_event ON temporal_candidates(event_id);
CREATE INDEX IF NOT EXISTS temporal_evaluation_gaps_event ON temporal_evaluation_gaps(event_id);
CREATE INDEX IF NOT EXISTS temporal_detections_anchor ON temporal_detections(anchor_id);
CREATE TABLE IF NOT EXISTS temporal_evidence (
 revision text NOT NULL, rule_id text NOT NULL, anchor_id uuid NOT NULL,
 event_id uuid NOT NULL,
 PRIMARY KEY(revision,rule_id,anchor_id,event_id),
 FOREIGN KEY(revision,rule_id,anchor_id) REFERENCES temporal_detections(revision,rule_id,anchor_id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS temporal_evidence_event ON temporal_evidence(event_id);
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='temporal_candidates_revision_fk' AND conrelid='temporal_candidates'::regclass) THEN
 ALTER TABLE temporal_candidates ADD CONSTRAINT temporal_candidates_revision_fk FOREIGN KEY(revision) REFERENCES temporal_rule_snapshots(revision) ON DELETE RESTRICT NOT VALID;
 END IF;
END $$;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='temporal_detections_revision_fk' AND conrelid='temporal_detections'::regclass) THEN
 ALTER TABLE temporal_detections ADD CONSTRAINT temporal_detections_revision_fk FOREIGN KEY(revision) REFERENCES temporal_rule_snapshots(revision) ON DELETE RESTRICT NOT VALID;
 END IF;
END $$;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='temporal_evaluation_gaps_revision_fk' AND conrelid='temporal_evaluation_gaps'::regclass) THEN
 ALTER TABLE temporal_evaluation_gaps ADD CONSTRAINT temporal_evaluation_gaps_revision_fk FOREIGN KEY(revision) REFERENCES temporal_rule_snapshots(revision) ON DELETE RESTRICT NOT VALID;
 END IF;
END $$;
CREATE OR REPLACE FUNCTION openxdr_reset_temporal_scope() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.group_id IS DISTINCT FROM NEW.group_id THEN
  DELETE FROM temporal_candidates WHERE asset_id=NEW.id;
 END IF;
 RETURN NEW;
END $$;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='openxdr_temporal_scope' AND tgrelid='assets'::regclass) THEN
 CREATE TRIGGER openxdr_temporal_scope AFTER UPDATE OF group_id ON assets
 FOR EACH ROW EXECUTE FUNCTION openxdr_reset_temporal_scope();
 END IF;
END $$;`)
	return err
}

type Observation struct {
	// Skipped 是本事件的覆盖缺口原因，去重后逐项计入 openxdr_temporal_skipped_total：
	// unscoped（无资产或未分组）、no_account（账号维度规则相关但事件无用户名）、candidate_limit（窗口候选超上限）、
	// late（事件时间早于迟到余量，窗口内候选可能已被清理）。
	Skipped []string
	Matches []Match
}

func (o *Observation) skip(reason string) {
	if !slices.Contains(o.Skipped, reason) {
		o.Skipped = append(o.Skipped, reason)
	}
}

// Observe 必须在事件与告警共用的事务中调用。基础命中只能来自该 snapshot。
// 组和资产从数据库获取；没有分组时显式记 unscoped，不使用自报归属。
// 资产维度按 (组, 资产) 关联；账号维度按 (组, 规范化用户名) 跨同组资产累计，用户名只取事件 username 列。
func (s *Snapshot) Observe(ctx context.Context, tx *sql.Tx, id uuid.UUID, ruleIDs []string) (Observation, error) {
	var e Event
	var assetID, groupID uuid.NullUUID
	var username sql.NullString
	var result Observation
	err := tx.QueryRowContext(ctx, `SELECT e.id,e.ts,e.asset_id,a.group_id,e.username FROM events e
 LEFT JOIN assets a ON a.id=e.asset_id WHERE e.id=$1`, id).Scan(&e.ID, &e.Time, &assetID, &groupID, &username)
	if err != nil {
		return Observation{}, err
	}
	if !assetID.Valid {
		result.skip("unscoped")
		return result, nil
	}
	// 锁住资产行再重新读组，避免归组查询与换组之间的竞态。
	if err := tx.QueryRowContext(ctx, `SELECT group_id FROM assets WHERE id=$1 FOR SHARE`, assetID.UUID).Scan(&groupID); err != nil {
		return Observation{}, err
	}
	if !groupID.Valid || groupID.UUID == uuid.Nil {
		result.skip("unscoped")
		return result, nil
	}
	e.Rules = append([]string(nil), ruleIDs...)
	slices.Sort(e.Rules)
	e.Rules = slices.Compact(e.Rules)
	known := map[string]bool{}
	for _, rule := range s.base.Rules() {
		known[rule.ID] = true
	}
	for _, id := range e.Rules {
		if !known[id] {
			return Observation{}, fmt.Errorf("未知快照基础命中: %s", id)
		}
	}
	// 迟到超过余量的事件：窗口内候选可能已被 PruneCandidates 清理，不在残缺窗口上求值，记缺口。
	// 用数据库时间判断，与清理同一时钟。
	var late bool
	if err := tx.QueryRowContext(ctx, `SELECT $1::timestamptz < now() - make_interval(secs => $2)`, e.Time, LateGrace.Seconds()).Scan(&late); err != nil {
		return Observation{}, err
	}
	if late {
		if err := s.persistArchive(ctx, tx); err != nil {
			return Observation{}, err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO temporal_evaluation_gaps
 (revision,event_id,asset_id,group_id,reason,candidate_count_lower_bound,window_from,window_to)
 VALUES($1,$2,$3,$4,'late',0,$5,$6) ON CONFLICT(revision,event_id) DO NOTHING`,
			s.revision, e.ID, assetID.UUID, groupID.UUID, e.Time.Add(-s.window), e.Time.Add(s.window))
		if err != nil {
			return Observation{}, err
		}
		result.skip("late")
		return result, nil
	}
	assetScope := Scope{Group: groupID.UUID, Entity: assetID.UUID.String()}
	accountScope := Scope{Group: groupID.UUID, Entity: AccountEntity(username.String)}
	byAccount := s.Relevant(GroupByAccount, e.Rules)
	if byAccount && accountScope.Entity == "" {
		result.skip("no_account")
		byAccount = false
	}
	// 加锁顺序固定为先资产后账号：每个事务至多持有一个资产锁和一个账号锁，不会互相等待成环。
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "temporal|"+s.revision+"|"+assetScope.Entity); err != nil {
		return Observation{}, err
	}
	if byAccount {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "temporal|"+s.revision+"|"+groupID.UUID.String()+"|"+accountScope.Entity); err != nil {
			return Observation{}, err
		}
	}
	if err := s.persistArchive(ctx, tx); err != nil {
		return Observation{}, err
	}
	encoded, err := json.Marshal(e.Rules)
	if err != nil {
		return Observation{}, err
	}
	account := sql.NullString{String: strings.TrimPrefix(accountScope.Entity, accountPrefix), Valid: accountScope.Entity != ""}
	var accepted uuid.UUID
	err = tx.QueryRowContext(ctx, `INSERT INTO temporal_candidates AS existing(revision,event_id,asset_id,group_id,ts,rules,account)
VALUES($1,$2,$3,$4,$5,$6::jsonb,$7) ON CONFLICT(revision,event_id) DO UPDATE SET rules=existing.rules
WHERE existing.asset_id=EXCLUDED.asset_id AND existing.group_id=EXCLUDED.group_id
AND existing.ts=EXCLUDED.ts AND existing.rules=EXCLUDED.rules AND existing.account IS NOT DISTINCT FROM EXCLUDED.account RETURNING event_id`,
		s.revision, e.ID, assetID.UUID, groupID.UUID, e.Time, string(encoded), account).Scan(&accepted)
	if err != nil {
		return Observation{}, fmt.Errorf("时序候选写入失败或重投内容冲突: %w", err)
	}
	dimensions := []struct {
		groupBy, column string
		scope           Scope
		key             any
	}{
		{GroupByAsset, "asset_id", assetScope, assetID.UUID},
		{GroupByAccount, "account", accountScope, account.String},
	}
	for _, d := range dimensions {
		if !s.Relevant(d.groupBy, e.Rules) || (d.groupBy == GroupByAccount && !byAccount) {
			continue
		}
		matches, err := s.observeScope(ctx, tx, &result, e, assetID.UUID, d.groupBy, d.column, d.scope, d.key)
		if err != nil {
			return Observation{}, err
		}
		result.Matches = append(result.Matches, matches...)
	}
	return result, nil
}

// observeScope 回查同一实体的候选窗口并记录新命中。column 只取固定列名，不拼接外部输入。
func (s *Snapshot) observeScope(ctx context.Context, tx *sql.Tx, result *Observation, e Event, assetID uuid.UUID, groupBy, column string, scope Scope, key any) ([]Match, error) {
	rows, err := tx.QueryContext(ctx, `SELECT event_id,ts,rules,asset_id FROM temporal_candidates
WHERE revision=$1 AND group_id=$2 AND `+column+`=$3 AND ts >= $4 AND ts <= $5
ORDER BY ts,event_id LIMIT 10001`, s.revision, scope.Group, key, e.Time.Add(-s.window), e.Time.Add(s.window))
	if err != nil {
		return nil, err
	}
	var candidates []Event
	for rows.Next() {
		candidate := Event{Scope: scope}
		var data []byte
		var asset uuid.UUID
		if err := rows.Scan(&candidate.ID, &candidate.Time, &data, &asset); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(data, &candidate.Rules); err != nil {
			rows.Close()
			return nil, err
		}
		candidate.Asset = asset.String()
		candidates = append(candidates, candidate)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(candidates) > 10000 {
		// 容量缺口与事件/基础告警一起提交，避免永久阻塞该资产所在的队列分片。
		// 不在截断窗口上求值，也不将重投视为自动补检。两个维度都超限时只记一条缺口。
		_, err := tx.ExecContext(ctx, `INSERT INTO temporal_evaluation_gaps
 (revision,event_id,asset_id,group_id,reason,candidate_count_lower_bound,window_from,window_to)
 VALUES($1,$2,$3,$4,'candidate_limit',$5,$6,$7) ON CONFLICT(revision,event_id) DO NOTHING`,
			s.revision, e.ID, assetID, scope.Group, len(candidates), e.Time.Add(-s.window), e.Time.Add(s.window))
		if err != nil {
			return nil, err
		}
		result.skip("candidate_limit")
		return nil, nil
	}
	// R1 引用生命周期锁：本函数随后写 temporal_detections（anchor_id）与
	// temporal_evidence（event_id，PinnedIDs 的第二支），涉及的 UTC 日 = 候选窗口里每个
	// 事件的归属日（锚点与证据都在候选集合里）。按日升序一条语句取齐共享锁；processor
	// 入口已按 ±时序窗口 span 取过（本集合是其子集，重复取幂等），独立调用时这里自足。
	if err := eventpart.LifecycleLockShared(ctx, tx, lockDaysFor(candidates, e.Time)...); err != nil {
		return nil, err
	}
	matches, err := s.Evaluate(groupBy, candidates)
	if err != nil {
		return nil, err
	}
	var recorded []Match
	for _, match := range matches {
		// 新事件只可能改变它之后（含同一时刻）终点的结果；更早的终点已在当时求值落库
		if match.Time.Before(e.Time) {
			continue
		}
		evidence, err := json.Marshal(match.Evidence)
		if err != nil {
			return nil, err
		}
		inserted, err := tx.ExecContext(ctx, `INSERT INTO temporal_detections(revision,rule_id,anchor_id,group_id,entity,evidence)
VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT DO NOTHING`, match.Revision, match.RuleID, match.Anchor, match.Scope.Group, match.Scope.Entity, string(evidence))
		if err != nil {
			return nil, err
		}
		n, err := inserted.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		// R1 锁内重读：将被引用的锚点与证据事件确认仍在热表（见 assertHotReferences）。
		if err := assertHotReferences(ctx, tx, append([]uuid.UUID{match.Anchor}, match.Evidence...)...); err != nil {
			return nil, err
		}
		for _, evidenceID := range match.Evidence {
			if evidenceID == match.Anchor {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO temporal_evidence(revision,rule_id,anchor_id,event_id) VALUES($1,$2,$3,$4)`, match.Revision, match.RuleID, match.Anchor, evidenceID); err != nil {
				return nil, err
			}
		}
		recorded = append(recorded, match)
	}
	return recorded, nil
}

// LateGrace 是事件迟到的容忍余量：事件时间早于数据库当前时间减此值时不再求值（记 late 缺口），
// 候选也只需保留到「最大窗口 + LateGrace」。agent 离线缓冲更久的事件照常入库与单事件检测，但不参与时序关联。
const LateGrace = 2 * time.Hour

// pruneSlack 覆盖处理事务从开始（now() 取事务开始时间）到读窗口之间的耗时，清理多留这段余量。
const pruneSlack = 10 * time.Minute

// PruneCandidates 删除不会再被任何求值读取的候选，限批返回删除行数。
// 当前版本：早于 now() - 最大窗口 - LateGrace - pruneSlack；更晚到的事件已按 late 缺口跳过，读不到被删的候选。
// 其他版本可能仍被尚未重载的节点使用，按规则允许的最大窗口 24 小时计。候选不被证据或告警引用，
// 删除不影响已落库命中、temporal_evidence 及原始事件；被删版本的归档随后可由 PruneArchives 释放。
func PruneCandidates(ctx context.Context, db *sql.DB, revision string, window time.Duration) (int64, error) {
	result, err := db.ExecContext(ctx, `DELETE FROM temporal_candidates WHERE ctid = ANY(ARRAY(
 SELECT ctid FROM temporal_candidates WHERE ts < now() - make_interval(secs => $2)
 AND (revision=$1 OR ts < now() - make_interval(secs => $3)) LIMIT 10000))`,
		revision, (window + LateGrace + pruneSlack).Seconds(), (24*time.Hour + LateGrace + pruneSlack).Seconds())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// PruneGaps 按诊断保留期清理时序求值缺口（R6）：只看 gap 自身的 created_at（诊断时间），
// 绝不 JOIN events——冷归档 swap 把事件移出热表后，retire 的差集清理与逐行删除触发器
// 都看不到这些事件的 gap，没有这步它们会永久残留。旧事件迟到新产生的 gap（事件 ts 很老、
// created_at 新）不因事件时间过期。用数据库 now() 判过期，与 created_at 的 DEFAULT now() 同钟。
func PruneGaps(ctx context.Context, db *sql.DB, retention time.Duration) (int64, error) {
	result, err := db.ExecContext(ctx,
		`DELETE FROM temporal_evaluation_gaps WHERE created_at < now() - make_interval(secs => $1)`,
		retention.Seconds())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// lockDaysFor 收集时序引用涉及的 UTC 日：候选窗口里每个事件的归属日（锚点与证据都在
// 候选集合里），加上当前事件自身。
func lockDaysFor(candidates []Event, now time.Time) []time.Time {
	days := make([]time.Time, 0, len(candidates)+1)
	for _, c := range candidates {
		days = append(days, c.Time)
	}
	return append(days, now)
}

// assertHotReferences 是 R1 的锁内重读（时序侧）：将被引用的锚点与证据事件确认仍在热表。
//
// 时序包不能 import 冷归档做物化补链（eventarchive 的切换闸门 guard.go 反过来要用本包
// 的迟到余量，会成环）；物化补链由同一接入事务在事件/告警写入点完成——ingest 的
// eventarchive.EnsureHotEvents。在 processor 的入口锁保护下，候选读出时目标都在热表、
// 同日切换又被共享锁挡住，这里理论上必命中；独立调用或异常状态下热行缺失时，按底稿
// R1 的口径「不支持冷物化的入口至少拒绝建立失效引用」明确失败，错误带事件 id 供排查。
func assertHotReferences(ctx context.Context, tx *sql.Tx, ids ...uuid.UUID) error {
	var missing []string
	for _, id := range ids {
		var hot bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE id = $1)`, id).Scan(&hot); err != nil {
			return fmt.Errorf("核对时序引用目标 %s 是否在热表: %w", id, err)
		}
		if !hot {
			missing = append(missing, id.String())
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("时序引用目标不在热表，拒绝建立失效引用：%s（检查调用方是否持有当日生命周期锁并完成了冷物化补链）",
			strings.Join(missing, "、"))
	}
	return nil
}
