package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/automation"
	"openxdr/server/internal/cmdorigin"
	"openxdr/server/internal/eventarchive"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/graphqueue"
	"openxdr/server/internal/identity"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/temporal"
)

type Metrics interface {
	Processed(source string, duplicate bool, alerts int, elapsed time.Duration)
	Failed(stage string)
}

type Processor struct {
	DB          *sql.DB
	Temporal    *temporal.Store
	Rules       sigma.Catalog
	Suppress    *suppress.Store
	Intel       *intel.Store
	DedupWindow time.Duration
	Metrics     Metrics
	// Archive 是冷归档判重（分区被切走后的重放）；nil = 不启用，行为与改动前一致。
	// 由 main.go 按 EVENT_ARCHIVE_DEDUP 注入，见 archive.go。
	Archive ArchiveDedup
}

// EnsureSchema 创建事务处理状态。temporal_matches 是已消费命中的持久记录，
// 不能在事件仍保留时清空，否则迟到回看可能重复生成告警。
// 指向事件的列都不建外键：分区表的唯一约束必须含 ts，删除级联由 eventpart 的触发器与分区退役负责。
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS alert_dedup_state (
  fingerprint text PRIMARY KEY,
  alert_id uuid NOT NULL,
  first_ts timestamptz NOT NULL,
  last_ts timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS alert_dedup_last_ts ON alert_dedup_state(last_ts);
CREATE TABLE IF NOT EXISTS temporal_matches (
 rule_id text NOT NULL,
 event_id uuid NOT NULL,
 PRIMARY KEY(rule_id,event_id)
);
CREATE INDEX IF NOT EXISTS temporal_matches_event ON temporal_matches(event_id);`)
	if err != nil {
		return err
	}
	if err := temporal.EnsureSchema(ctx, db); err != nil {
		return err
	}
	if err := identity.EnsureSchema(ctx, db); err != nil {
		return err
	}
	return graphqueue.EnsureSchema(ctx, db)
}

func (p *Processor) Process(ctx context.Context, e Envelope) error {
	return p.ProcessBatch(ctx, []Envelope{e})
}

// ProcessBatch 按接收顺序处理整批，在同一事务内提交事件及所有派生状态。
func (p *Processor) ProcessBatch(ctx context.Context, events []Envelope) (err error) {
	if len(events) == 0 {
		return nil
	}
	defer func() {
		if err != nil && p.Metrics != nil {
			p.Metrics.Failed("process")
		}
	}()
	for _, e := range events {
		if err := e.Validate(); err != nil {
			return err
		}
	}
	var snapshot *temporal.Snapshot
	if p.Temporal != nil {
		snapshot = p.Temporal.Current()
		if snapshot == nil {
			return fmt.Errorf("时序规则已配置但没有有效快照")
		}
	}
	tx, err := p.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := p.lockReferenceDays(ctx, tx, events, snapshot); err != nil {
		return err
	}
	type result struct {
		started   time.Time
		duplicate bool
		alerts    int
		skipped   []string
	}
	results := make([]result, len(events))
	for i, e := range events {
		results[i].started = time.Now()
		envelopes, external, err := suricataHit(ctx, tx, e)
		if err != nil {
			return err
		}
		results[i].duplicate = true
		for _, item := range envelopes {
			stored, n, skipped, err := p.store(ctx, tx, item, snapshot, external)
			if err != nil {
				return err
			}
			results[i].duplicate = results[i].duplicate && !stored
			results[i].alerts += n
			results[i].skipped = append(results[i].skipped, skipped...)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// 仅提交成功才计入成功数；耗时包含该事件开始处理至整批提交的真实等待。
	if p.Metrics != nil {
		for i, e := range events {
			r := results[i]
			p.Metrics.Processed(e.Source, r.duplicate, r.alerts, time.Since(r.started))
			if metrics, ok := p.Metrics.(interface{ TemporalSkipped(string) }); ok {
				for _, reason := range r.skipped {
					metrics.TemporalSkipped(reason)
				}
			}
		}
	}
	return nil
}

// store 在调用方事务内落一条事件并产出告警；事件已存在（重传）时返回 stored=false。
func (p *Processor) store(ctx context.Context, tx *sql.Tx, e Envelope, snapshot *temporal.Snapshot, external *intel.Hit) (stored bool, alerts int, temporalSkipped []string, err error) {
	// 同一身份的认证写入先串行，避免并发失败和成功都看不到对方未提交的事件。
	if authEntity(e) {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			"auth-sequence|"+e.AssetID.String()+"|"+e.Username); err != nil {
			return false, 0, nil, err
		}
	}
	// 冷归档判重：分区被 `eventarchive swap` 切走之后，这条事件在 events 里已经没有行了，
	// 下面的 INSERT ... ON CONFLICT 看不到它，迟到/重传会被当成新事件重新入库、重新检测。
	//
	// 为什么是「先查后插」而不是「插入后再删」：插入再删有一段窗口让行重新可见（并可能被
	// 并发读到），而且检测副作用（告警、时序命中、身份观测）已经发生，删掉事件行并不能回滚
	// 它们；先查则命中时一次都不落库，幂等是由「不写」实现的，不是由「写完再撤销」实现的。
	// 查询只在时间闸门命中时才发（见 archivedBefore），代价压在罕见的重传路径上。
	//
	// 竞态分析：
	//   - 并发重传同一条事件仍由下面的 INSERT ... ON CONFLICT 兜底，本检查不承担并发去重。
	//   - 与 Swap 并发：RewriteDay 在事务里先对该日分区加 SHARE 锁再重建；冷块早在
	//     shadow + verify 阶段就写好了，与切换本身无关。所以 Archived 读到的是切换前或
	//     切换后的确定状态，两种落点都不丢事件：
	//     读到「已归档」→ 本次不入库，而该日分区随后也只会移走这一行（本来就不该留在热表）；
	//     读到「不在归档」→ 这条事件不在 run 口径内（类别/来源之外，或仍被 pin 在热表里），
	//     Swap 不会移走它，插入照常成立。只有「口径内、未 pin、闸门通过之后恰好被同一次
	//     切换带走」这一瞬间的插入会随分区重建消失，它的副本仍在冷块里，下一次重传会被判为
	//     已归档——数据不丢，也不会有第二种结果。
	//   - 闸门边界有 60 秒缓存：刚归档/刚切走的时段最多 60 秒内仍可能被判成「不在归档」，
	//     后果与接线前一样（重复入库 + 告警去重窗口吸收），不会反过来丢事件（见 CachedArchive）。
	if p.archivedBefore(ctx, e) {
		return false, 0, nil, nil
	}
	// R1 引用生命周期锁已由 ProcessBatch 在事务开头按整批取齐（见 lockReferenceDays）。
	// 不写冲突列：分区表主键是 (id, ts)，老表是 id。稳定 ID 由含时间戳的来源字段算出，同一 id 必是同一 ts，两者等价
	result, err := tx.ExecContext(ctx, `INSERT INTO events
  (id, ts, class_uid, source, asset_id, process_guid, parent_process_guid, username, conn_tuple, raw)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
ON CONFLICT DO NOTHING`, e.ID, e.Timestamp, e.ClassUID, e.Source,
		nullUUID(e.AssetID), nullUUID(e.ProcessGUID), nullUUID(e.ParentProcessGUID),
		nullString(e.Username), nullString(e.ConnTuple), string(e.Raw))
	if err != nil {
		return false, 0, nil, fmt.Errorf("事件落库: %w", err)
	}
	if inserted, _ := result.RowsAffected(); inserted == 0 {
		return false, 0, nil, nil
	}
	if err := graphqueue.Capture(ctx, tx, e.ID, e.Timestamp, e.ClassUID); err != nil {
		return false, 0, nil, err
	}

	if e.Source == "agent" && e.ClassUID == 3002 && e.AssetID != nil {
		if err := identity.ObserveWindows(ctx, tx, e.ID); err != nil {
			return false, 0, nil, err
		}
		if err := identity.ObserveLinuxLogin(ctx, tx, e.ID); err != nil {
			return false, 0, nil, err
		}
	}
	if e.Source == "agent" && e.ClassUID == 5001 && e.AssetID != nil {
		if err := identity.ObserveLinuxAccounts(ctx, tx, e.ID); err != nil {
			return false, 0, nil, err
		}
	}
	var raw map[string]any
	if json.Unmarshal(e.Raw, &raw) != nil {
		raw = map[string]any{}
	}
	sigma.WithActor(raw, e.Username)
	var baseHits []*sigma.Rule
	if snapshot != nil {
		baseHits = snapshot.EvaluateBase(e.ClassUID, e.AssetOS, raw)
	} else {
		baseHits = p.Rules.Evaluate(e.ClassUID, e.AssetOS, raw)
	}
	var observation temporal.Observation
	if snapshot != nil {
		ids := snapshot.CandidateRules(e.ClassUID, e.AssetOS, raw, baseHits)
		if len(ids) > 0 {
			observation, err = snapshot.Observe(ctx, tx, e.ID, ids)
			if err != nil {
				return false, 0, nil, err
			}
			temporalSkipped = observation.Skipped
		}
	}
	hits := intel.Detections(baseHits, p.Intel.Match(raw, e.Timestamp))
	if external != nil {
		hits = append(hits, *external)
	}
	var from origin
	if len(hits) > 0 {
		if from.command, err = cmdorigin.Of(ctx, tx, raw, e.AssetID, e.Timestamp); err != nil {
			return false, 0, nil, err
		}
		// 平台指令优先：指令拉起的进程也在某次登录会话里，但发起与审批都有记录，挂在指令上更准
		if from.command == nil && e.Source == "agent" {
			if from.automation, err = automation.Of(ctx, tx, raw, e.AssetID, e.Timestamp); err != nil {
				return false, 0, nil, err
			}
		}
	}
	for _, hit := range hits {
		if p.Suppress.Suppressed(hit.RuleID, e.AssetID, raw, e.Timestamp) {
			continue
		}
		hitFrom := from
		hitFrom.watch = from.automation != nil && automation.Watch(hit.RuleID, baseHits)
		created, err := p.upsertAlert(ctx, tx, e, hit, hitFrom)
		if err != nil {
			return false, 0, nil, err
		}
		if created {
			alerts++
		}
	}
	n, err := p.authSequence(ctx, tx, e, authStatus(raw))
	if err != nil {
		return false, 0, nil, err
	}
	alerts += n
	for _, match := range observation.Matches {
		created, err := p.temporalAlert(ctx, tx, match)
		if err != nil {
			return false, 0, nil, err
		}
		if created {
			alerts++
		}
	}
	return true, alerts, temporalSkipped, nil
}

// origin 告警的已知来源：平台指令，或登记的可信自动化（watch 为高危例外，仍进关联与研判）
type origin struct {
	command    *uuid.UUID
	automation *uuid.UUID
	watch      bool
}

// lockReferenceDays 在整批事务开头一次取齐本事务要写的全部事件引用（alerts / temporal_evidence /
// 已出告警的时序锚点）所涉 UTC 日的共享生命周期锁（R1）。锁内插入事件与引用，与同日 swap / retire /
// 到期清理的排他锁互斥：要么引用先落定（swap 的锁内重读把目标行判为 pin 留热），要么破坏性操作先做完
// （本事务等它提交后按「热行缺失 → 冷层物化补链」继续，见 upsertAlert / temporal / EnsureHotEvents）。
//
// 整批一条语句、按 UTC 日升序取（升序是全局锁序，与按日升序取排他锁的一方互相不成环）：
// 逐条事件各取一次既多一次往返，批内日期乱序时取锁顺序也不再升序。
//   - 无时序规则：引用只有事件自身（sigma / 情报 / 时序告警的 event_id 都是刚插入的这条），锁事件所在日；
//   - 有时序规则：时序候选与锚点可能落在 e.Timestamp ± MaxWindow 内的任何一天（窗口不超过 24 小时，
//     两端加中点就覆盖了区间内每一天），一次把整段锁齐。归档只覆盖 min-age 之外的老日子，
//     常规流量锁的是新日子，与 swap 天然错开；只有迟到事件会在老日子上排队，这正是要保护的对象。
//
// Suricata 派生的信封与原事件同一时间戳，按外层事件算即可。之后各写入点再取同日锁是幂等的。
func (p *Processor) lockReferenceDays(ctx context.Context, tx *sql.Tx, events []Envelope, snapshot *temporal.Snapshot) error {
	var window time.Duration
	if snapshot != nil {
		window = snapshot.MaxWindow()
	}
	ts := make([]time.Time, 0, 3*len(events))
	for _, e := range events {
		ts = append(ts, e.Timestamp.Add(-window), e.Timestamp, e.Timestamp.Add(window))
	}
	return eventpart.LifecycleLockShared(ctx, tx, ts...)
}

func (p *Processor) upsertAlert(ctx context.Context, tx *sql.Tx, e Envelope, hit intel.Hit, from origin) (bool, error) {
	// R1 引用写入点：alerts.event_id 是 PinnedIDs 的第一支。先取目标事件归属日的共享
	// 生命周期锁（store 的入口已随 ±时序窗口取齐，这里幂等补上独立调用场景），再锁内
	// 重读目标热行——本事务刚插入的事件必命中（接入热路径零行为差异）；独立路径遇到
	// 热行缺失时由 EnsureHotEvents 从冷层物化回热表再写引用，物化不了（冷层也没有 /
	// 定位状态说不清 / 块损坏）就返回错误让整个引用事务失败，不提交悬空引用。
	if err := eventpart.LifecycleLockShared(ctx, tx, e.Timestamp); err != nil {
		return false, err
	}
	if err := eventarchive.EnsureHotEvents(ctx, tx, e.ID); err != nil {
		return false, err
	}
	fingerprint := alertFingerprint(e, hit, from)
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
  (id, ts, rule_id, severity, event_id, asset_id, count, last_ts, command_id, automation_id, automation_watch, detail)
VALUES ($1,$2,$3,$4,$5,$6,1,$2,$7,$8,$9,$10)`, alertID, e.Timestamp, hit.RuleID, hit.Severity, e.ID, nullUUID(e.AssetID),
		nullUUID(from.command), nullUUID(from.automation), from.watch, nullString(hit.Detail)); err != nil {
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

func alertFingerprint(e Envelope, hit intel.Hit, from origin) string {
	fingerprint := hit.RuleID + "|" + e.PartitionKey + e.FingerprintSuffix
	if hit.RuleID == sigma.RuleBruteforceSuccess {
		fingerprint += "|" + e.Username
	}
	// 指令触发的告警单独去重：否则之后同规则的真实命中会被并进这条「已知来源」的告警里
	if from.command != nil {
		fingerprint += "|cmd:" + from.command.String()
	}
	// 可信来源同理：并进去的真实命中会跟着不进关联
	if from.automation != nil {
		fingerprint += "|auto:" + from.automation.String()
	}
	return fingerprint
}
