package attemptoutcome

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/containment"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/authevents"
	"openxdr/server/internal/incidentstate"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/review"
)

var authFailureRuleList = []string{
	RuleLinuxLoginFailure,
	RuleSSHAuthFailure,
	RuleWinLoginFailure,
	RuleTemporalLinuxAuthBurst,
	RuleTemporalLinuxAccountAuthBurst,
	RuleTemporalSSHDFailBurst,
	RuleTemporalWindowsFailBurst,
}

// SweepStats 单轮扫描的统计结果。
type SweepStats struct {
	Closed   int
	Reopened int
	Findings int
}

// Closer 认证未得手自动结案、静默后成功登录批量重开与公网入口加固建议归并器（经 cluster.RunLeader 单活运行）。
type Closer struct {
	DB                   *ent.Client
	SQL                  *sql.DB
	QuietWindow          time.Duration
	Interval             time.Duration
	StatementTimeout     time.Duration
	MinHardeningFailures int
	MinHardeningSources  int
	ReopenLookback       time.Duration

	mu                 sync.Mutex
	reopenCheckedUntil map[uuid.UUID]time.Time
}

// Run 单活后台定时扫描循环。
func (c *Closer) Run(ctx context.Context) {
	interval := c.Interval
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		stats, err := c.Sweep(ctx, time.Now())
		if err != nil && ctx.Err() == nil {
			slog.Error("认证尝试结果核验扫描失败", "err", err)
		} else if stats.Closed > 0 || stats.Reopened > 0 || stats.Findings > 0 {
			slog.Info("认证尝试结果核验完成",
				"closed", stats.Closed,
				"reopened", stats.Reopened,
				"findings", stats.Findings,
			)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Closer) quietWindow() time.Duration {
	if c.QuietWindow <= 0 {
		return DefaultQuietHours * time.Hour
	}
	return c.QuietWindow
}

func (c *Closer) statementTimeout() time.Duration {
	if c.StatementTimeout <= 0 {
		return defaultStatementTimeout
	}
	return c.StatementTimeout
}

func (c *Closer) reopenLookback() time.Duration {
	if c.ReopenLookback <= 0 {
		return 7 * 24 * time.Hour
	}
	return c.ReopenLookback
}

// Sweep 执行一轮完整核验：先按近 7 天已结案集合批量检查是否出现同源成功登录（重开），
// 再核验未结案认证失败族事件并更新反复猜解服务的加固建议待办。
func (c *Closer) Sweep(ctx context.Context, now time.Time) (SweepStats, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var stats SweepStats

	reopened, err := c.reopenVerified(ctx, now)
	stats.Reopened = reopened
	if err != nil {
		return stats, err
	}

	closedCount, findingsCount, err := c.closeAndTrack(ctx, now)
	stats.Closed = closedCount
	stats.Findings = findingsCount
	return stats, err
}

func (c *Closer) closeAndTrack(ctx context.Context, now time.Time) (int, int, error) {
	closedCount := 0
	targetDedup := map[string]ServiceTarget{}
	var cursor uuid.UUID

	for {
		if err := ctx.Err(); err != nil {
			return closedCount, 0, err
		}
		candidates, err := c.DB.Incident.Query().
			Where(
				incident.StatusIn("open", "triaged"),
				incident.IDGT(cursor),
				incident.HasAlertsWith(alert.RuleIDIn(authFailureRuleList...)),
				incident.Not(incident.HasAlertsWith(alert.RuleIDNotIn(authFailureRuleList...))),
			).
			Order(ent.Asc(incident.FieldID)).
			Limit(200).
			All(ctx)
		if err != nil {
			return closedCount, 0, err
		}
		if len(candidates) == 0 {
			break
		}

		for _, inc := range candidates {
			cursor = inc.ID
			v, didClose, err := c.evaluateOne(ctx, inc, now)
			if err != nil {
				return closedCount, 0, err
			}
			if v != nil && len(v.InternalSources) == 0 {
				for _, tgt := range v.Targets {
					if tgt.GroupID != uuid.Nil && tgt.AssetID != uuid.Nil {
						targetDedup[tgt.AssetID.String()+"|"+tgt.ServiceSlug] = tgt
					}
				}
			}
			if didClose {
				closedCount++
			}
		}
		if len(candidates) < 200 {
			break
		}
	}

	var targets []ServiceTarget
	for _, tgt := range targetDedup {
		targets = append(targets, tgt)
	}
	slices.SortFunc(targets, func(a, b ServiceTarget) int {
		return cmp.Or(strings.Compare(a.AssetID.String(), b.AssetID.String()), strings.Compare(a.ServiceSlug, b.ServiceSlug))
	})

	findingsUpdated, err := UpsertHardeningFindings(
		ctx,
		c.DB,
		c.SQL,
		targets,
		now,
		c.MinHardeningFailures,
		c.MinHardeningSources,
		c.statementTimeout(),
	)
	return closedCount, findingsUpdated, err
}

func (c *Closer) evaluateOne(ctx context.Context, inc *ent.Incident, now time.Time) (*Verification, bool, error) {
	v, err := Verify(ctx, c.DB, c.SQL, inc.ID, Options{
		Now:              now,
		QuietWindow:      c.quietWindow(),
		StatementTimeout: c.statementTimeout(),
	})
	if err != nil || v == nil || !v.ReadyToClose() {
		return v, false, err
	}

	// 人工接管/锁定、正在执行研判、已有遏制处置或正在运行绑定该事件的 AI 对话时，不自动结案
	if ManuallyHeld(inc) {
		return v, false, nil
	}
	if inc.TriageHeartbeatAt != nil && inc.TriageHeartbeatAt.After(now.Add(-2*time.Minute)) {
		return v, false, nil
	}
	hasContainment, err := c.incidentHasContainment(ctx, inc.ID)
	if err != nil || hasContainment {
		return v, false, err
	}
	hasRunningChat, err := c.incidentHasRunningSession(ctx, inc.ID)
	if err != nil || hasRunningChat {
		return v, false, err
	}

	alertSnapshotCount, alertMaxEnd, err := c.incidentAlertWatermark(ctx, c.DB, inc.ID)
	if err != nil {
		return v, false, err
	}
	if alertMaxEnd.After(v.LastFailure) {
		return v, false, nil
	}

	tx, err := c.DB.Tx(ctx)
	if err != nil {
		return v, false, err
	}
	defer tx.Rollback()

	fresh, err := tx.Incident.Get(ctx, inc.ID)
	if err != nil {
		if ent.IsNotFound(err) {
			return v, false, nil
		}
		return v, false, err
	}
	if (fresh.Status != "open" && fresh.Status != "triaged") ||
		ManuallyHeld(fresh) ||
		(fresh.TriageHeartbeatAt != nil && fresh.TriageHeartbeatAt.After(now.Add(-2*time.Minute))) {
		return v, false, nil
	}

	txAlertCount, txMaxEnd, err := c.incidentAlertWatermark(ctx, tx.Client(), inc.ID)
	if err != nil {
		return v, false, err
	}
	if txAlertCount != alertSnapshotCount || !txMaxEnd.Equal(alertMaxEnd) {
		return v, false, nil
	}

	resolution := v.FormatResolution()
	n, err := tx.Incident.Update().
		Where(
			incident.IDEQ(inc.ID),
			incident.StatusEQ(fresh.Status),
		).
		SetStatus("closed").
		SetResolvedBy(review.ClosedBy).
		SetResolutionSource(ResolutionSource).
		SetResolvedAt(now).
		SetResolution(resolution).
		ClearClosureProposal().
		Save(ctx)
	if err != nil || n != 1 {
		return v, false, err
	}

	closedInc, err := tx.Incident.Get(ctx, inc.ID)
	if err != nil {
		return v, false, err
	}
	if err := incidentwork.Refresh(ctx, tx.Client(), closedInc, now); err != nil {
		return v, false, err
	}
	if err := incidentstate.Record(ctx, tx, inc.ID, incidentstate.StatusChanged, incidentstate.Origin{Kind: ResolutionSource, ID: Actor}, fresh.Status); err != nil {
		return v, false, err
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), Actor, "server", AuditActionVerified, inc.ID.String(), "closed "+resolution); err != nil {
		return v, false, err
	}

	// 先登记已结案来源索引再提交结案事务：确保事件进入 closed 瞬间重开索引已就位；若提交失败则回滚清理
	if err := RecordClosure(ctx, c.SQL, inc.ID, v.Targets, v.SourceIPs, v.FirstFailure, now); err != nil {
		return v, false, err
	}
	if err := tx.Commit(); err != nil {
		_ = DeleteClosures(context.WithoutCancel(ctx), c.SQL, inc.ID)
		return v, false, err
	}
	return v, true, nil
}

// RecordClosure 将按 attempt_verified 自动结案的（事件、来源 IP、目标资产/组）写入 auth_attempt_closures 索引表。
func RecordClosure(
	ctx context.Context,
	sqlDB *sql.DB,
	incidentID uuid.UUID,
	targets []ServiceTarget,
	srcIPs []string,
	firstFailure, resolvedAt time.Time,
) error {
	if sqlDB == nil || incidentID == uuid.Nil || len(targets) == 0 || len(srcIPs) == 0 {
		return nil
	}
	type assetGroup struct {
		assetID uuid.UUID
		groupID uuid.NullUUID
	}
	seenAssets := map[uuid.UUID]assetGroup{}
	for _, t := range targets {
		if t.AssetID == uuid.Nil {
			continue
		}
		var gid uuid.NullUUID
		if t.GroupID != uuid.Nil {
			gid = uuid.NullUUID{UUID: t.GroupID, Valid: true}
		}
		seenAssets[t.AssetID] = assetGroup{assetID: t.AssetID, groupID: gid}
	}
	if len(seenAssets) == 0 {
		return nil
	}

	total := len(seenAssets) * len(srcIPs)
	incIDs := make([]uuid.UUID, 0, total)
	ips := make([]string, 0, total)
	assetIDs := make([]uuid.UUID, 0, total)
	groupIDs := make([]uuid.NullUUID, 0, total)
	firsts := make([]time.Time, 0, total)
	resolveds := make([]time.Time, 0, total)

	if firstFailure.IsZero() {
		firstFailure = resolvedAt
	}
	for _, ag := range seenAssets {
		for _, ip := range srcIPs {
			if ip == "" {
				continue
			}
			incIDs = append(incIDs, incidentID)
			ips = append(ips, ip)
			assetIDs = append(assetIDs, ag.assetID)
			groupIDs = append(groupIDs, ag.groupID)
			firsts = append(firsts, firstFailure)
			resolveds = append(resolveds, resolvedAt)
		}
	}
	if len(incIDs) == 0 {
		return nil
	}
	_, err := sqlDB.ExecContext(ctx, `
INSERT INTO auth_attempt_closures (incident_id, src_ip, asset_id, group_id, first_failure, resolved_at)
SELECT * FROM unnest($1::uuid[], $2::text[], $3::uuid[], $4::uuid[], $5::timestamptz[], $6::timestamptz[])
ON CONFLICT (incident_id, src_ip, asset_id) DO UPDATE
SET group_id = COALESCE(EXCLUDED.group_id, auth_attempt_closures.group_id),
    first_failure = LEAST(auth_attempt_closures.first_failure, EXCLUDED.first_failure),
    resolved_at = EXCLUDED.resolved_at`,
		incIDs, ips, assetIDs, groupIDs, firsts, resolveds,
	)
	return err
}

// DeleteClosures 按事件 ID 批量清理已重开或结案回滚的 auth_attempt_closures 索引行。
func DeleteClosures(ctx context.Context, sqlDB *sql.DB, incidentIDs ...uuid.UUID) error {
	if sqlDB == nil || len(incidentIDs) == 0 {
		return nil
	}
	_, err := sqlDB.ExecContext(ctx, `DELETE FROM auth_attempt_closures WHERE incident_id = ANY($1)`, incidentIDs)
	return err
}

func (c *Closer) incidentHasContainment(ctx context.Context, incID uuid.UUID) (bool, error) {
	alertIDs, err := c.DB.Alert.Query().Where(alert.IncidentIDEQ(incID)).IDs(ctx)
	if err != nil {
		return false, err
	}
	if len(alertIDs) == 0 {
		return c.DB.Containment.Query().Where(containment.IncidentIDEQ(incID)).Exist(ctx)
	}
	return c.DB.Containment.Query().
		Where(containment.Or(containment.IncidentIDEQ(incID), containment.AlertIDIn(alertIDs...))).
		Exist(ctx)
}

func (c *Closer) incidentHasRunningSession(ctx context.Context, incID uuid.UUID) (bool, error) {
	rows, err := c.DB.AgentSession.Query().
		Where(agentsession.StatusEQ("running")).
		Select(agentsession.FieldSubjects).
		All(ctx)
	if err != nil {
		return false, err
	}
	needle := "incident:" + incID.String()
	for _, r := range rows {
		if slices.Contains(r.Subjects, needle) {
			return true, nil
		}
	}
	return false, nil
}

func (c *Closer) incidentAlertWatermark(ctx context.Context, db *ent.Client, incID uuid.UUID) (int, time.Time, error) {
	alerts, err := db.Alert.Query().Where(alert.IncidentIDEQ(incID)).Select(alert.FieldID, alert.FieldRuleID, alert.FieldTs, alert.FieldLastTs).All(ctx)
	if err != nil {
		return 0, time.Time{}, err
	}
	if !IncidentAllAuthFailures(alerts) {
		return -1, time.Time{}, nil
	}
	var maxEnd time.Time
	for _, a := range alerts {
		end := a.Ts
		if a.LastTs != nil && a.LastTs.After(end) {
			end = *a.LastTs
		}
		if end.After(maxEnd) {
			maxEnd = end
		}
	}
	return len(alerts), maxEnd, nil
}

type closureEntry struct {
	incidentID   uuid.UUID
	srcIP        string
	assetID      uuid.UUID
	groupID      uuid.UUID
	firstFailure time.Time
	resolvedAt   time.Time
}

type batchSuccessHit struct {
	eventID  uuid.UUID
	assetID  uuid.UUID
	hostname string
	groupID  uuid.UUID
	ts       time.Time
	srcIP    string
	service  string
	account  string
}

// reopenVerified 批量检查近 7 天按 attempt_verified 结案的「来源 IP + 资产」集合：
// 每轮只用一条查询在 auth_events 上按 (src_ip, ts) 索引查 success=true，命中同来源成功登录即自动重开。
// 新告警触发的重开由关联引擎热路径 ReopenForPendingAlerts 当场处理。
func (c *Closer) reopenVerified(ctx context.Context, now time.Time) (int, error) {
	if c.SQL == nil {
		return 0, nil
	}
	cutoff := now.Add(-c.reopenLookback())

	// 1. 清理超出 7 天观察期或事件已不再处于 closed+attempt_verified 状态的索引行
	if _, err := c.SQL.ExecContext(ctx, `
DELETE FROM auth_attempt_closures c
WHERE c.resolved_at < $1
   OR NOT EXISTS (
     SELECT 1 FROM incidents i
     WHERE i.id = c.incident_id
       AND i.status = 'closed'
       AND i.resolution_source = $2
   )`, cutoff, ResolutionSource); err != nil {
		return 0, err
	}

	// 2. 一次取出近 7 天所有活跃 attempt_verified 结案的（事件、来源 IP、目标资产/组）集合
	rows, err := c.SQL.QueryContext(ctx, `
SELECT c.incident_id, c.src_ip, c.asset_id, c.group_id, c.first_failure, i.resolved_at
FROM auth_attempt_closures c
JOIN incidents i ON i.id = c.incident_id
WHERE c.resolved_at >= $1
  AND i.status = 'closed'
  AND i.resolution_source = $2`, cutoff, ResolutionSource)
	if err != nil {
		return 0, err
	}
	var entries []closureEntry
	activeIncidents := map[uuid.UUID]time.Time{}
	closuresByIP := map[string][]closureEntry{}
	for rows.Next() {
		var (
			e          closureEntry
			gid        uuid.NullUUID
			resolvedAt sql.NullTime
		)
		if err := rows.Scan(&e.incidentID, &e.srcIP, &e.assetID, &gid, &e.firstFailure, &resolvedAt); err != nil {
			rows.Close()
			return 0, err
		}
		if !resolvedAt.Valid || e.srcIP == "" {
			continue
		}
		e.resolvedAt = resolvedAt.Time
		if gid.Valid {
			e.groupID = gid.UUID
		}
		entries = append(entries, e)
		activeIncidents[e.incidentID] = e.resolvedAt
		closuresByIP[e.srcIP] = append(closuresByIP[e.srcIP], e)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	c.mu.Lock()
	if c.reopenCheckedUntil == nil {
		c.reopenCheckedUntil = map[uuid.UUID]time.Time{}
	}
	for id := range c.reopenCheckedUntil {
		if _, ok := activeIncidents[id]; !ok {
			delete(c.reopenCheckedUntil, id)
		}
	}
	if len(entries) == 0 {
		c.mu.Unlock()
		return 0, nil
	}

	var batchSince time.Time
	for _, e := range entries {
		incSince := e.resolvedAt.Add(-time.Hour)
		if !e.firstFailure.IsZero() {
			earliest := maxTime(e.firstFailure.Add(-time.Hour), e.resolvedAt.Add(-48*time.Hour))
			if earliest.Before(incSince) {
				incSince = earliest
			}
		}
		if prev, seen := c.reopenCheckedUntil[e.incidentID]; seen && !now.Before(prev) {
			if delta := prev.Add(-15 * time.Minute); delta.After(incSince) {
				incSince = delta
			}
		}
		if batchSince.IsZero() || incSince.Before(batchSince) {
			batchSince = incSince
		}
	}
	c.mu.Unlock()

	allSrcIPs := make([]string, 0, len(closuresByIP))
	for ip := range closuresByIP {
		allSrcIPs = append(allSrcIPs, ip)
	}
	slices.Sort(allSrcIPs)
	queryTo := maxTime(now.Add(5*time.Minute), batchSince.Add(time.Minute))

	// 3. 在带 statement_timeout 的只读事务内，用一条查询对 auth_events 做 src_ip = ANY(...) 且 success = true 的匹配
	hits, truncated, err := c.queryBatchSuccessAuthEvents(ctx, allSrcIPs, batchSince, queryTo, maxSuccessScanRows)
	if err != nil {
		if ctx.Err() == nil && isTimeoutError(err) {
			return 0, nil
		}
		return 0, err
	}

	type reopenPlan struct {
		resolvedAt time.Time
		reason     string
	}
	plans := map[uuid.UUID]reopenPlan{}
	for _, h := range hits {
		for _, ce := range closuresByIP[h.srcIP] {
			if _, exists := plans[ce.incidentID]; exists {
				continue
			}
			sameScope := h.assetID == ce.assetID || (ce.groupID != uuid.Nil && h.groupID == ce.groupID)
			if !sameScope {
				continue
			}
			minAllowed := ce.resolvedAt.Add(-48 * time.Hour)
			if !ce.firstFailure.IsZero() && ce.firstFailure.Add(-time.Hour).After(minAllowed) {
				minAllowed = ce.firstFailure.Add(-time.Hour)
			}
			if h.ts.Before(minAllowed) {
				continue
			}
			hostLabel := cmp.Or(h.hostname, h.assetID.String())
			plans[ce.incidentID] = reopenPlan{
				resolvedAt: ce.resolvedAt,
				reason: fmt.Sprintf("未得手结案后检测到同来源 %s 在主机 %s 成功认证账号 %s（%s，时间 %s），自动重开调查",
					h.srcIP, hostLabel, cmp.Or(h.account, "-"), authevents.ServiceLabel(h.service), h.ts.UTC().Format(time.RFC3339)),
			}
		}
	}

	planIDs := make([]uuid.UUID, 0, len(plans))
	for id := range plans {
		planIDs = append(planIDs, id)
	}
	slices.SortFunc(planIDs, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })

	reopened := 0
	var reopenedIDs []uuid.UUID
	for _, incID := range planIDs {
		p := plans[incID]
		resolvedAt := p.resolvedAt
		tx, err := c.DB.Tx(ctx)
		if err != nil {
			return reopened, err
		}
		ok, err := reopenIncidentInTx(ctx, tx, &ent.Incident{ID: incID, ResolvedAt: &resolvedAt}, now, p.reason)
		if err != nil {
			_ = tx.Rollback()
			return reopened, err
		}
		if !ok {
			_ = tx.Rollback()
			continue
		}
		if err := tx.Commit(); err != nil {
			return reopened, err
		}
		reopened++
		reopenedIDs = append(reopenedIDs, incID)
	}
	if len(reopenedIDs) > 0 {
		_ = DeleteClosures(ctx, c.SQL, reopenedIDs...)
	}

	c.mu.Lock()
	reopenedSet := make(map[uuid.UUID]bool, len(reopenedIDs))
	for _, id := range reopenedIDs {
		reopenedSet[id] = true
		delete(c.reopenCheckedUntil, id)
	}
	if !truncated {
		for id := range activeIncidents {
			if !reopenedSet[id] {
				c.reopenCheckedUntil[id] = now
			}
		}
	}
	c.mu.Unlock()
	return reopened, nil
}

func (c *Closer) queryBatchSuccessAuthEvents(
	ctx context.Context,
	srcIPs []string,
	from, to time.Time,
	limit int,
) ([]batchSuccessHit, bool, error) {
	if c.SQL == nil || len(srcIPs) == 0 {
		return nil, false, nil
	}
	qctx, cancel := context.WithTimeout(ctx, c.statementTimeout())
	defer cancel()

	ms, err := statementTimeoutMillis(qctx, c.statementTimeout())
	if err != nil {
		return nil, false, err
	}
	roTx, err := c.SQL.BeginTx(qctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, false, err
	}
	defer roTx.Rollback()
	if _, err := roTx.ExecContext(qctx, fmt.Sprintf("SET LOCAL statement_timeout = '%dms'", ms)); err != nil {
		return nil, false, err
	}

	rows, err := roTx.QueryContext(qctx, `
SELECT ae.event_id, ae.asset_id, COALESCE(a.hostname, ''), a.group_id, ae.ts, ae.src_ip, ae.service, ae.account
FROM auth_events ae
LEFT JOIN assets a ON a.id = ae.asset_id
WHERE ae.src_ip = ANY($1)
  AND ae.ts >= $2 AND ae.ts <= $3
  AND ae.success = true
LIMIT $4`, srcIPs, from, to, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	var out []batchSuccessHit
	for rows.Next() {
		var (
			h   batchSuccessHit
			gid uuid.NullUUID
		)
		if err := rows.Scan(&h.eventID, &h.assetID, &h.hostname, &gid, &h.ts, &h.srcIP, &h.service, &h.account); err != nil {
			return nil, false, err
		}
		if gid.Valid {
			h.groupID = gid.UUID
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	slices.SortFunc(out, func(a, b batchSuccessHit) int {
		return cmp.Or(a.ts.Compare(b.ts), strings.Compare(a.eventID.String(), b.eventID.String()))
	})
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

// ReopenForPendingAlerts 供关联引擎在待归并告警入队时调用：
// 只对 auth_attempt_closures (src_ip, resolved_at) 索引做单次点查；批内无来源 IP 时零查询返回，无命中时零额外开销返回。
func ReopenForPendingAlerts(ctx context.Context, tx *ent.Tx, sqlDB *sql.DB, pending []*ent.Alert, now time.Time) error {
	if len(pending) == 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}

	pendingIPByGroup := map[uuid.UUID]map[string]string{}
	pendingIPByAsset := map[uuid.UUID]map[string]string{}
	ipDedup := map[string]bool{}

	for _, al := range pending {
		if al == nil || al.AssetID == nil {
			continue
		}
		cuid := 0
		var raw []byte
		if al.Edges.Event != nil {
			cuid = al.Edges.Event.ClassUID
			raw = al.Edges.Event.Raw
		}
		ips := ExtractAlertIPs(al.RuleID, al.Detail, cuid, raw)
		if len(ips) == 0 {
			continue
		}
		if pendingIPByAsset[*al.AssetID] == nil {
			pendingIPByAsset[*al.AssetID] = map[string]string{}
		}
		for _, ip := range ips {
			ipDedup[ip] = true
			pendingIPByAsset[*al.AssetID][ip] = al.RuleID
		}
		if al.Edges.Asset != nil && al.Edges.Asset.GroupID != nil {
			gid := *al.Edges.Asset.GroupID
			if pendingIPByGroup[gid] == nil {
				pendingIPByGroup[gid] = map[string]string{}
			}
			for _, ip := range ips {
				pendingIPByGroup[gid][ip] = al.RuleID
			}
		}
	}
	if len(ipDedup) == 0 {
		return nil
	}

	allIPs := make([]string, 0, len(ipDedup))
	for ip := range ipDedup {
		allIPs = append(allIPs, ip)
	}
	slices.Sort(allIPs)
	cutoff := now.Add(-7 * 24 * time.Hour)

	if sqlDB == nil {
		return reopenPendingViaEntFallback(ctx, tx, allIPs, cutoff, pendingIPByAsset, pendingIPByGroup, now)
	}

	rows, err := sqlDB.QueryContext(ctx, `
SELECT incident_id, src_ip, asset_id, group_id
FROM auth_attempt_closures
WHERE src_ip = ANY($1)
  AND resolved_at >= $2`, allIPs, cutoff)
	if err != nil {
		return err
	}
	type matchedClosure struct {
		ip     string
		ruleID string
	}
	matched := map[uuid.UUID]matchedClosure{}
	for rows.Next() {
		var (
			incID   uuid.UUID
			srcIP   string
			assetID uuid.UUID
			gid     uuid.NullUUID
		)
		if err := rows.Scan(&incID, &srcIP, &assetID, &gid); err != nil {
			rows.Close()
			return err
		}
		if _, done := matched[incID]; done {
			continue
		}
		ruleID := ""
		if gid.Valid {
			ruleID = pendingIPByGroup[gid.UUID][srcIP]
		}
		if ruleID == "" {
			ruleID = pendingIPByAsset[assetID][srcIP]
		}
		if ruleID == "" {
			continue
		}
		matched[incID] = matchedClosure{ip: srcIP, ruleID: ruleID}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(matched) == 0 {
		return nil
	}

	var staleOrReopenedIDs []uuid.UUID
	for incID, m := range matched {
		inc, err := tx.Incident.Get(ctx, incID)
		if err != nil {
			if ent.IsNotFound(err) {
				staleOrReopenedIDs = append(staleOrReopenedIDs, incID)
				continue
			}
			return err
		}
		if inc.Status != "closed" || inc.ResolutionSource == nil || *inc.ResolutionSource != ResolutionSource || inc.ResolvedAt == nil {
			staleOrReopenedIDs = append(staleOrReopenedIDs, incID)
			continue
		}
		reason := fmt.Sprintf("未得手结案后到达同来源 %s 的新告警 %s，自动重开并归并调查", m.ip, m.ruleID)
		ok, err := reopenIncidentInTx(ctx, tx, inc, now, reason)
		if err != nil {
			return err
		}
		if ok {
			staleOrReopenedIDs = append(staleOrReopenedIDs, incID)
		}
	}
	if len(staleOrReopenedIDs) > 0 {
		idsCopy := slices.Clone(staleOrReopenedIDs)
		tx.OnCommit(func(next ent.Committer) ent.Committer {
			return ent.CommitFunc(func(cctx context.Context, tx *ent.Tx) error {
				if err := next.Commit(cctx, tx); err != nil {
					return err
				}
				_ = DeleteClosures(context.WithoutCancel(cctx), sqlDB, idsCopy...)
				return nil
			})
		})
	}
	return nil
}

// reopenPendingViaEntFallback 兼容未注入 SQL 的单元测试/集成测试 Engine：仍走 auth_attempt_closures (src_ip, resolved_at) 索引半连接。
func reopenPendingViaEntFallback(
	ctx context.Context,
	tx *ent.Tx,
	allIPs []string,
	cutoff time.Time,
	pendingIPByAsset map[uuid.UUID]map[string]string,
	pendingIPByGroup map[uuid.UUID]map[string]string,
	now time.Time,
) error {
	db := tx.Client()
	anyIPs := make([]any, len(allIPs))
	for i, ip := range allIPs {
		anyIPs[i] = ip
	}
	closedIncs, err := db.Incident.Query().
		Where(
			incident.StatusEQ("closed"),
			incident.ResolutionSourceEQ(ResolutionSource),
			predicate.Incident(func(s *entsql.Selector) {
				c := entsql.Table("auth_attempt_closures").As("c")
				sub := entsql.Select(c.C("incident_id")).From(c).Where(entsql.And(
					entsql.ColumnsEQ(c.C("incident_id"), s.C(incident.FieldID)),
					entsql.In(c.C("src_ip"), anyIPs...),
					entsql.GTE(c.C("resolved_at"), cutoff),
				))
				s.Where(entsql.Exists(sub))
			}),
		).
		WithAlerts(func(q *ent.AlertQuery) { q.WithAsset() }).
		All(ctx)
	if err != nil || len(closedIncs) == 0 {
		return err
	}
	for _, inc := range closedIncs {
		if inc.ResolvedAt == nil {
			continue
		}
		matchedIP, matchedRule := "", ""
		for _, a := range inc.Edges.Alerts {
			if a.AssetID != nil {
				for ip, r := range pendingIPByAsset[*a.AssetID] {
					matchedIP, matchedRule = ip, r
					break
				}
			}
			if matchedIP == "" && a.Edges.Asset != nil && a.Edges.Asset.GroupID != nil {
				for ip, r := range pendingIPByGroup[*a.Edges.Asset.GroupID] {
					matchedIP, matchedRule = ip, r
					break
				}
			}
			if matchedIP != "" {
				break
			}
		}
		if matchedIP == "" {
			continue
		}
		reason := fmt.Sprintf("未得手结案后到达同来源 %s 的新告警 %s，自动重开并归并调查", matchedIP, matchedRule)
		if _, err := reopenIncidentInTx(ctx, tx, inc, now, reason); err != nil {
			return err
		}
	}
	return nil
}

func reopenIncidentInTx(ctx context.Context, tx *ent.Tx, inc *ent.Incident, now time.Time, reason string) (bool, error) {
	if inc.ResolvedAt == nil {
		return false, nil
	}
	db := tx.Client()
	n, err := db.Incident.Update().
		Where(
			incident.IDEQ(inc.ID),
			incident.StatusEQ("closed"),
			incident.ResolutionSourceEQ(ResolutionSource),
			incident.ResolvedAtEQ(*inc.ResolvedAt),
		).
		SetStatus("open").
		SetEvidenceAt(now).
		SetUrgentAt(now).
		ClearResolution().
		ClearResolvedAt().
		ClearResolvedBy().
		ClearResolutionSource().
		ClearClosureProposal().
		ClearWork().
		ClearWorkNextCheckAt().
		Save(ctx)
	if err != nil || n != 1 {
		return false, err
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), Actor, "server", AuditActionReopened, inc.ID.String(), reason); err != nil {
		return false, err
	}
	if err := incidentstate.Record(ctx, tx, inc.ID, incidentstate.StatusChanged, incidentstate.Origin{Kind: ResolutionSource, ID: Actor}, "closed"); err != nil {
		return false, err
	}
	return true, nil
}
