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

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/containment"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/audit"
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

type closedMeta struct {
	assetIDs     []uuid.UUID
	groupIDs     []uuid.UUID
	srcIPs       []string
	firstFailure time.Time
}

// SweepStats 单轮扫描的统计结果。
type SweepStats struct {
	Closed   int
	Reopened int
	Findings int
}

// Closer 认证未得手自动结案、静默后成功登录重开与公网入口加固建议归并器（经 cluster.RunLeader 单活运行）。
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
	closedMetaCache    map[uuid.UUID]closedMeta
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

// Sweep 执行一轮完整核验：先检查已按 attempt_verified 结案的事件是否出现同源成功登录或新告警（重开），
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
	if err := tx.Commit(); err != nil {
		return v, false, err
	}
	return v, true, nil
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

// reopenVerified 增量检查近期按 attempt_verified 结案的事件：若同来源后来出现成功登录（即使未触发新告警）或新告警，立即自动重开。
func (c *Closer) reopenVerified(ctx context.Context, now time.Time) (int, error) {
	cutoff := now.Add(-c.reopenLookback())
	closedIncs, err := c.DB.Incident.Query().
		Where(
			incident.StatusEQ("closed"),
			incident.ResolutionSourceEQ(ResolutionSource),
			incident.ResolvedAtGTE(cutoff),
		).
		Order(ent.Asc(incident.FieldID)).
		All(ctx)
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	if c.reopenCheckedUntil == nil {
		c.reopenCheckedUntil = map[uuid.UUID]time.Time{}
	}
	if c.closedMetaCache == nil {
		c.closedMetaCache = map[uuid.UUID]closedMeta{}
	}
	activeIDs := make(map[uuid.UUID]bool, len(closedIncs))
	for _, inc := range closedIncs {
		activeIDs[inc.ID] = true
	}
	for id := range c.reopenCheckedUntil {
		if !activeIDs[id] {
			delete(c.reopenCheckedUntil, id)
			delete(c.closedMetaCache, id)
		}
	}
	c.mu.Unlock()

	if len(closedIncs) == 0 {
		return 0, nil
	}

	reopened := 0
	for _, inc := range closedIncs {
		if inc.ResolvedAt == nil {
			continue
		}
		ok, err := c.checkAndReopenOne(ctx, inc, now)
		if err != nil {
			if ctx.Err() == nil && isTimeoutError(err) {
				continue
			}
			return reopened, err
		}
		if ok {
			reopened++
		}
	}
	return reopened, nil
}

func (c *Closer) checkAndReopenOne(ctx context.Context, inc *ent.Incident, now time.Time) (bool, error) {
	meta, err := c.getClosedMeta(ctx, inc)
	if err != nil || len(meta.srcIPs) == 0 || len(meta.assetIDs) == 0 {
		return false, err
	}

	c.mu.Lock()
	prevChecked, seen := c.reopenCheckedUntil[inc.ID]
	c.mu.Unlock()

	// 首次检查回溯到首次失败前 1 小时（最多往回 48 小时），捕获迟到补发的成功认证；后续每轮只增量查最近 15 分钟
	since := inc.ResolvedAt.Add(-time.Hour)
	if !meta.firstFailure.IsZero() {
		earliest := maxTime(meta.firstFailure.Add(-time.Hour), inc.ResolvedAt.Add(-48*time.Hour))
		if earliest.Before(since) {
			since = earliest
		}
	}
	if seen && !now.Before(prevChecked) {
		incSince := prevChecked.Add(-15 * time.Minute)
		if incSince.After(since) {
			since = incSince
		}
	}
	queryTo := maxTime(now.Add(5*time.Minute), since.Add(time.Minute))

	qctx, cancel := context.WithTimeout(ctx, c.statementTimeout())
	defer cancel()

	var roTx *sql.Tx
	if c.SQL != nil {
		ms, err := statementTimeoutMillis(qctx, c.statementTimeout())
		if err != nil {
			return false, err
		}
		roTx, err = c.SQL.BeginTx(qctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return false, err
		}
		defer roTx.Rollback()
		if _, err := roTx.ExecContext(qctx, fmt.Sprintf("SET LOCAL statement_timeout = '%dms'", ms)); err != nil {
			return false, err
		}
	}

	srcIPSet := make(map[string]bool, len(meta.srcIPs))
	for _, ip := range meta.srcIPs {
		srcIPSet[ip] = true
	}

	reason := ""

	// 1. 检查同来源成功认证（events + ssh_logins）
	succRows, _, err := queryAssetAuthEvents(qctx, c.DB, roTx, meta.assetIDs, since, queryTo, true, 500)
	if err != nil {
		return false, err
	}
	for _, r := range succRows {
		parsed, ok := ParseAuthEvent(r.classUID, r.source, "", r.username, r.raw)
		if ok && parsed.Success && srcIPSet[parsed.SrcIP] {
			reason = fmt.Sprintf("未得手结案后检测到同来源 %s 成功认证账号 %s（%s，时间 %s），自动重开调查",
				parsed.SrcIP, cmp.Or(parsed.Account, "-"), parsed.ServiceLabel, r.ts.UTC().Format(time.RFC3339))
			break
		}
	}
	if reason == "" {
		sshHits, err := queryGroupSSHLogins(qctx, c.DB, roTx, meta.groupIDs, meta.assetIDs, meta.srcIPs, since, queryTo)
		if err != nil {
			return false, err
		}
		if len(sshHits) > 0 {
			h := sshHits[0]
			reason = fmt.Sprintf("未得手结案后检测到同来源 %s 在主机 %s 成功 SSH 登录账号 %s（时间 %s），自动重开调查",
				h.srcIP, cmp.Or(h.hostname, h.assetID.String()), cmp.Or(h.account, "-"), h.ts.UTC().Format(time.RFC3339))
		}
	}

	// 2. 检查结案时刻之后同来源的新增告警
	if reason == "" {
		alertSince := *inc.ResolvedAt
		if seen && !now.Before(prevChecked) && prevChecked.Add(-15*time.Minute).After(alertSince) {
			alertSince = prevChecked.Add(-15 * time.Minute)
		}
		otherHits, latestFailTs, _, err := querySameSourceAlerts(qctx, c.DB, roTx, inc.ID, meta.groupIDs, meta.assetIDs, srcIPSet, alertSince, queryTo)
		if err != nil {
			return false, err
		}
		for _, oa := range otherHits {
			if oa.Ts.After(*inc.ResolvedAt) {
				reason = fmt.Sprintf("未得手结案后检测到同来源 %s 新增关联告警 %s（时间 %s），自动重开调查",
					oa.SrcIP, oa.RuleID, oa.Ts.UTC().Format(time.RFC3339))
				break
			}
		}
		if reason == "" && latestFailTs.After(*inc.ResolvedAt) {
			reason = fmt.Sprintf("未得手结案后同来源再次发起认证攻击（最新命中 %s），自动重开归并",
				latestFailTs.UTC().Format(time.RFC3339))
		}
	}

	if reason == "" {
		c.mu.Lock()
		c.reopenCheckedUntil[inc.ID] = now
		c.mu.Unlock()
		return false, nil
	}

	tx, err := c.DB.Tx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	reopened, err := reopenIncidentInTx(ctx, tx, inc, now, reason)
	if err != nil || !reopened {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}

	c.mu.Lock()
	delete(c.reopenCheckedUntil, inc.ID)
	delete(c.closedMetaCache, inc.ID)
	c.mu.Unlock()
	return true, nil
}

func (c *Closer) getClosedMeta(ctx context.Context, inc *ent.Incident) (closedMeta, error) {
	c.mu.Lock()
	cached, ok := c.closedMetaCache[inc.ID]
	c.mu.Unlock()
	if ok {
		return cached, nil
	}

	meta, err := extractClosedIncidentMeta(ctx, c.DB, c.SQL, inc, c.statementTimeout())
	if err != nil {
		return closedMeta{}, err
	}
	if len(meta.srcIPs) > 0 && len(meta.assetIDs) > 0 {
		c.mu.Lock()
		c.closedMetaCache[inc.ID] = meta
		c.mu.Unlock()
	}
	return meta, nil
}

func extractClosedIncidentMeta(ctx context.Context, db *ent.Client, sqlDB *sql.DB, inc *ent.Incident, timeout time.Duration) (closedMeta, error) {
	var meta closedMeta
	alerts, err := db.Alert.Query().Where(alert.IncidentIDEQ(inc.ID)).WithAsset().WithEvent().All(ctx)
	if err != nil || len(alerts) == 0 {
		return meta, err
	}
	assetSet := map[uuid.UUID]bool{}
	groupSet := map[uuid.UUID]bool{}
	ipSet := map[string]bool{}
	var minTs, maxTs time.Time
	var alertIDs []uuid.UUID
	var foldFrom, foldTo time.Time
	needFoldScan := false

	for _, a := range alerts {
		alertIDs = append(alertIDs, a.ID)
		if a.AssetID != nil {
			assetSet[*a.AssetID] = true
		}
		if a.Edges.Asset != nil && a.Edges.Asset.GroupID != nil {
			groupSet[*a.Edges.Asset.GroupID] = true
		}
		if minTs.IsZero() || a.Ts.Before(minTs) {
			minTs = a.Ts
		}
		end := a.Ts
		if a.LastTs != nil && a.LastTs.After(end) {
			end = *a.LastTs
		}
		if maxTs.IsZero() || end.After(maxTs) {
			maxTs = end
		}
		if a.LastTs != nil && a.LastTs.After(a.Ts) {
			f, t := a.Ts.Add(-time.Second), end.Add(time.Second)
			if !needFoldScan || f.Before(foldFrom) {
				foldFrom = f
			}
			if !needFoldScan || t.After(foldTo) {
				foldTo = t
			}
			needFoldScan = true
		}
		var raw []byte
		cuid := 0
		if a.Edges.Event != nil {
			cuid = a.Edges.Event.ClassUID
			raw = a.Edges.Event.Raw
		}
		for _, ip := range ExtractAlertIPs(a.RuleID, a.Detail, cuid, raw) {
			ipSet[ip] = true
		}
	}
	for id := range assetSet {
		meta.assetIDs = append(meta.assetIDs, id)
	}
	for id := range groupSet {
		meta.groupIDs = append(meta.groupIDs, id)
	}
	meta.firstFailure = minTs

	// 补充时序证据事件与去重折叠区间内的其他来源 IP
	if len(alertIDs) > 0 && !minTs.IsZero() {
		qctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var roTx *sql.Tx
		if sqlDB != nil {
			if ms, err := statementTimeoutMillis(qctx, timeout); err == nil {
				if t, err := sqlDB.BeginTx(qctx, &sql.TxOptions{ReadOnly: true}); err == nil {
					roTx = t
					defer roTx.Rollback()
					_, _ = roTx.ExecContext(qctx, fmt.Sprintf("SET LOCAL statement_timeout = '%dms'", ms))
				}
			}
		}
		if tempRows, err := loadTemporalEvidenceEvents(qctx, roTx, alertIDs, minTs.Add(-2*time.Hour), maxTs.Add(time.Hour)); err == nil {
			for _, r := range tempRows {
				if r.assetID != uuid.Nil && !assetSet[r.assetID] {
					assetSet[r.assetID] = true
					meta.assetIDs = append(meta.assetIDs, r.assetID)
				}
				if parsed, ok := ParseAuthEvent(r.classUID, r.source, "", r.username, r.raw); ok && parsed.Failure && parsed.SrcIP != "" {
					ipSet[parsed.SrcIP] = true
					if r.ts.Before(meta.firstFailure) {
						meta.firstFailure = r.ts
					}
				}
			}
		}
		if needFoldScan && len(meta.assetIDs) > 0 {
			if rows, _, err := queryAssetAuthEvents(qctx, db, roTx, meta.assetIDs, foldFrom, foldTo, false, 5000); err == nil {
				for _, r := range rows {
					if parsed, ok := ParseAuthEvent(r.classUID, r.source, "", r.username, r.raw); ok && parsed.Failure && parsed.SrcIP != "" {
						ipSet[parsed.SrcIP] = true
						if r.ts.Before(meta.firstFailure) {
							meta.firstFailure = r.ts
						}
					}
				}
			}
		}
	}
	for ip := range ipSet {
		meta.srcIPs = append(meta.srcIPs, ip)
	}
	slices.Sort(meta.srcIPs)
	return meta, nil
}

// ReopenForPendingAlerts 供关联引擎在待归并告警入队时调用：若新到的告警与近期按 attempt_verified 结案的事件同源，
// 当场在同一事务内重开原事件，以便关联引擎直接把新证据并回。
func ReopenForPendingAlerts(ctx context.Context, tx *ent.Tx, pending []*ent.Alert, now time.Time) error {
	if len(pending) == 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	pendingIPByGroup := map[uuid.UUID]map[string]string{}
	pendingIPByAsset := map[uuid.UUID]map[string]string{}
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
	if len(pendingIPByAsset) == 0 && len(pendingIPByGroup) == 0 {
		return nil
	}

	db := tx.Client()
	closedIncs, err := db.Incident.Query().
		Where(
			incident.StatusEQ("closed"),
			incident.ResolutionSourceEQ(ResolutionSource),
			incident.ResolvedAtGTE(now.Add(-7*24*time.Hour)),
		).
		All(ctx)
	if err != nil || len(closedIncs) == 0 {
		return err
	}

	for _, inc := range closedIncs {
		if inc.ResolvedAt == nil {
			continue
		}
		meta, err := extractClosedIncidentMeta(ctx, db, nil, inc, 3*time.Second)
		if err != nil || len(meta.srcIPs) == 0 {
			continue
		}
		matchedIP, matchedRule := "", ""
		for _, ip := range meta.srcIPs {
			for _, gid := range meta.groupIDs {
				if r, ok := pendingIPByGroup[gid][ip]; ok {
					matchedIP, matchedRule = ip, r
					break
				}
			}
			if matchedIP != "" {
				break
			}
			for _, aid := range meta.assetIDs {
				if r, ok := pendingIPByAsset[aid][ip]; ok {
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
