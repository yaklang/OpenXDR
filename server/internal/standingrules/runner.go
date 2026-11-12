package standingrules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/approval"
	"openxdr/server/ent/command"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/standingrule"
	"openxdr/server/ent/standingrulerun"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/repairpolicy"
	"openxdr/server/internal/response"
)

const (
	defaultInterval                 = time.Minute
	proposalTTL                     = 24 * time.Hour
	skipDedupWindow                 = 6 * time.Hour
	onlineGrace                     = 5 * time.Minute
	DefaultMaxProposalExecsPerTick  = 3
	DefaultMaxHostDispatchesPerTick = 5
)

// Runner 单活执行常设规矩：推进已批准的提议、扫描未结案运维待办并按三档边界执行。
type Runner struct {
	DB                *ent.Client
	Hub               *response.Hub
	Repair            *repairpolicy.Store
	Notify            func(ctx context.Context, title, text, path string) error
	NotifyApproval    func(ctx context.Context, title, text, path string) error
	Now               func() time.Time
	Poll              time.Duration
	Interval          time.Duration
	MaxProposalExecs  int
	MaxHostDispatches int
	// IssueAndWait 测试替身：下发单条命令并等待完成，返回落库的 *ent.Command。为空时走 Hub.IssueExec。
	IssueAndWait func(ctx context.Context, a *ent.Asset, cmd, issuedBy string, timeout time.Duration, onIssued func(*ent.Command) error) (*ent.Command, error)
}

func (r *Runner) maxProposalExecs() int {
	if r.MaxProposalExecs > 0 {
		return r.MaxProposalExecs
	}
	return DefaultMaxProposalExecsPerTick
}

func (r *Runner) maxHostDispatches() int {
	if r.MaxHostDispatches > 0 {
		return r.MaxHostDispatches
	}
	return DefaultMaxHostDispatchesPerTick
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Runner) pollInterval() time.Duration {
	if r.Poll > 0 {
		return r.Poll
	}
	return 2 * time.Second
}

// Run 周期运行单活循环。
func (r *Runner) Run(ctx context.Context) {
	interval := r.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := r.Tick(ctx); err != nil && ctx.Err() == nil {
			slog.Error("常设规矩单活轮次失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick 执行单轮常设规矩对账与匹配。
func (r *Runner) Tick(ctx context.Context) error {
	if err := r.reconcilePendingApprovals(ctx); err != nil {
		return err
	}
	rules, err := r.DB.StandingRule.Query().
		Where(standingrule.EnabledEQ(true)).
		Order(ent.Asc(standingrule.FieldCreatedAt)).
		All(ctx)
	if err != nil || len(rules) == 0 {
		return err
	}
	now := r.now()
	openFindings, err := r.DB.Finding.Query().
		Where(
			finding.StatusEQ("open"),
			finding.Or(finding.WorkLeaseUntilIsNil(), finding.WorkLeaseUntilLTE(now)),
		).
		Order(ent.Asc(finding.FieldFirstSeen)).
		Limit(200).
		All(ctx)
	if err != nil || len(openFindings) == 0 {
		return err
	}
	dispatches := 0
	limit := r.maxHostDispatches()
	for _, f := range openFindings {
		for _, rule := range rules {
			if dispatches >= limit {
				return nil
			}
			// 刷新规矩快照：前一待办可能刚触发连续出错降级
			latest, err := r.DB.StandingRule.Get(ctx, rule.ID)
			if err != nil || !latest.Enabled {
				continue
			}
			if !MatchFinding(latest, f) {
				continue
			}
			already, err := r.alreadyHandled(ctx, latest.ID, f, r.now())
			if err != nil || already {
				continue
			}
			a, err := r.DB.Asset.Get(ctx, f.AssetID)
			if err != nil || a.RetiredAt != nil || a.GroupID == nil || *a.GroupID != f.GroupID || a.Os == nil || !strings.EqualFold(*a.Os, "linux") {
				continue
			}
			usedHost, err := r.dispatch(ctx, latest, f, a)
			if usedHost {
				dispatches++
			}
			if err != nil && ctx.Err() != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Runner) alreadyHandled(ctx context.Context, ruleID uuid.UUID, f *ent.Finding, now time.Time) (bool, error) {
	runs, err := r.DB.StandingRuleRun.Query().
		Where(standingrulerun.RuleIDEQ(ruleID), standingrulerun.FindingIDEQ(f.ID)).
		Order(ent.Desc(standingrulerun.FieldCreatedAt)).
		Limit(10).
		All(ctx)
	if err != nil || len(runs) == 0 {
		return false, err
	}
	for _, run := range runs {
		sameRound := run.FindingFirstSeen != nil && run.FindingFirstSeen.Equal(f.FirstSeen)
		if !sameRound {
			continue
		}
		switch run.Status {
		case standingrulerun.StatusSucceeded, standingrulerun.StatusFailed, standingrulerun.StatusPendingApproval, standingrulerun.StatusRejected, standingrulerun.StatusQueuedHuman:
			return true, nil
		case standingrulerun.StatusSkipped:
			runAt := run.CreatedAt
			if run.CompletedAt != nil {
				runAt = *run.CompletedAt
			}
			if now.Sub(runAt) < skipDedupWindow {
				return true, nil
			}
		}
	}
	return false, nil
}

func (r *Runner) dispatch(ctx context.Context, rule *ent.StandingRule, f *ent.Finding, a *ent.Asset) (bool, error) {
	switch rule.Tier {
	case standingrule.TierHuman:
		return false, r.handleHuman(ctx, rule, f, a)
	case standingrule.TierPropose:
		return r.handlePropose(ctx, rule, f, a)
	case standingrule.TierAuto:
		return r.handleAuto(ctx, rule, f, a)
	default:
		return false, nil
	}
}

func (r *Runner) recordSkip(ctx context.Context, rule *ent.StandingRule, f *ent.Finding, a *ent.Asset, tier string, cmdID uuid.UUID, reason string) error {
	now := r.now()
	firstSeen := f.FirstSeen
	q := r.DB.StandingRuleRun.Create().
		SetCreatedAt(now).
		SetRuleID(rule.ID).
		SetGroupID(f.GroupID).
		SetAssetID(a.ID).
		SetFindingID(f.ID).
		SetFindingFirstSeen(firstSeen).
		SetTier(tier).
		SetStatus(standingrulerun.StatusSkipped).
		SetHitSummary(fmt.Sprintf("%s：%s", a.Hostname, f.Title)).
		SetResult(reason).
		SetCompletedAt(now)
	if cmdID != uuid.Nil {
		q.SetCommandID(cmdID)
	}
	_, err := q.Save(ctx)
	return err
}

func (r *Runner) handleHuman(ctx context.Context, rule *ent.StandingRule, f *ent.Finding, a *ent.Asset) error {
	now := r.now()
	ref := Ref(rule.ID)
	tpl, _ := LookupTemplate(rule.ActionTemplate)
	var work findings.Work
	if len(f.Work) > 0 {
		_ = json.Unmarshal(f.Work, &work)
	}
	work.Stage = "blocked"
	work.Blocker = "manual_business_decision"
	summary := fmt.Sprintf("命中常设规矩 [%s] %s，已转入人工队列等待管理员确认", ref, rule.Name)
	work.BlockedReason = summary
	work.BlockerDetail = summary
	if err := r.DB.Finding.UpdateOneID(f.ID).
		SetWorkOwner("human").
		SetWork(findings.EncodeWork(work)).
		Exec(ctx); err != nil {
		return err
	}
	firstSeen := f.FirstSeen
	run, err := r.DB.StandingRuleRun.Create().
		SetRuleID(rule.ID).
		SetGroupID(f.GroupID).
		SetAssetID(a.ID).
		SetFindingID(f.ID).
		SetFindingFirstSeen(firstSeen).
		SetTier("human").
		SetStatus(standingrulerun.StatusQueuedHuman).
		SetHitSummary(fmt.Sprintf("%s：%s", a.Hostname, f.Title)).
		SetResult(summary).
		SetRollback(tpl.RollbackHint).
		SetCompletedAt(now).
		Save(ctx)
	if err != nil {
		return err
	}
	_ = r.DB.StandingRule.UpdateOneID(rule.ID).SetLastRunAt(now).SetLastRunStatus("queued_human").Exec(ctx)
	audit.System(ctx, r.DB, "standing_rule_queued_human", run.ID.String(), fmt.Sprintf("rule=%s host=%s finding=%s", ref, a.Hostname, f.ID))
	if r.Notify != nil {
		_ = r.Notify(ctx, "常设规矩转交人工确认", fmt.Sprintf("规矩：[%s] %s\n主机：%s\n待办：%s\n说明：%s", ref, rule.Name, a.Hostname, f.Title, tpl.RollbackHint), "/control?tab=rules&ref="+ref)
	}
	return nil
}

func (r *Runner) handlePropose(ctx context.Context, rule *ent.StandingRule, f *ent.Finding, a *ent.Asset) (bool, error) {
	if !r.canExec(a) {
		return false, nil
	}
	probeCmd, err := ProbeSpec(rule, f)
	if err != nil {
		return false, r.recordSkip(ctx, rule, f, a, "propose", uuid.Nil, "预探针不可用，暂缓重试："+err.Error())
	}
	if probeCmd == "" {
		return false, nil
	}
	probeRec, err := r.issueAndWait(ctx, a, probeCmd, "standing-rule:"+Ref(rule.ID), 2*time.Minute, nil)
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if err != nil || probeRec == nil || probeRec.Stdout == nil {
		why := "探针无标准输出"
		if err != nil {
			why = err.Error()
		}
		cmdID := uuid.Nil
		if probeRec != nil {
			cmdID = probeRec.ID
		}
		return true, r.recordSkip(ctx, rule, f, a, "propose", cmdID, "预探针未成功，暂缓重试："+why)
	}
	now := r.now()
	plan, err := BuildPlan(rule, f, *probeRec.Stdout, now)
	if err != nil {
		_ = r.recordSkip(ctx, rule, f, a, "propose", probeRec.ID, "动作方案构建失败，暂缓重试："+err.Error())
		return true, err
	}
	firstSeen := f.FirstSeen
	if !plan.Applicable {
		return true, r.recordSkip(ctx, rule, f, a, "propose", probeRec.ID, plan.Summary)
	}
	ref := Ref(rule.ID)
	app, err := r.DB.Approval.Create().
		SetGroupID(f.GroupID).
		SetAssetID(a.ID).
		SetRequestedBy("standing-rule:" + ref).
		SetOrigin(approval.OriginAi).
		SetCmd(plan.Command).
		SetTimeoutMs(300000).
		SetExpiresAt(now.Add(proposalTTL)).
		Save(ctx)
	if err != nil {
		return true, err
	}
	run, err := r.DB.StandingRuleRun.Create().
		SetRuleID(rule.ID).
		SetGroupID(f.GroupID).
		SetAssetID(a.ID).
		SetFindingID(f.ID).
		SetFindingFirstSeen(firstSeen).
		SetTier("propose").
		SetStatus(standingrulerun.StatusPendingApproval).
		SetHitSummary(fmt.Sprintf("%s：%s（%s）", a.Hostname, f.Title, plan.Summary)).
		SetCommand(plan.Command).
		SetApprovalID(app.ID).
		SetResult("已生成提议，等待管理员审批").
		SetRollback(plan.Rollback).
		Save(ctx)
	if err != nil {
		return true, err
	}
	_ = r.DB.StandingRule.UpdateOneID(rule.ID).SetLastRunAt(now).SetLastRunStatus("pending_approval").Exec(ctx)
	audit.System(ctx, r.DB, "standing_rule_proposed", run.ID.String(), fmt.Sprintf("rule=%s approval=%s host=%s", ref, app.ID, a.Hostname))
	notifyFn := r.NotifyApproval
	if notifyFn == nil {
		notifyFn = r.Notify
	}
	if notifyFn != nil {
		_ = notifyFn(ctx, "待批准：常设规矩提议执行", fmt.Sprintf("规矩：[%s] %s\n主机：%s\n摘要：%s\n命令：%s\n回退：%s", ref, rule.Name, a.Hostname, plan.Summary, plan.Command, plan.Rollback), "/approvals")
	}
	return true, nil
}

func (r *Runner) handleAuto(ctx context.Context, rule *ent.StandingRule, f *ent.Finding, a *ent.Asset) (bool, error) {
	tpl, ok := LookupTemplate(rule.ActionTemplate)
	if !ok || !slices.Contains(tpl.AllowedTiers, "auto") {
		return false, nil
	}
	now := r.now()
	inWindow, _, _, err := repairpolicy.WindowBounds(rule.MaintenanceWindow, time.Local, now)
	if err != nil || !inWindow || !r.canExec(a) || r.Repair == nil {
		return false, nil
	}
	// 先做冷却快速检查，冷却期内不下发任何预探针
	if rule.ActionTemplate != TplRestartFailedService {
		if until, err := r.Repair.CooldownUntil(ctx, a.ID, repairpolicy.ReclaimDisk, now); err != nil || until != nil {
			return false, err
		}
	} else if unit := pickConfiguredUnit(rule, f); unit != "" {
		if until, err := r.Repair.CooldownUntil(ctx, a.ID, unit, now); err != nil || until != nil {
			return false, err
		}
	}

	ref := Ref(rule.ID)
	probeCmd, err := ProbeSpec(rule, f)
	if err != nil {
		return false, r.recordSkip(ctx, rule, f, a, "auto", uuid.Nil, "预探针不可用，暂缓重试："+err.Error())
	}
	if probeCmd == "" {
		return false, nil
	}
	probeRec, err := r.issueAndWait(ctx, a, probeCmd, "standing-rule:"+ref, 2*time.Minute, nil)
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if err != nil || probeRec == nil || probeRec.Stdout == nil {
		why := "探针无标准输出"
		if err != nil {
			why = err.Error()
		}
		cmdID := uuid.Nil
		if probeRec != nil {
			cmdID = probeRec.ID
		}
		return true, r.recordSkip(ctx, rule, f, a, "auto", cmdID, "预探针未成功，暂缓重试："+why)
	}
	plan, err := BuildPlan(rule, f, *probeRec.Stdout, r.now())
	if err != nil {
		_ = r.recordSkip(ctx, rule, f, a, "auto", probeRec.ID, "动作方案构建失败，暂缓重试："+err.Error())
		return true, err
	}
	firstSeen := f.FirstSeen
	if !plan.Applicable {
		return true, r.recordSkip(ctx, rule, f, a, "auto", probeRec.ID, plan.Summary)
	}

	beforeProbeID := probeRec.ID
	if plan.Unit == repairpolicy.ReclaimDisk {
		dfRec, err := r.issueAndWait(ctx, a, "df -P "+plan.Mount, "standing-rule:"+ref, time.Minute, nil)
		if err != nil || dfRec == nil {
			return true, r.recordAutoRunFailure(ctx, rule, f, a, plan, uuid.Nil, uuid.Nil, fmt.Errorf("执行前 df -P 探针失败: %v", err))
		}
		beforeProbeID = dfRec.ID
	}

	resID, err := r.Repair.ReserveStanding(ctx, repairpolicy.StandingRequest{
		RuleID:          rule.ID,
		RuleVersion:     rule.UpdatedAt.UTC().Format(time.RFC3339Nano),
		GroupID:         f.GroupID,
		AssetID:         a.ID,
		FindingID:       f.ID,
		Unit:            plan.Unit,
		Command:         plan.Command,
		Mount:           plan.Mount,
		AllowedPaths:    AllowedDiskPaths(rule),
		BeforeProbeID:   beforeProbeID,
		CooldownMinutes: rule.CooldownMinutes,
	})
	if err != nil {
		if strings.Contains(err.Error(), "冷却期") || strings.Contains(err.Error(), "未知写动作") {
			return true, r.recordSkip(ctx, rule, f, a, "auto", beforeProbeID, err.Error())
		}
		return true, r.recordAutoRunFailure(ctx, rule, f, a, plan, uuid.Nil, uuid.Nil, err)
	}

	var issuedID uuid.UUID
	actionRec, execErr := r.issueAndWait(ctx, a, plan.Command, "standing-rule:"+ref, 5*time.Minute, func(c *ent.Command) error {
		issuedID = c.ID
		return r.Repair.BindStandingAction(ctx, a.ID, plan.Unit, resID, c.ID)
	})
	if execErr != nil {
		return true, r.recordAutoRunFailure(ctx, rule, f, a, plan, issuedID, resID, execErr)
	}

	resultText := "动作已执行成功"
	if actionRec.Stdout != nil && strings.TrimSpace(*actionRec.Stdout) != "" {
		resultText = truncateText(strings.TrimSpace(*actionRec.Stdout), 800)
	}
	if plan.Unit == repairpolicy.ReclaimDisk {
		afterRec, err := r.issueAndWait(ctx, a, "df -P "+plan.Mount, "standing-rule:"+ref, time.Minute, nil)
		if err != nil || afterRec == nil {
			return true, r.recordAutoRunFailure(ctx, rule, f, a, plan, actionRec.ID, resID, fmt.Errorf("执行后 df -P 校验探针失败: %v", err))
		}
		preKB, postKB, err := r.Repair.VerifyStandingDisk(ctx, a.ID, resID, afterRec.ID)
		if err != nil {
			return true, r.recordAutoRunFailure(ctx, rule, f, a, plan, actionRec.ID, resID, err)
		}
		resultText = fmt.Sprintf("执行成功并经 df -P (%s) 独立核验：可用空间 %d KB -> %d KB（释放 %d KB）", plan.Mount, preKB, postKB, postKB-preKB)
	} else {
		verifyRec, err := r.issueAndWait(ctx, a, "systemctl show --property=ActiveState -- "+plan.Unit, "standing-rule:"+ref, time.Minute, nil)
		if err != nil || verifyRec == nil || verifyRec.Stdout == nil || strings.TrimSpace(*verifyRec.Stdout) != "ActiveState=active" {
			why := "服务重启后未进入 active 状态"
			if err != nil {
				why += "：" + err.Error()
			}
			return true, r.recordAutoRunFailure(ctx, rule, f, a, plan, actionRec.ID, resID, errors.New(why))
		}
		resultText = fmt.Sprintf("服务 %s 已重启并核实 ActiveState=active", plan.Unit)
	}

	doneAt := r.now()
	run, err := r.DB.StandingRuleRun.Create().
		SetRuleID(rule.ID).
		SetGroupID(f.GroupID).
		SetAssetID(a.ID).
		SetFindingID(f.ID).
		SetFindingFirstSeen(firstSeen).
		SetTier("auto").
		SetStatus(standingrulerun.StatusSucceeded).
		SetHitSummary(fmt.Sprintf("%s：%s（%s）", a.Hostname, f.Title, plan.Summary)).
		SetCommand(plan.Command).
		SetCommandID(actionRec.ID).
		SetReservationID(resID).
		SetResult(resultText).
		SetRollback(plan.Rollback).
		SetCompletedAt(doneAt).
		Save(ctx)
	if err != nil {
		return true, err
	}
	_ = r.DB.StandingRule.UpdateOneID(rule.ID).
		SetConsecutiveFailures(0).
		SetLastRunAt(doneAt).
		SetLastRunStatus("succeeded").
		Exec(ctx)
	_ = r.DB.Finding.UpdateOneID(f.ID).SetWorkNextCheckAt(doneAt).Exec(ctx)
	audit.System(ctx, r.DB, "standing_rule_auto_executed", run.ID.String(), fmt.Sprintf("rule=%s host=%s cmd_id=%s reservation=%s", ref, a.Hostname, actionRec.ID, resID))
	if r.Notify != nil {
		_ = r.Notify(ctx, "常设规矩已自动执行", fmt.Sprintf("规矩：[%s] %s\n主机：%s\n结果：%s\n回退方式：%s", ref, rule.Name, a.Hostname, resultText, plan.Rollback), "/control?tab=rules&ref="+ref)
	}
	return true, nil
}

func (r *Runner) recordAutoRunFailure(ctx context.Context, rule *ent.StandingRule, f *ent.Finding, a *ent.Asset, plan ActionPlan, cmdID, resID uuid.UUID, cause error) error {
	now := r.now()
	firstSeen := f.FirstSeen
	create := r.DB.StandingRuleRun.Create().
		SetRuleID(rule.ID).
		SetGroupID(f.GroupID).
		SetAssetID(a.ID).
		SetFindingID(f.ID).
		SetFindingFirstSeen(firstSeen).
		SetTier("auto").
		SetStatus(standingrulerun.StatusFailed).
		SetHitSummary(fmt.Sprintf("%s：%s（%s）", a.Hostname, f.Title, plan.Summary)).
		SetCommand(plan.Command).
		SetResult(cause.Error()).
		SetRollback(plan.Rollback).
		SetCompletedAt(now)
	if cmdID != uuid.Nil {
		create.SetCommandID(cmdID)
	}
	if resID != uuid.Nil {
		create.SetReservationID(resID)
	}
	run, err := create.Save(ctx)
	if err != nil {
		return err
	}

	current, err := r.DB.StandingRule.Get(ctx, rule.ID)
	if err != nil {
		return err
	}
	failures := current.ConsecutiveFailures + 1
	upd := r.DB.StandingRule.UpdateOneID(rule.ID).
		SetConsecutiveFailures(failures).
		SetLastRunAt(now).
		SetLastRunStatus("failed")
	degraded := false
	if current.Tier == standingrule.TierAuto && failures >= MaxConsecutiveFailures {
		reason := fmt.Sprintf("连续 %d 次自动执行出错，最后错误：%s", failures, truncateText(cause.Error(), 300))
		upd.SetTier(standingrule.TierPropose).
			SetDegradedAt(now).
			SetDegradedReason(reason)
		degraded = true
	}
	if err := upd.Exec(ctx); err != nil {
		return err
	}
	ref := Ref(rule.ID)
	audit.System(ctx, r.DB, "standing_rule_auto_failed", run.ID.String(), fmt.Sprintf("rule=%s host=%s failures=%d err=%s", ref, a.Hostname, failures, cause.Error()))
	if degraded {
		audit.System(ctx, r.DB, "standing_rule_degraded", rule.ID.String(), fmt.Sprintf("rule=%s failures=%d tier=auto->propose reason=%s", ref, failures, cause.Error()))
		if r.Notify != nil {
			_ = r.Notify(ctx, "常设规矩已因连续出错降级为提议", fmt.Sprintf("规矩：[%s] %s\n主机：%s\n错误：%s\n当前已自动降级为 propose（提议），后续命中将等待管理员审批。", ref, rule.Name, a.Hostname, cause.Error()), "/control?tab=rules&ref="+ref)
		}
	}
	return nil
}

func (r *Runner) reconcilePendingApprovals(ctx context.Context) error {
	pendingRuns, err := r.DB.StandingRuleRun.Query().
		Where(standingrulerun.StatusEQ(standingrulerun.StatusPendingApproval), standingrulerun.ApprovalIDNotNil()).
		Order(ent.Asc(standingrulerun.FieldCreatedAt)).
		Limit(100).
		All(ctx)
	if err != nil || len(pendingRuns) == 0 {
		return err
	}
	executed := 0
	maxExecs := r.maxProposalExecs()
	for _, run := range pendingRuns {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		now := r.now()
		app, err := r.DB.Approval.Get(ctx, *run.ApprovalID)
		if err != nil {
			continue
		}
		switch app.Status {
		case approval.StatusPending:
			if !now.Before(app.ExpiresAt) {
				_, _ = r.DB.Approval.Update().Where(approval.IDEQ(app.ID), approval.StatusEQ(approval.StatusPending)).SetStatus(approval.StatusExpired).Save(ctx)
				_ = r.finalizeProposalRun(ctx, run, standingrulerun.StatusExpired, uuid.Nil, "提议审批超时未处理", now)
			}
		case approval.StatusRejected, approval.StatusCancelled:
			who := ""
			if app.DecidedBy != nil {
				who = *app.DecidedBy
			}
			_ = r.finalizeProposalRun(ctx, run, standingrulerun.StatusRejected, uuid.Nil, strings.TrimSpace("管理员拒绝执行 "+who), now)
		case approval.StatusExpired:
			_ = r.finalizeProposalRun(ctx, run, standingrulerun.StatusExpired, uuid.Nil, "提议审批已过期", now)
		case approval.StatusApproved:
			if !now.Before(app.ExpiresAt) {
				_, _ = r.DB.Approval.Update().Where(approval.IDEQ(app.ID), approval.StatusEQ(approval.StatusApproved)).SetStatus(approval.StatusExpired).Save(ctx)
				_ = r.finalizeProposalRun(ctx, run, standingrulerun.StatusExpired, uuid.Nil, "批准已过期，未下发执行", now)
				continue
			}
			a, err := r.DB.Asset.Get(ctx, run.AssetID)
			if err != nil || a.RetiredAt != nil || a.GroupID == nil || *a.GroupID != run.GroupID || a.Os == nil || !strings.EqualFold(*a.Os, "linux") {
				_, _ = r.DB.Approval.Update().Where(approval.IDEQ(app.ID), approval.StatusEQ(approval.StatusApproved)).SetStatus(approval.StatusCancelled).Save(ctx)
				_ = r.finalizeProposalRun(ctx, run, standingrulerun.StatusFailed, uuid.Nil, "目标主机已停用或归组变化，取消下发", now)
				continue
			}
			if executed >= maxExecs {
				continue
			}
			if !r.canExec(a) {
				// 主机暂不在线或响应未开启，保留批准直到上线或审批过期
				continue
			}
			hasPendingWrite, err := r.hasPendingWrite(ctx, a.ID)
			if err != nil || hasPendingWrite {
				continue
			}
			// 原子消费批准：确保多轮或故障切换下绝不重复下发
			n, err := r.DB.Approval.Update().
				Where(approval.IDEQ(app.ID), approval.StatusEQ(approval.StatusApproved), approval.ExpiresAtGT(now)).
				SetStatus(approval.StatusConsumed).
				Save(ctx)
			if err != nil || n != 1 {
				continue
			}
			executed++
			ref := Ref(run.RuleID)
			var issuedID uuid.UUID
			cmdRec, execErr := r.issueAndWait(ctx, a, run.Command, "standing-rule:"+ref, 5*time.Minute, func(c *ent.Command) error {
				issuedID = c.ID
				return nil
			})
			doneAt := r.now()
			who := "admin"
			if app.DecidedBy != nil && *app.DecidedBy != "" {
				who = *app.DecidedBy
			}
			if execErr != nil {
				_ = r.finalizeProposalRun(ctx, run, standingrulerun.StatusFailed, issuedID, fmt.Sprintf("经 %s 批准后执行失败：%s", who, execErr.Error()), doneAt)
				audit.System(ctx, r.DB, "standing_rule_proposal_failed", run.ID.String(), fmt.Sprintf("rule=%s approved_by=%s err=%s", ref, who, execErr.Error()))
				continue
			}
			outSummary := fmt.Sprintf("经 %s 批准并执行完成", who)
			if cmdRec.Stdout != nil && strings.TrimSpace(*cmdRec.Stdout) != "" {
				outSummary += "：" + truncateText(strings.TrimSpace(*cmdRec.Stdout), 600)
			}
			_ = r.finalizeProposalRun(ctx, run, standingrulerun.StatusSucceeded, cmdRec.ID, outSummary, doneAt)
			if run.FindingID != nil {
				_ = r.DB.Finding.UpdateOneID(*run.FindingID).SetWorkNextCheckAt(doneAt).Exec(ctx)
			}
			audit.System(ctx, r.DB, "standing_rule_proposal_executed", run.ID.String(), fmt.Sprintf("rule=%s approved_by=%s cmd_id=%s", ref, who, cmdRec.ID))
		}
	}
	return nil
}

func (r *Runner) finalizeProposalRun(ctx context.Context, run *ent.StandingRuleRun, st standingrulerun.Status, cmdID uuid.UUID, result string, now time.Time) error {
	upd := r.DB.StandingRuleRun.UpdateOneID(run.ID).
		SetStatus(st).
		SetResult(result).
		SetCompletedAt(now)
	if cmdID != uuid.Nil {
		upd.SetCommandID(cmdID)
	}
	if err := upd.Exec(ctx); err != nil {
		return err
	}
	return r.DB.StandingRule.UpdateOneID(run.RuleID).
		SetLastRunAt(now).
		SetLastRunStatus(string(st)).
		Exec(ctx)
}

func (r *Runner) hasPendingWrite(ctx context.Context, assetID uuid.UUID) (bool, error) {
	rows, err := r.DB.Command.Query().
		Where(command.AssetIDEQ(assetID), command.StatusIn("pending", "sent", "unknown")).
		All(ctx)
	if err != nil {
		return false, err
	}
	for _, c := range rows {
		if c.Kind != "exec" || c.Cmd == nil || !commandgate.ReadOnly(*c.Cmd) {
			return true, nil
		}
	}
	return false, nil
}

func (r *Runner) canExec(a *ent.Asset) bool {
	if r.IssueAndWait != nil {
		return true
	}
	if r.Hub == nil || !r.Hub.Enabled || a.AgentID == nil {
		return false
	}
	if a.SilentSince != nil || r.now().Sub(a.LastSeen) > onlineGrace {
		return false
	}
	return r.Hub.Online(*a.AgentID)
}

func (r *Runner) issueAndWait(ctx context.Context, a *ent.Asset, cmd, issuedBy string, timeout time.Duration, onIssued func(*ent.Command) error) (*ent.Command, error) {
	if r.IssueAndWait != nil {
		return r.IssueAndWait(ctx, a, cmd, issuedBy, timeout, onIssued)
	}
	if r.Hub == nil || !r.Hub.Enabled {
		return nil, errors.New("响应能力未启用")
	}
	c, err := r.Hub.IssueExec(ctx, response.Request{
		AssetID:   a.ID,
		Kind:      "exec",
		IssuedBy:  issuedBy,
		Cmd:       &cmd,
		TimeoutMS: uint32(timeout.Milliseconds()),
	})
	if c != nil && onIssued != nil {
		if bindErr := onIssued(c); bindErr != nil && err == nil {
			return c, bindErr
		}
	}
	if err != nil {
		return c, err
	}
	poll := r.pollInterval()
	deadline := time.Now().Add(timeout + 30*time.Second)
	for time.Now().Before(deadline) {
		cur, err := r.DB.Command.Get(ctx, c.ID)
		if err != nil {
			return cur, err
		}
		switch cur.Status {
		case "succeeded":
			if cur.ExitCode != nil && *cur.ExitCode != 0 {
				return cur, fmt.Errorf("退出码 %d", *cur.ExitCode)
			}
			return cur, nil
		case "failed", "unsupported", "unknown":
			detail := cur.Status
			if cur.Detail != nil && *cur.Detail != "" {
				detail += "：" + *cur.Detail
			} else if cur.Stderr != nil && strings.TrimSpace(*cur.Stderr) != "" {
				detail += "：" + truncateText(strings.TrimSpace(*cur.Stderr), 300)
			}
			return cur, errors.New(detail)
		}
		select {
		case <-ctx.Done():
			return cur, ctx.Err()
		case <-time.After(poll):
		}
	}
	return c, errors.New("等待主机指令回执超时")
}

func truncateText(s string, maxRunes int) string {
	rs := []rune(s)
	if len(rs) <= maxRunes {
		return s
	}
	return string(rs[:maxRunes]) + "…"
}
