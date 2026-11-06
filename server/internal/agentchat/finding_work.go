package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/command"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/taskrun"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/repaircmd"
)

// prepareFindingWork 只认真实调度记录，不以可修改的标题或模型参数识别任务身份。
func (s *Service) prepareFindingWork(ctx context.Context, session *ent.AgentSession) (bool, bool, error) {
	bound, err := s.DB.TaskRun.Query().Where(taskrun.TaskIDEQ(findings.FollowupTask), taskrun.SessionIDEQ(session.ID), taskrun.GroupIDEQ(session.GroupID), taskrun.StatusEQ("running")).Exist(ctx)
	if err != nil || !bound {
		return false, false, err
	}
	rows, err := findings.Claim(ctx, s.DB, session, time.Now())
	if err != nil {
		return true, false, err
	}
	subjects := make([]string, 0, len(rows))
	for _, f := range rows {
		subjects = append(subjects, "finding:"+f.ID.String())
	}
	if len(subjects) == 0 {
		return true, false, nil
	}
	n, err := s.DB.AgentSession.Update().Where(agentsession.IDEQ(session.ID), agentsession.StatusEQ("running"), agentsession.CancelRequestedAtIsNil()).SetSubjects(subjects).Save(ctx)
	if err != nil {
		return true, false, err
	}
	if n != 1 {
		return true, false, errTaskLeaseLost
	}
	session.Subjects = subjects
	return true, true, nil
}

// guardFindingExec 不扩大组授权；预算耗尽只允许只读命令，历史未知动作未澄清前禁止新增写操作。
func (s *Service) isFindingFollowup(ctx context.Context, session *ent.AgentSession) (bool, error) {
	return s.DB.TaskRun.Query().Where(taskrun.TaskIDEQ(findings.FollowupTask), taskrun.SessionIDEQ(session.ID), taskrun.GroupIDEQ(session.GroupID), taskrun.StatusEQ("running")).Exist(ctx)
}

func (s *Service) guardFindingExec(ctx context.Context, session *ent.AgentSession, host uuid.UUID, cmd string) error {
	_, err := s.findingExecTarget(ctx, session, host, cmd)
	return err
}

func (s *Service) findingExecTarget(ctx context.Context, session *ent.AgentSession, host uuid.UUID, cmd string, requested ...uuid.UUID) (*ent.Finding, error) {
	bound, err := s.isFindingFollowup(ctx, session)
	if err != nil || !bound {
		return nil, err
	}

	rows, err := s.DB.Finding.Query().Where(finding.WorkSessionIDEQ(session.ID), finding.StatusEQ("open"), finding.GroupIDEQ(session.GroupID), finding.WorkLeaseUntilGT(time.Now())).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("本轮已无有效领取的待办，禁止继续执行")
	}
	readOnly := commandgate.ReadOnly(cmd)
	selected := uuid.Nil
	if len(requested) > 0 {
		selected = requested[0]
	}
	allowed := false
	var target *ent.Finding
	for _, f := range rows {
		if f.AssetID == host && (selected == uuid.Nil || f.ID == selected) {
			allowed = true
			if !readOnly && f.WorkOwner != "ai" {
				return nil, errors.New("人工决策阻塞中的待办仅允许自动只读复查")
			}
			if !readOnly && target != nil {
				return nil, errors.New("同主机有多个领取的待办，写动作必须指定 finding_id")
			}
			target = f
			var work findings.Work
			if err := json.Unmarshal(f.Work, &work); err != nil && len(f.Work) > 0 {
				return nil, errors.New("待办计划损坏，拒绝自动修复")
			}
			if work.RepairAttempts >= findings.RepairBudget && !readOnly {
				return nil, errors.New("主动修复预算已用尽，本轮只允许只读观察")
			}
		}
	}
	if !allowed {
		return nil, errors.New("自主待办会话只能操作本轮领取的主机")
	}
	if readOnly {
		return nil, nil
	}
	_, reclaim := repaircmd.Parse(cmd)
	if !findingRestart.MatchString(cmd) && !reclaim {
		err := errors.New("自治跟进只允许只读命令：这条命令没有被认定为只读（含命令替换、cd、docker exec 等写入或无法确定的片段）。请拆成单条简单的只读命令；写操作只允许已授权的 systemctl restart -- <服务>、docker image prune -f、docker builder prune -f、apt-get clean 或 find -- <授权目录> -xdev -type f -mtime +<7..3650> -delete。")
		logCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if auditErr := audit.Checked(logCtx, s.DB.AuditLog.Create(), "system", "server", "repair_action_denied", session.ID.String(), err.Error()); auditErr != nil {
			return nil, fmt.Errorf("%w；拒绝审计落库失败", err)
		}
		return nil, err
	}
	// 无法确认归属到某次待办的旧写操作也不能冒险重放；先只读查清或由人确认。
	unknown, err := s.DB.Command.Query().Where(command.AssetIDEQ(host), command.StatusIn("pending", "sent", "unknown")).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range unknown {
		if c.Kind != "exec" || c.Cmd == nil || !commandgate.ReadOnly(*c.Cmd) {
			return nil, errors.New("主机存在未确认的写操作，禁止自动新增修复指令；先查回执与只读效果")
		}
	}
	if s.AuthorizeFindingRepair == nil || s.RevalidateFindingRepair == nil {
		return nil, errors.New("未配置明确的自主修复维护范围，本任务只读跟进；不能自行重启生产服务、删除数据、安装补丁或修改 HA/数据库/安全采集/网络")
	}
	if reclaim && (s.RecordFindingProbe == nil || s.VerifyFindingRepair == nil) {
		return nil, errors.New("未配置磁盘回收指令关联与独立效果验证，本任务仅允许只读跟进")
	}
	if err := s.AuthorizeFindingRepair(ctx, session, target, cmd); err != nil {
		return nil, err
	}
	return target, nil
}

// findingEvidence 以新鲜、同资产的真实只读回执支撑复查，不接受单凭执行成功宣称问题已解决。
func (s *Service) findingEvidence(ctx context.Context, session *ent.AgentSession, f *ent.Finding, ids []uuid.UUID, resolved bool, blocker string) error {
	if len(ids) == 0 || len(ids) > 5 {
		return errors.New("复查修复或人工阻塞必须关联 1–5 条本轮真实复查指令")
	}
	current, err := s.DB.Asset.Query().Where(asset.IDEQ(f.AssetID), asset.GroupIDEQ(session.GroupID)).Exist(ctx)
	if err != nil {
		return err
	}
	if !current {
		return errors.New("主机已移出本组")
	}
	if resolved {
		pending, err := s.DB.Command.Query().Where(command.AssetIDEQ(f.AssetID), command.StatusIn("pending", "sent", "unknown")).All(ctx)
		if err != nil {
			return err
		}
		for _, c := range pending {
			if c.Kind != "exec" || c.Cmd == nil || !commandgate.ReadOnly(*c.Cmd) {
				return errors.New("存在未确认写操作，不能宣称已修复")
			}
		}
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range ids {
		if seen[id] || id == uuid.Nil {
			return errors.New("复查指令ID为空或重复")
		}
		seen[id] = true
		c, err := s.DB.Command.Query().Where(command.IDEQ(id), command.AssetIDEQ(f.AssetID), command.CreatedAtGTE(session.CreatedAt)).Only(ctx)
		if err != nil {
			return errors.New("复查指令不存在、早于本轮或不属该主机")
		}
		if c.Kind != "exec" || c.Cmd == nil || !commandgate.ReadOnly(*c.Cmd) {
			return errors.New("须引用独立只读复查，不能用修复动作成功代替效果验证")
		}
		if resolved {
			if c.Status != "succeeded" || c.ExitCode == nil || *c.ExitCode != 0 || c.CompletedAt == nil || c.CompletedAt.Before(time.Now().Add(-10*time.Minute)) || c.CompletedAt.After(time.Now()) || c.CreatedAt.After(*c.CompletedAt) || c.Truncated || c.Stdout == nil || strings.TrimSpace(*c.Stdout) == "" {
				return errors.New("复查须成功返回非空且未截断的证据；空日志或未知回执不能证明已修复")
			}
			later, err := s.DB.Command.Query().Where(command.AssetIDEQ(f.AssetID), command.CreatedAtGTE(*c.CompletedAt)).All(ctx)
			if err != nil {
				return err
			}
			for _, action := range later {
				if action.Kind != "exec" || action.Cmd == nil || !commandgate.ReadOnly(*action.Cmd) {
					return errors.New("复查后发生了新写操作，必须重新独立验证")
				}
			}
		} else {
			if blocker != "permission" && blocker != "unsupported" {
				if c.Status != "succeeded" || c.ExitCode == nil || *c.ExitCode != 0 || c.CompletedAt == nil || c.CompletedAt.Before(time.Now().Add(-10*time.Minute)) || c.Truncated || c.Stdout == nil || strings.TrimSpace(*c.Stdout) == "" {
					return errors.New("阻塞条件须引用新鲜完整且有输出的只读探针")
				}
				words := strings.Fields(*c.Cmd)
				if len(words) == 0 {
					return errors.New("阻塞证据命令为空")
				}
				switch filepath.Base(words[0]) {
				case "date", "hostname", "uname", "echo", "printf", "true", "pwd", "whoami", "id":
					return errors.New("主机基本信息不足以证明需业务决策或维护窗口")
				}
				continue
			}
			if c.Status != "failed" && c.Status != "unsupported" {
				return errors.New("权限或能力阻塞须有真实失败或不支持回执")
			}
			detail := ""
			if c.Detail != nil {
				detail += *c.Detail
			}
			if c.Stderr != nil {
				detail += " " + *c.Stderr
			}
			if blocker == "permission" && !strings.Contains(strings.ToLower(detail), "permission denied") && !strings.Contains(strings.ToLower(detail), "operation not permitted") {
				return errors.New("回执未证明权限阻塞")
			}
			if blocker == "unsupported" && c.Status != "unsupported" {
				return errors.New("回执未证明端点能力不支持")
			}
		}
	}
	if resolved && s.VerifyFindingRepair != nil {
		return s.VerifyFindingRepair(ctx, session, f, ids)
	}
	return nil
}

func (s *Service) saveFindingPlan(ctx context.Context, session *ent.AgentSession, f *ent.Finding, plan, blocker string, ids []uuid.UUID) error {
	if len(ids) > 5 {
		return errors.New("最多关联五条本轮证据指令")
	}
	if len(plan) > 1000 {
		return errors.New("next_step 不能超过 1000 字节")
	}
	owner, stage := f.WorkOwner, "waiting"
	if owner == "" {
		owner = "ai"
	}
	var prior findings.Work
	if err := json.Unmarshal(f.Work, &prior); err != nil && len(f.Work) > 0 {
		return err
	}
	if plan == "" {
		plan = prior.Plan
		if plan == "" {
			plan = "按计划只读复查；新证据唤醒，未知回执不重放"
		}
	}
	if blocker != "" {
		switch blocker {
		case "policy_required":
			if s.FindingRepairAvailable == nil {
				return errors.New("未配置可信维护范围查询，不能宣称缺授权")
			}
			available, err := s.FindingRepairAvailable(ctx, session, f)
			if err != nil {
				return err
			}
			if available {
				return errors.New("资产已有维护范围，须核对具体动作，不能笼统记为缺授权")
			}
		case "permission", "unsupported", "maintenance_window_required", "manual_business_decision", "legacy_decommission_confirm", "external_dependency":
			if err := s.findingEvidence(ctx, session, f, ids, false, blocker); err != nil {
				return err
			}
		default:
			return errors.New("不支持的结构化阻塞原因")
		}
		if blocker == "permission" || blocker == "unsupported" {
			owner = "human"
		} else {
			owner = "ai"
		}
	} else {
		// 未显式提交新的阻塞结论时保留旧原因；成功复核结案另走独立路径。
		blocker = prior.Blocker
	}
	if len(ids) > 0 {
		prior.EvidenceCommands = ids
		now := time.Now()
		prior.EvidenceAt, prior.EvidenceStale = &now, false
	}
	next := time.Now().Add(time.Hour)
	if f.WorkAttempts >= 3 || prior.RepairAttempts >= findings.RepairBudget {
		next = time.Now().Add(24 * time.Hour)
		stage = "monitoring"
	}
	if f.Severity == "high" && prior.EscalatedAt == nil {
		next = time.Now().Add(time.Hour)
	}
	if blocker != "" {
		stage = "blocked"
	}
	if prior.OriginalTitle == "" {
		prior.OriginalTitle = f.Title
	}
	if prior.OriginalProblem == "" {
		prior.OriginalProblem = f.Detail
	}
	prior.Version = 2
	prior.Plan, prior.Blocker, prior.Stage = plan, blocker, stage
	prior.WakeOn = "new_observation_or_next_check"
	complete, err := s.findingReferences(ctx, session, f, ids)
	if err != nil {
		return err
	}
	escalated := false
	if complete {
		escalated, err = s.updateFindingRisk(ctx, session, f, &prior, ids)
		if err != nil {
			return err
		}
	}
	if prior.RiskSince != nil && prior.EscalatedAt == nil {
		next = time.Now().Add(15 * time.Minute)
	}
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := tx.Asset.Query().Where(asset.IDEQ(f.AssetID), asset.GroupIDEQ(session.GroupID)).Exist(ctx)
	if err != nil {
		return err
	}
	if !current {
		return errors.New("待办主机已转组")
	}
	n, err := tx.Finding.Update().Where(finding.IDEQ(f.ID), finding.GroupIDEQ(session.GroupID), finding.StatusEQ("open"), findings.Snapshot(f)).SetWorkOwner(owner).SetWorkNextCheckAt(next).SetWork(findings.EncodeWork(prior)).Save(ctx)
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("待办计划或修复预留已变化，请重新读取后跟进")
	}
	if escalated {
		if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "finding_risk_escalated", f.ID.String(), "risk="+prior.RiskKind+" session="+session.ID.String()+" evidence="+fmt.Sprint(ids)); err != nil {
			return err
		}
	}
	if old := readFindingWork(f); old.EscalatedAt != nil && prior.EscalatedAt == nil {
		if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "finding_risk_recovered", f.ID.String(), "独立只读探针确认当前资源风险恢复，session="+session.ID.String()+" evidence="+fmt.Sprint(ids)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// 未结案计划可以保存失败或未知回执作为后续调查线索，不能把这些引用当作恢复证明。
func (s *Service) findingReferences(ctx context.Context, session *ent.AgentSession, f *ent.Finding, ids []uuid.UUID) (bool, error) {
	complete := len(ids) > 0
	seen := map[uuid.UUID]bool{}
	for _, id := range ids {
		if id == uuid.Nil || seen[id] {
			return false, errors.New("线索指令ID为空或重复")
		}
		seen[id] = true
		c, err := s.DB.Command.Query().Where(command.IDEQ(id), command.AssetIDEQ(f.AssetID), command.CreatedAtGTE(session.CreatedAt)).Only(ctx)
		if err != nil {
			return false, errors.New("线索指令不属本轮当前资产")
		}
		if c.CreatedAt.After(time.Now()) {
			return false, errors.New("线索指令时间无效")
		}
		if c.Kind != "exec" || c.Cmd == nil || !commandgate.ReadOnly(*c.Cmd) || c.Status != "succeeded" || c.ExitCode == nil || *c.ExitCode != 0 || c.CompletedAt == nil || c.Truncated {
			complete = false
		}
	}
	return complete, nil
}

func findingWorkJSON(f *ent.Finding) any { var w any; _ = json.Unmarshal(f.Work, &w); return w }

func originalTitle(f *ent.Finding) string {
	var w findings.Work
	_ = json.Unmarshal(f.Work, &w)
	if w.OriginalTitle != "" {
		return w.OriginalTitle
	}
	return f.Title
}
func originalProblem(f *ent.Finding) string {
	var w findings.Work
	_ = json.Unmarshal(f.Work, &w)
	if w.OriginalProblem != "" {
		return w.OriginalProblem
	}
	return f.Detail
}

var findingRestart = regexp.MustCompile(`^systemctl restart -- ([a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}\.service)$`)
