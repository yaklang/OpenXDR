package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/command"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/taskrun"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/findings"
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
	bound, err := s.isFindingFollowup(ctx, session)
	if err != nil || !bound {
		return err
	}

	rows, err := s.DB.Finding.Query().Where(finding.WorkSessionIDEQ(session.ID), finding.StatusEQ("open"), finding.GroupIDEQ(session.GroupID), finding.WorkLeaseUntilGT(time.Now())).All(ctx)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return errors.New("本轮已无有效领取的待办，禁止继续执行")
	}
	allowed := false
	var target *ent.Finding
	for _, f := range rows {
		if f.AssetID == host {
			allowed = true
			target = f
			if f.WorkAttempts > findings.RepairBudget && !commandgate.ReadOnly(cmd) {
				return errors.New("主动修复预算已用尽，本轮只允许只读观察")
			}
		}
	}
	if !allowed {
		return errors.New("自主待办会话只能操作本轮领取的主机")
	}
	if commandgate.ReadOnly(cmd) {
		return nil
	}
	// 无法确认归属到某次待办的旧写操作也不能冒险重放；先只读查清或由人确认。
	unknown, err := s.DB.Command.Query().Where(command.AssetIDEQ(host), command.StatusIn("pending", "sent", "unknown")).All(ctx)
	if err != nil {
		return err
	}
	for _, c := range unknown {
		if c.Kind != "exec" || c.Cmd == nil || !commandgate.ReadOnly(*c.Cmd) {
			return errors.New("主机存在未确认的写操作，禁止自动新增修复指令；先查回执与只读效果")
		}
	}
	if s.AuthorizeFindingRepair == nil {
		return errors.New("未配置明确的自主修复维护范围，本任务只读跟进；不能自行重启生产服务、删除数据、安装补丁或修改 HA/数据库/安全采集/网络")
	}
	return s.AuthorizeFindingRepair(ctx, session, target, cmd)
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
	for _, id := range ids {
		c, err := s.DB.Command.Query().Where(command.IDEQ(id), command.AssetIDEQ(f.AssetID), command.CreatedAtGTE(session.CreatedAt)).Only(ctx)
		if err != nil {
			return errors.New("复查指令不存在、早于本轮或不属该主机")
		}
		if c.Kind != "exec" || c.Cmd == nil || !commandgate.ReadOnly(*c.Cmd) {
			return errors.New("须引用独立只读复查，不能用修复动作成功代替效果验证")
		}
		if resolved {
			if c.Status != "succeeded" || c.ExitCode == nil || *c.ExitCode != 0 || c.CompletedAt == nil || c.Truncated || c.Stdout == nil || strings.TrimSpace(*c.Stdout) == "" {
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
			if c.Status != "failed" && c.Status != "unsupported" {
				return errors.New("人工阻塞须有真实失败或不支持回执，不能仅因缺证交人")
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
	return nil
}

func (s *Service) saveFindingPlan(ctx context.Context, session *ent.AgentSession, f *ent.Finding, plan, blocker string, ids []uuid.UUID) error {
	if plan == "" {
		plan = "按计划只读复查；新证据唤醒，未知回执不重放"
	}
	if len(plan) > 1000 {
		return errors.New("next_step 不能超过 1000 字节")
	}
	owner, stage := "ai", "waiting"
	var prior findings.Work
	_ = json.Unmarshal(f.Work, &prior)
	if blocker == "" && f.WorkOwner == "human" {
		if len(ids) == 0 {
			owner, stage, blocker, ids = "human", "blocked", prior.Blocker, prior.EvidenceCommands
		} else if err := s.findingEvidence(ctx, session, f, ids, true, ""); err != nil {
			return err
		}
	}

	if blocker != "" && owner != "human" {
		if blocker != "permission" && blocker != "unsupported" {
			return errors.New("blocker 仅支持 permission / unsupported")
		}
		if err := s.findingEvidence(ctx, session, f, ids, false, blocker); err != nil {
			return err
		}
		owner, stage = "human", "blocked"
	}
	next := time.Now().Add(time.Hour)
	if f.WorkAttempts >= findings.RepairBudget {
		next = time.Now().Add(24 * time.Hour)
		stage = "monitoring"
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
	w := findings.Work{OriginalTitle: prior.OriginalTitle, OriginalProblem: prior.OriginalProblem, Stage: stage, Plan: plan, WakeOn: "new_observation_or_next_check", Blocker: blocker, EvidenceCommands: ids}
	_, err := s.DB.Finding.Update().Where(finding.IDEQ(f.ID), finding.GroupIDEQ(session.GroupID), finding.StatusEQ("open")).SetWorkOwner(owner).SetWorkNextCheckAt(next).SetWork(findings.EncodeWork(w)).Save(ctx)
	return err
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
