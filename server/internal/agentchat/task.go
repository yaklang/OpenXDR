package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/report"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/schedule"
)

var _ schedule.Runner = (*Service)(nil)

// RunTask 以系统身份跑一次定时任务会话，实现 schedule.Runner。会话由调度器建好；
// 这里只认 kind=task、initiator=system 且仍在 running 的会话。
// 轮数耗尽时先续一次只带 report 的收尾；截断、收尾后仍未结束或没交报告都算失败：
// 巡检不完整不能当成"一切正常"。唯一的例外是运行期限到了：模型交了报告就算完成（期限只截掉了交报告之后的那一轮），
// 没交报告就由平台整理一份保底报告（level attention），会话 error 记 PartialNote，照常推送，不当成没有结果。
func (s *Service) RunTask(ctx context.Context, job schedule.Job) (retErr error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	session := job.Session
	partial := false
	if session.Kind != "task" || session.Initiator != commandgate.SystemActor || session.Status != "running" {
		return errors.New("不是待运行的任务会话")
	}
	ctx, owner, stopLease, err := s.startTaskLease(ctx, session)
	if err != nil {
		return err
	}
	defer func() {
		stopLease()
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		update := s.DB.AgentSession.Update().Where(agentsession.IDEQ(session.ID), agentsession.StatusEQ("running"), agentsession.RunOwnerEQ(owner)).ClearRunExpiresAt().SetStatus("succeeded").SetFinishedAt(time.Now())
		if partial {
			update.SetError(PartialNote)
		}
		if retErr != nil {
			update.SetStatus("failed").SetError(retErr.Error())
		}
		n, err := update.Save(finish)
		if err != nil && retErr == nil {
			retErr = fmt.Errorf("保存会话终态失败: %w", err)
		} else if n != 1 && retErr == nil {
			retErr = errTaskLeaseLost
		}
	}()
	if err := s.checkBudget(ctx, session.GroupID); err != nil {
		return err
	}
	request, err := s.request(ctx, session, job.Prompt, nil)
	if err != nil {
		return err
	}
	seq := 0
	who := commandgate.Request{System: true, ApprovalTimeout: job.ApprovalTimeout}
	handle := func(ctx context.Context, name string, args json.RawMessage) (string, error) {
		// 每次调用重读会话，避免用拉起时的旧快照判权
		current, err := s.DB.AgentSession.Get(ctx, session.ID)
		if err != nil {
			return "", err
		}
		return s.tool(ctx, current, who, name, args)
	}
	record := s.recorder(session, &seq, nil)
	// 轮数或时间耗尽先收尾一次，收尾仍没正常结束或没交报告才算失败
	result, runErr := s.investigate(ctx, session, request, handle, record, &seq)
	// 只有运行期限到了才出保底报告；停机、失去租约（取消）由调度器记 interrupted 重跑，其余错误照常失败
	expired := runErr != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)
	if runErr != nil && !expired {
		return runErr
	}
	// 期限已过，查报告与写保底报告用独立的短时限
	post, done := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer done()
	n, err := s.DB.Report.Query().Where(report.SessionIDEQ(session.ID)).Count(post)
	if err != nil {
		return err
	}
	if expired {
		if n > 0 {
			return nil
		}
		if _, err := s.guardTool(post, session, "report"); err != nil {
			return err
		}
		if err := s.fallbackReport(post, session, job.Prompt); err != nil {
			return fmt.Errorf("%w；保底报告生成失败: %v", runErr, err)
		}
		partial = true
		return nil
	}
	// 收尾就是为了交报告：报告交上了、只是收尾的轮数在最后一句话前用完，不算失败，否则会白白整轮重跑
	if result.StopReason != "stop" && (result.StopReason != "max_turns" || n == 0) {
		return fmt.Errorf("会话未完整结束：%s", result.StopReason)
	}
	if n == 0 {
		return errors.New("会话结束但没有提交报告")
	}
	return nil
}
