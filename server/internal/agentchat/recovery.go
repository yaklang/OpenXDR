package agentchat

import (
	"context"
	"log/slog"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/taskrun"
	"openxdr/server/internal/commandgate"
)

const recoveredReadOnlyTask = "任务短租约已过期，仅完成只读调查，可由调度器按窗口安全重跑"
const expiredSessionReason = "会话执行期限已过，结果未知；未重放命令"

func (s *Service) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 4 * time.Hour
}

// Recover 清理过期会话；只有新协议证明无副作用且未到硬期限的任务可交回调度器。
// 旧版本无期限的记录先等待一个完整运行上限。
func (s *Service) Recover(ctx context.Context) {
	started := time.Now()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		now := time.Now()
		legacy := time.Time{}
		if now.After(started.Add(s.timeout() + time.Minute)) {
			legacy = started
		}
		if err := s.recoverExpired(ctx, now, legacy); err != nil && ctx.Err() == nil {
			slog.Error("恢复过期会话失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func replayableTask(session *ent.AgentSession, now time.Time) bool {
	return session.Kind == "task" && session.Initiator == commandgate.SystemActor &&
		session.RunReplaySafe && session.CancelRequestedAt == nil && session.RunDeadlineAt != nil && now.Before(*session.RunDeadlineAt)
}

func (s *Service) recoverExpired(ctx context.Context, now, legacy time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	expired := agentsession.RunExpiresAtLTE(now)
	if !legacy.IsZero() {
		expired = agentsession.Or(expired, agentsession.And(agentsession.RunExpiresAtIsNil(), agentsession.CreatedAtLT(legacy)))
	}
	// 锁定后复查过期条件，不能抢走另一节点刚续期的任务。
	sessions, err := tx.AgentSession.Query().Where(agentsession.StatusEQ("running"), expired).
		Where(func(sel *sql.Selector) { sel.ForUpdate(sql.WithLockAction(sql.SkipLocked)) }).Limit(100).All(ctx)
	if err != nil {
		return err
	}
	recovered := map[uuid.UUID]bool{}
	for _, session := range sessions {
		safe := replayableTask(session, now)
		reason := expiredSessionReason
		if safe {
			reason = recoveredReadOnlyTask
		}
		if err := tx.AgentSession.UpdateOneID(session.ID).SetStatus("failed").SetError(reason).SetFinishedAt(now).ClearRunExpiresAt().Exec(ctx); err != nil {
			return err
		}
		recovered[session.ID] = true
	}
	// 覆盖会话终态已落库、进程却没来得及回写 TaskRun 的窗口。
	runs, err := tx.TaskRun.Query().Where(taskrun.StatusEQ("running"), taskrun.SessionIDNotNil()).Limit(1000).All(ctx)
	if err != nil {
		return err
	}
	for _, run := range runs {
		session, err := tx.AgentSession.Get(ctx, *run.SessionID)
		if err != nil {
			return err
		}
		if session.Status == "running" {
			continue
		}
		if !recovered[session.ID] && (session.FinishedAt == nil || !session.FinishedAt.Before(now.Add(-time.Minute))) {
			continue
		}
		status, reason := "failed", "会话已结束但任务运行未收尾，结果未知；未重放命令"
		if session.Error != nil && *session.Error == recoveredReadOnlyTask && replayableTask(session, now) && session.GroupID == run.GroupID {
			status, reason = "interrupted", recoveredReadOnlyTask
		}
		if err := tx.TaskRun.UpdateOneID(run.ID).Where(taskrun.StatusEQ("running"), taskrun.SessionIDEQ(session.ID)).
			SetStatus(status).SetError(reason).SetFinishedAt(now).Exec(ctx); err != nil {
			return err
		}
	}
	return tx.Commit()
}
