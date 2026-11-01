package agentchat

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/agentsession"
	"openxdr/server/ent/taskrun"
)

func (s *Service) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 4 * time.Hour
}

func expiry(ctx context.Context) time.Time {
	deadline, _ := ctx.Deadline()
	return deadline.Add(time.Minute)
}

// Recover 清理执行期限已过的会话，不重放命令。各节点可同时运行，状态更新在事务内完成。
// 旧版本无期限的记录先等待一个完整运行上限，避免升级时误伤仍在退出的会话。
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
	// 先更新会话，持有行锁直到关联 TaskRun 完成；并发完成或清理会重新检查状态。
	const reason = "会话执行期限已过，结果未知；未重放命令"
	if err := tx.AgentSession.Update().Where(agentsession.StatusEQ("running"), expired).
		SetStatus("failed").SetError(reason).SetFinishedAt(now).Exec(ctx); err != nil {
		return err
	}
	// 也覆盖会话已收尾、但进程在 TaskRun 回写前退出的窗口。
	runs, err := tx.TaskRun.Query().Where(taskrun.StatusEQ("running"), taskrun.SessionIDNotNil()).All(ctx)
	if err != nil {
		return err
	}
	sessionIDs := make([]uuid.UUID, 0, len(runs))
	for _, run := range runs {
		sessionIDs = append(sessionIDs, *run.SessionID)
	}
	ids, err := tx.AgentSession.Query().Where(agentsession.IDIn(sessionIDs...), agentsession.StatusNEQ("running"),
		agentsession.Or(agentsession.And(agentsession.ErrorEQ(reason), agentsession.FinishedAtEQ(now)), agentsession.FinishedAtLT(now.Add(-time.Minute)))).IDs(ctx)
	if err != nil {
		return err
	}
	if err := tx.TaskRun.Update().Where(taskrun.StatusEQ("running"), taskrun.SessionIDIn(ids...)).
		SetStatus("failed").SetError("会话已结束但任务运行未收尾，结果未知；未重放命令").SetFinishedAt(now).Exec(ctx); err != nil {
		return err
	}
	return tx.Commit()
}
