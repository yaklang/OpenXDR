package agentchat

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/schedule"
)

const taskLeaseTTL = schedule.TaskLeaseWindow
const taskHeartbeat = time.Minute

var errTaskLeaseLost = errors.New("任务执行租约已失效，旧执行者停止调用工具")

type taskOwnerKey struct{}

func leaseEnd(now, deadline time.Time) time.Time {
	end := now.Add(taskLeaseTTL)
	if deadline.Before(end) {
		return deadline
	}
	return end
}

// 只有受信任务入口能签发所有者；重跑使用新会话，旧所有者永不重新启用。
func (s *Service) startTaskLease(ctx context.Context, session *ent.AgentSession) (context.Context, uuid.UUID, func(), error) {
	owner := uuid.New()
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, uuid.Nil, nil, errors.New("任务缺少固定执行期限")
	}
	deadline = deadline.Add(time.Minute)
	if session.RunDeadlineAt != nil && session.RunDeadlineAt.Before(deadline) {
		deadline = *session.RunDeadlineAt
	}
	now := time.Now()
	if !deadline.After(now) {
		return nil, uuid.Nil, nil, errTaskLeaseLost
	}
	n, err := s.DB.AgentSession.Update().Where(agentsession.IDEQ(session.ID), agentsession.GroupIDEQ(session.GroupID), agentsession.KindEQ("task"),
		agentsession.InitiatorEQ(commandgate.SystemActor), agentsession.StatusEQ("running"), agentsession.RunOwnerIsNil(), agentsession.CancelRequestedAtIsNil()).
		SetRunOwner(owner).SetRunDeadlineAt(deadline).SetRunExpiresAt(leaseEnd(now, deadline)).SetRunReplaySafe(true).Save(ctx)
	if err != nil {
		return nil, uuid.Nil, nil, err
	}
	if n != 1 {
		return nil, uuid.Nil, nil, errTaskLeaseLost
	}
	work, cancel := context.WithCancel(context.WithValue(ctx, taskOwnerKey{}, owner))
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(taskHeartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-work.Done():
				return
			case now := <-ticker.C:
				renew, done := context.WithTimeout(work, 10*time.Second)
				err := s.renewTaskLease(renew, session.ID, owner, now, deadline)
				done()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()
	return work, owner, func() { cancel(); <-done }, nil
}

func (s *Service) renewTaskLease(ctx context.Context, id, owner uuid.UUID, now, deadline time.Time) error {
	session, err := s.DB.AgentSession.Get(ctx, id)
	if err != nil {
		return err
	}
	if session.RunDeadlineAt == nil {
		return errTaskLeaseLost
	}
	if session.RunDeadlineAt.Before(deadline) {
		deadline = *session.RunDeadlineAt
	}
	n, err := s.DB.AgentSession.Update().Where(agentsession.IDEQ(id), agentsession.StatusEQ("running"),
		agentsession.RunOwnerEQ(owner), agentsession.RunExpiresAtGT(now), agentsession.RunDeadlineAtGT(now),
		agentsession.RunDeadlineAtEQ(*session.RunDeadlineAt), agentsession.CancelRequestedAtIsNil()).
		SetRunExpiresAt(leaseEnd(now, deadline)).Save(ctx)
	if err != nil {
		return err
	}
	if n != 1 {
		return errTaskLeaseLost
	}
	return nil
}

// 先持久化可能的副作用，再调用工具；消息或回执尚未写入时崩溃也不会被误判为纯读。
func (s *Service) guardTool(ctx context.Context, prior *ent.AgentSession, name string) (*ent.AgentSession, error) {
	current, err := s.DB.AgentSession.Get(ctx, prior.ID)
	if err != nil {
		return nil, err
	}
	if current.Status != "running" || current.CancelRequestedAt != nil || current.GroupID != prior.GroupID || current.Initiator != prior.Initiator {
		return nil, errTaskLeaseLost
	}
	if current.Kind != "task" {
		return current, nil
	}
	if current.RunOwner == nil {
		if current.RunReplaySafe {
			return nil, errTaskLeaseLost
		}
		return current, nil
	}
	owner, ok := ctx.Value(taskOwnerKey{}).(uuid.UUID)
	now := time.Now()
	if !ok || owner != *current.RunOwner || current.RunExpiresAt == nil || !current.RunExpiresAt.After(now) ||
		current.RunDeadlineAt == nil || !current.RunDeadlineAt.After(now) {
		return nil, errTaskLeaseLost
	}
	if replaySafeTool(name) {
		return current, nil
	}
	n, err := s.DB.AgentSession.Update().Where(agentsession.IDEQ(current.ID), agentsession.StatusEQ("running"),
		agentsession.RunOwnerEQ(owner), agentsession.RunExpiresAtGT(now), agentsession.CancelRequestedAtIsNil()).SetRunReplaySafe(false).Save(ctx)
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, errTaskLeaseLost
	}
	current.RunReplaySafe = false
	return current, nil
}

func replaySafeTool(name string) bool {
	switch name {
	case "query", "command_status", "memories":
		return true
	default:
		return false
	}
}
