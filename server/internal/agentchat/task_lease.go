package agentchat

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/agentsession"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/schedule"
)

const taskLeaseTTL = schedule.TaskLeaseWindow
const taskHeartbeat = time.Minute
const taskRenewTimeout = 10 * time.Second
const taskLeaseReserve = 15 * time.Second

var errTaskLeaseLost = errors.New("任务执行租约已失效，旧执行者停止调用工具")

type taskOwnerKey struct{}

func leaseEnd(now, deadline time.Time) time.Time {
	end := now.Add(taskLeaseTTL)
	if deadline.Before(end) {
		end = deadline
	}
	return end.UTC().Truncate(time.Microsecond)
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
	confirmed := taskLeaseConfirmation{expires: leaseEnd(now, deadline)}
	if !confirmed.expires.After(time.Now().Add(taskLeaseReserve)) {
		return nil, uuid.Nil, nil, errTaskLeaseLost
	}
	work, cancel := context.WithCancel(context.WithValue(ctx, taskOwnerKey{}, owner))
	// 截止独立于 SQL 续租调用；数据库阻塞时也必须及时撤销本地执行权限。
	safety := time.AfterFunc(time.Until(confirmed.expires)-taskLeaseReserve, cancel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer safety.Stop()
		ticker := time.NewTicker(taskHeartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-work.Done():
				return
			case tick := <-ticker.C:
				now := time.Now()
				if !confirmed.expires.After(now.Add(taskLeaseReserve)) {
					cancel()
					return
				}
				renewEnd := minTaskLeaseTime(now.Add(taskRenewTimeout), confirmed.expires.Add(-taskLeaseReserve))
				renew, done := context.WithDeadline(work, renewEnd)
				ack, err := s.renewTaskLeaseAck(renew, session.ID, owner, now, deadline)
				done()
				if work.Err() != nil || !confirmed.accept(ack, err, time.Now(), tick.Add(taskHeartbeat)) {
					cancel()
					return
				}
				if err != nil {
					slog.Warn("任务续租暂时失败，等待下一次心跳", "session", session.ID, "confirmed_expires_at", confirmed.expires, "err", err)
					continue
				}
				if !safety.Reset(time.Until(confirmed.expires) - taskLeaseReserve) {
					cancel()
					return
				}
			}
		}
	}()
	return work, owner, func() { cancel(); <-done }, nil
}

func (s *Service) renewTaskLease(ctx context.Context, id, owner uuid.UUID, now, deadline time.Time) error {
	_, err := s.renewTaskLeaseAck(ctx, id, owner, now, deadline)
	return err
}

// renewTaskLeaseAck 只有 CAS 写入明确成功时返回已确认截止；超时提交结果未知不能扩展本地租约。
func (s *Service) renewTaskLeaseAck(ctx context.Context, id, owner uuid.UUID, now, deadline time.Time) (time.Time, error) {
	session, err := s.DB.AgentSession.Get(ctx, id)
	if ent.IsNotFound(err) {
		return time.Time{}, errTaskLeaseLost
	}
	if err != nil {
		return time.Time{}, err
	}
	if session.Kind != "task" || session.Initiator != commandgate.SystemActor || session.Status != "running" || session.CancelRequestedAt != nil ||
		session.RunOwner == nil || *session.RunOwner != owner || session.RunExpiresAt == nil || !session.RunExpiresAt.After(now) ||
		session.RunDeadlineAt == nil || !session.RunDeadlineAt.After(now) {
		return time.Time{}, errTaskLeaseLost
	}
	deadline = minTaskLeaseTime(deadline, *session.RunDeadlineAt)
	expires := leaseEnd(now, deadline)
	if !expires.After(now) {
		return time.Time{}, errTaskLeaseLost
	}
	n, err := s.DB.AgentSession.Update().Where(agentsession.IDEQ(id), agentsession.GroupIDEQ(session.GroupID), agentsession.KindEQ("task"),
		agentsession.InitiatorEQ(commandgate.SystemActor), agentsession.StatusEQ("running"), agentsession.RunOwnerEQ(owner),
		agentsession.RunExpiresAtGT(now), agentsession.RunExpiresAtLTE(expires), agentsession.RunDeadlineAtGT(now),
		agentsession.RunDeadlineAtEQ(*session.RunDeadlineAt), agentsession.CancelRequestedAtIsNil()).SetRunExpiresAt(expires).Save(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if n != 1 {
		return time.Time{}, errTaskLeaseLost
	}
	return expires, nil
}

type taskLeaseConfirmation struct{ expires time.Time }

// accept 失败不前移截止；只有已确认剩余足够覆盖下一拍及一次续租的安全预算时才容忍瞬时超时。
func (c *taskLeaseConfirmation) accept(ack time.Time, err error, now, retryAt time.Time) bool {
	if err == nil {
		if !c.expires.After(now.Add(taskLeaseReserve)) || !ack.After(now.Add(taskLeaseReserve)) {
			return false
		}
		c.expires = ack
		return true
	}
	if errors.Is(err, errTaskLeaseLost) || errors.Is(err, context.Canceled) {
		return false
	}
	var timeout net.Error
	if !errors.Is(err, context.DeadlineExceeded) && !(errors.As(err, &timeout) && timeout.Timeout()) {
		return false
	}
	if retryAt.Before(now) {
		retryAt = now
	}
	return c.expires.After(retryAt.Add(taskRenewTimeout + taskLeaseReserve))
}

func minTaskLeaseTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
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
	case "query", "command_status", "memories", "repair_capabilities":
		return true
	default:
		return false
	}
}
