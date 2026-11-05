//go:build integration

package agentchat

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/testdb"
)

func leaseRetrySession(t *testing.T) (context.Context, *ent.Client, *ent.AgentSession, uuid.UUID, time.Time) {
	t.Helper()
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	g := db.Group.Create().SetName("lease-retry").SaveX(ctx)
	owner := uuid.New()
	session := db.AgentSession.Create().SetKind("task").SetGroupID(g.ID).SetInitiator(commandgate.SystemActor).SetModel("m").SetRunOwner(owner).SetRunExpiresAt(now.Add(taskLeaseTTL)).SetRunDeadlineAt(now.Add(10 * time.Minute)).SaveX(ctx)
	return ctx, db, session, owner, now
}

func TestTaskLeaseTransientTimeoutCanRenewNextBeat(t *testing.T) {
	ctx, db, session, owner, now := leaseRetrySession(t)
	svc := &Service{DB: db}
	var fail atomic.Bool
	fail.Store(true)
	db.AgentSession.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if fail.CompareAndSwap(true, false) {
				return nil, context.DeadlineExceeded
			}
			return next.Mutate(ctx, m)
		})
	})
	confirmed := taskLeaseConfirmation{expires: *session.RunExpiresAt}
	ack, err := svc.renewTaskLeaseAck(ctx, session.ID, owner, now.Add(time.Minute), *session.RunDeadlineAt)
	if !errors.Is(err, context.DeadlineExceeded) || !ack.IsZero() {
		t.Fatal("timeout不能返回已确认期限", ack, err)
	}
	if !confirmed.accept(ack, err, now.Add(time.Minute+10*time.Second), now.Add(2*time.Minute)) || !confirmed.expires.Equal(*session.RunExpiresAt) {
		t.Fatal("瞬时错误错误取消或扩租")
	}
	ack, err = svc.renewTaskLeaseAck(ctx, session.ID, owner, now.Add(2*time.Minute), *session.RunDeadlineAt)
	if err != nil || !confirmed.accept(ack, err, now.Add(2*time.Minute), now.Add(3*time.Minute)) {
		t.Fatal("下一拍未恢复续租", ack, err)
	}
	if !confirmed.expires.Equal(*db.AgentSession.GetX(ctx, session.ID).RunExpiresAt) {
		t.Fatal("本地不是精确确认期限")
	}
}

func TestTaskLeaseUnknownCommitCannotExtendConfirmedExpiry(t *testing.T) {
	ctx, db, session, owner, now := leaseRetrySession(t)
	svc := &Service{DB: db}
	db.AgentSession.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			_, err := next.Mutate(ctx, m)
			if err != nil {
				return nil, err
			}
			return nil, context.DeadlineExceeded
		})
	})
	confirmed := taskLeaseConfirmation{expires: *session.RunExpiresAt}
	ack, err := svc.renewTaskLeaseAck(ctx, session.ID, owner, now.Add(time.Minute), *session.RunDeadlineAt)
	if !errors.Is(err, context.DeadlineExceeded) || !ack.IsZero() {
		t.Fatal("提交未知不能产生ack")
	}
	if !db.AgentSession.GetX(ctx, session.ID).RunExpiresAt.After(confirmed.expires) {
		t.Fatal("未覆盖服务端提交但客户端未收到确认的窗口")
	}
	if !confirmed.accept(ack, err, now.Add(time.Minute+10*time.Second), now.Add(2*time.Minute)) || !confirmed.expires.Equal(*session.RunExpiresAt) {
		t.Fatal("未知提交错误改变本地确认")
	}
	ack, err = svc.renewTaskLeaseAck(ctx, session.ID, owner, now.Add(2*time.Minute), *session.RunDeadlineAt)
	if confirmed.accept(ack, err, now.Add(2*time.Minute+10*time.Second), now.Add(3*time.Minute)) {
		t.Fatal("借未知提交跨越最后已确认租约")
	}
	if !confirmed.expires.Equal(*session.RunExpiresAt) {
		t.Fatal("未知提交延长权限")
	}
}

func TestTaskLeaseAuthoritativeLossIsNotTolerated(t *testing.T) {
	for _, change := range []string{"owner", "cancel", "terminal", "expired", "deadline", "deadline_race"} {
		t.Run(change, func(t *testing.T) {
			ctx, db, session, owner, now := leaseRetrySession(t)
			svc := &Service{DB: db}
			switch change {
			case "owner":
				db.AgentSession.UpdateOneID(session.ID).SetRunOwner(uuid.New()).ExecX(ctx)
			case "cancel":
				db.AgentSession.UpdateOneID(session.ID).SetCancelRequestedAt(now).ExecX(ctx)
			case "terminal":
				db.AgentSession.UpdateOneID(session.ID).SetStatus("succeeded").ExecX(ctx)
			case "expired":
				db.AgentSession.UpdateOneID(session.ID).SetRunExpiresAt(now.Add(-time.Second)).ExecX(ctx)
			case "deadline":
				db.AgentSession.UpdateOneID(session.ID).SetRunDeadlineAt(now.Add(-time.Second)).ExecX(ctx)
			case "deadline_race":
				var change atomic.Bool
				change.Store(true)
				db.AgentSession.Use(func(next ent.Mutator) ent.Mutator {
					return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
						if change.CompareAndSwap(true, false) {
							if err := db.AgentSession.UpdateOneID(session.ID).SetRunDeadlineAt(now.Add(90 * time.Second)).Exec(ctx); err != nil {
								return nil, err
							}
						}
						return next.Mutate(ctx, m)
					})
				})
			}
			ack, err := svc.renewTaskLeaseAck(ctx, session.ID, owner, now, *session.RunDeadlineAt)
			if !errors.Is(err, errTaskLeaseLost) || !ack.IsZero() {
				t.Fatal("权威失效仍获续租", ack, err)
			}
			confirmed := taskLeaseConfirmation{expires: now.Add(time.Hour)}
			if confirmed.accept(ack, err, now, now.Add(time.Minute)) {
				t.Fatal("失效租约凭本地旧确认继续")
			}
		})
	}
}

func TestTaskLeaseSafetyDeadlineCancelsDuringBlockedRenewal(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("watchdog").SaveX(ctx)
	hard := time.Now().Add(taskLeaseReserve + 2*time.Second)
	session := db.AgentSession.Create().SetKind("task").SetGroupID(g.ID).SetInitiator(commandgate.SystemActor).SetModel("m").SetRunDeadlineAt(hard).SaveX(ctx)
	parent, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	svc := &Service{DB: db}
	work, owner, stop, err := svc.startTaskLease(parent, session)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	tx.AgentSession.UpdateOneID(session.ID).SetTitle("锁住续租更新").ExecX(ctx)
	type result struct {
		ack time.Time
		err error
	}
	completed := make(chan result, 1)
	go func() {
		ack, err := svc.renewTaskLeaseAck(work, session.ID, owner, time.Now(), hard)
		completed <- result{ack, err}
	}()
	select {
	case <-work.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SQL阻塞时本地安全截止未独立取消任务")
	}
	_ = tx.Rollback()
	select {
	case got := <-completed:
		if got.err == nil || !got.ack.IsZero() {
			t.Fatal("被取消的阻塞续租仍返回成功ack", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("安全截止后SQL未退出")
	}
	if work.Err() == nil {
		t.Fatal("晚到结果恢复了取消上下文")
	}
}

func TestTaskLeaseRealDatabaseTimeoutRetriesWithoutExtendingAck(t *testing.T) {
	ctx, db, session, owner, _ := leaseRetrySession(t)
	svc := &Service{DB: db}
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	tx.AgentSession.UpdateOneID(session.ID).SetTitle("暂时锁住续租").ExecX(ctx)
	confirmed := taskLeaseConfirmation{expires: *session.RunExpiresAt}
	attempt, done := context.WithTimeout(ctx, 100*time.Millisecond)
	ack, err := svc.renewTaskLeaseAck(attempt, session.ID, owner, time.Now(), *session.RunDeadlineAt)
	done()
	if !errors.Is(err, context.DeadlineExceeded) || !ack.IsZero() {
		t.Fatal("真实PG超时未保留deadline错误与未知ack", ack, err)
	}
	if !confirmed.accept(ack, err, time.Now(), time.Now().Add(taskHeartbeat)) || !confirmed.expires.Equal(*session.RunExpiresAt) {
		t.Fatal("可恢复数据库超时错误取消或扩租")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	ack, err = svc.renewTaskLeaseAck(ctx, session.ID, owner, time.Now(), *session.RunDeadlineAt)
	if err != nil || !confirmed.accept(ack, err, time.Now(), time.Now().Add(taskHeartbeat)) {
		t.Fatal("数据库恢复后未能续租", ack, err)
	}
	if !confirmed.expires.Equal(*db.AgentSession.GetX(ctx, session.ID).RunExpiresAt) {
		t.Fatal("本地确认与真实成功写入不一致")
	}
}

func TestTaskLeaseLateOldRenewalCannotShortenAcknowledgedExpiry(t *testing.T) {
	ctx, db, session, owner, now := leaseRetrySession(t)
	svc := &Service{DB: db}
	var pending atomic.Bool
	pending.Store(true)
	var newerAck time.Time
	db.AgentSession.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if pending.CompareAndSwap(true, false) {
				// 旧请求已读快照但尚未写入，此时下一拍先完成并明确确认更晚的expires。
				ack, err := svc.renewTaskLeaseAck(ctx, session.ID, owner, now.Add(time.Minute), *session.RunDeadlineAt)
				if err != nil {
					return nil, err
				}
				newerAck = ack
			}
			return next.Mutate(ctx, m)
		})
	})
	oldAck, err := svc.renewTaskLeaseAck(ctx, session.ID, owner, now.Add(30*time.Second), *session.RunDeadlineAt)
	if !errors.Is(err, errTaskLeaseLost) || !oldAck.IsZero() {
		t.Fatal("旧请求仍获准缩短新期限", oldAck, err)
	}
	current := db.AgentSession.GetX(ctx, session.ID)
	if newerAck.IsZero() || current.RunExpiresAt == nil || !current.RunExpiresAt.Equal(newerAck) {
		t.Fatal("晚到旧续租覆盖了新ack期限", newerAck, current.RunExpiresAt)
	}
}
