//go:build integration

package schedule

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

type leaseFinalizeRunner func(context.Context, Job) error

func (f leaseFinalizeRunner) RunTask(ctx context.Context, job Job) error { return f(ctx, job) }

func finalizeFixture(t *testing.T) (context.Context, *ent.Client, *ent.Task, *ent.Group, *ent.AgentSession, *ent.TaskRun) {
	t.Helper()
	ctx, db := testdb.New(t)
	task := db.Task.Create().SetID("finalize").SetName("终态收尾").SetSchedule("* * * * *").SetPrompt("test").SaveX(ctx)
	group := db.Group.Create().SetName("finalize").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetGroupID(group.ID).SetInitiator(Initiator).SetModel("test").SaveX(ctx)
	run := db.TaskRun.Create().SetTaskID(task.ID).SetGroupID(group.ID).SetSessionID(session.ID).SaveX(ctx)
	return ctx, db, task, group, session, run
}

func TestAttemptFinalizeSurvivesParentCancellationWithBoundedWindow(t *testing.T) {
	ctx, db, task, group, session, run := finalizeFixture(t)
	parent, cancel := context.WithCancel(ctx)
	defer cancel()
	db.TaskRun.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			end, ok := ctx.Deadline()
			if ctx.Err() != nil || !ok || time.Until(end) < 25*time.Second || time.Until(end) > 31*time.Second {
				return nil, errors.New("收尾缺少独立30s期限")
			}
			return next.Mutate(ctx, m)
		})
	})
	s := &Scheduler{DB: db, Timeout: time.Minute, Runner: leaseFinalizeRunner(func(context.Context, Job) error { cancel(); return nil })}
	if err := s.attempt(parent, task, group, run, session); err != nil {
		t.Fatal(err)
	}
	got := db.TaskRun.GetX(ctx, run.ID)
	if got.Status != "succeeded" || got.FinishedAt == nil {
		t.Fatal("任务完成后父ctx取消导致终态未保存", got)
	}
}

func TestAttemptFinalizeWaitsBeyondOldFiveSecondWindow(t *testing.T) {
	ctx, db, task, group, session, run := finalizeFixture(t)
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	tx.TaskRun.UpdateOneID(run.ID).SetError("持有行锁，模拟等待持久化").ExecX(ctx)
	started := make(chan struct{})
	done := make(chan error, 1)
	s := &Scheduler{DB: db, Timeout: time.Minute, Runner: leaseFinalizeRunner(func(context.Context, Job) error { close(started); return nil })}
	go func() { done <- s.attempt(ctx, task, group, run, session) }()
	<-started
	select {
	case err := <-done:
		t.Fatal("旧5s窗口提前结束终态保存", err)
	case <-time.After(6 * time.Second):
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("行锁释放后收尾未完成")
	}
	got := db.TaskRun.GetX(ctx, run.ID)
	if got.Status != "succeeded" || got.FinishedAt == nil {
		t.Fatal("超过5s的提交等待误判成失败", got)
	}
}

func TestAttemptFinalizeErrorPreservesPhaseAndUnknownOutcome(t *testing.T) {
	ctx, db, task, group, session, run := finalizeFixture(t)
	storeErr := context.DeadlineExceeded
	db.TaskRun.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(context.Context, ent.Mutation) (ent.Value, error) { return nil, storeErr })
	})
	s := &Scheduler{DB: db, Timeout: time.Minute, Runner: leaseFinalizeRunner(func(context.Context, Job) error { return errors.New("执行未完成") })}
	err := s.attempt(ctx, task, group, run, session)
	if !errors.Is(err, storeErr) || !strings.Contains(err.Error(), "task_run_finalize") {
		t.Fatal("保存错误丢失阶段或原始错误语义", err)
	}
	if db.TaskRun.GetX(ctx, run.ID).Status != "running" {
		t.Fatal("未知提交被伪造成失败或成功终态")
	}
}
