//go:build integration

package schedule

import (
	"context"
	"errors"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

type auditTaskRunner func(context.Context, Job) error

func (f auditTaskRunner) RunTask(ctx context.Context, j Job) error { return f(ctx, j) }

func TestOldTaskExecutorCannotOverwriteReplacement(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("fence").SaveX(ctx)
	task := db.Task.Create().SetID("audit").SetName("审计").SetSchedule("@hourly").SetPrompt("只读").SaveX(ctx)
	s := &Scheduler{DB: db}
	run, session, err := s.begin(ctx, task, g, "m", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	replacement := db.AgentSession.Create().SetKind("task").SetGroupID(g.ID).SetInitiator(Initiator).SetModel("m").SaveX(ctx)
	calls, notes := 0, 0
	s.Runner = auditTaskRunner(func(context.Context, Job) error {
		calls++
		db.TaskRun.UpdateOneID(run.ID).SetSessionID(replacement.ID).ExecX(ctx)
		return nil
	})
	s.Notify = func(context.Context, string, string, string) error { notes++; return nil }
	s.execute(ctx, task, g, run, session)
	got := db.TaskRun.GetX(ctx, run.ID)
	if got.Status != "running" || got.SessionID == nil || *got.SessionID != replacement.ID {
		t.Fatalf("旧执行者改写了接管任务: %+v", got)
	}
	if calls != 1 || notes != 0 {
		t.Fatalf("旧执行者不应重试或通知: calls=%d notes=%d", calls, notes)
	}
}

func TestTaskRetryRequiresDurableNoEffectProof(t *testing.T) {
	for _, mode := range []string{"safe", "unknown_command", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			ctx, db := testdb.New(t)
			g := db.Group.Create().SetName("retry").SaveX(ctx)
			host := db.Asset.Create().SetHostname("h").SetGroupID(g.ID).SaveX(ctx)
			task := db.Task.Create().SetID("audit").SetName("审计").SetSchedule("@hourly").SetPrompt("只读").SaveX(ctx)
			s := &Scheduler{DB: db}
			run, session, err := s.begin(ctx, task, g, "m", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			s.Runner = auditTaskRunner(func(_ context.Context, j Job) error {
				calls++
				upd := db.AgentSession.UpdateOneID(j.Session.ID).SetStatus("failed").SetFinishedAt(time.Now())
				if mode != "safe" {
					upd.SetRunReplaySafe(false)
				}
				if mode == "legacy" {
					upd.ClearRunDeadlineAt()
				}
				upd.ExecX(ctx)
				if mode == "unknown_command" {
					db.Command.Create().SetAssetID(host.ID).SetKind("exec").SetIssuedBy(Initiator).SetStatus("unknown").SaveX(ctx)
				}
				return errors.New("模拟任务中断")
			})
			s.execute(ctx, task, g, run, session)
			want := 1
			if mode == "safe" {
				want = 2
			}
			if calls != want {
				t.Errorf("attempts=%d want=%d", calls, want)
			}
			if db.TaskRun.GetX(ctx, run.ID).Status != "failed" {
				t.Fatal("失败任务被标成成功")
			}
			if mode == "unknown_command" && db.Command.Query().CountX(ctx) != 1 {
				t.Fatal("unknown指令产生了重放")
			}
		})
	}
}
