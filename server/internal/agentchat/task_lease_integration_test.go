//go:build integration

package agentchat

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/testdb"
)

func TestRecoveryRequiresTrustedNoEffectProof(t *testing.T) {
	for _, name := range []string{"safe", "not_started", "legacy", "effect_intent", "hard_deadline", "cancelled", "lease_live", "messages_not_proof"} {
		t.Run(name, func(t *testing.T) {
			ctx, db := testdb.New(t)
			now := time.Now().UTC()
			g := db.Group.Create().SetName("lease-audit").SaveX(ctx)
			b := db.AgentSession.Create().SetKind("task").SetGroupID(g.ID).SetInitiator(commandgate.SystemActor).SetModel("m").SetRunExpiresAt(now.Add(-time.Minute))
			if name != "legacy" {
				b.SetRunDeadlineAt(now.Add(time.Hour)).SetRunReplaySafe(true)
			}
			if name != "not_started" && name != "legacy" {
				b.SetRunOwner(uuid.New())
			}
			if name == "effect_intent" || name == "messages_not_proof" {
				b.SetRunReplaySafe(false)
			}
			if name == "hard_deadline" {
				b.SetRunDeadlineAt(now.Add(-time.Minute))
			}
			if name == "cancelled" {
				b.SetCancelRequestedAt(now)
			}
			if name == "lease_live" {
				b.SetRunExpiresAt(now.Add(time.Minute))
			}
			session := b.SaveX(ctx)
			if name == "messages_not_proof" {
				db.SessionMessage.Create().SetSessionID(session.ID).SetSeq(1).SetRole("assistant").SetContent([]byte(`{"content":[{"type":"toolCall","name":"query","arguments":{"sql":"SELECT 1"}}]}`)).ExecX(ctx)
			}
			run := db.TaskRun.Create().SetTaskID("incident-backlog").SetGroupID(g.ID).SetSessionID(session.ID).SaveX(ctx)
			svc := &Service{DB: db}
			if err := svc.recoverExpired(ctx, now, time.Time{}); err != nil {
				t.Fatal(err)
			}
			want := "failed"
			if name == "safe" || name == "not_started" {
				want = "interrupted"
			}
			if name == "lease_live" {
				want = "running"
			}
			if got := db.TaskRun.GetX(ctx, run.ID).Status; got != want {
				t.Fatalf("TaskRun=%s want=%s", got, want)
			}
			if err := svc.recoverExpired(ctx, now.Add(time.Second), time.Time{}); err != nil {
				t.Fatal(err)
			}
			if db.AgentSession.Query().CountX(ctx) != 1 || db.Command.Query().CountX(ctx) != 0 {
				t.Fatal("恢复器不应自行创建会话或指令")
			}
		})
	}
}

func TestTaskLeaseOwnershipAndHardDeadline(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("owner").SaveX(ctx)
	hard := time.Now().Add(30 * time.Second)
	session := db.AgentSession.Create().SetKind("task").SetGroupID(g.ID).SetInitiator(commandgate.SystemActor).SetModel("m").SetRunDeadlineAt(hard).SaveX(ctx)
	svc := &Service{DB: db}
	run, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	work, owner, stop, err := svc.startTaskLease(run, session)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if _, _, otherStop, err := svc.startTaskLease(run, session); err == nil {
		otherStop()
		t.Fatal("同一会话被第二执行者领取")
	}
	if err := svc.renewTaskLease(work, session.ID, uuid.New(), time.Now(), hard); err == nil {
		t.Fatal("错误所有者可续租")
	}
	if err := svc.renewTaskLease(work, session.ID, owner, time.Now(), hard.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	current := db.AgentSession.GetX(ctx, session.ID)
	if current.RunExpiresAt == nil || current.RunExpiresAt.After(hard.Add(time.Millisecond)) {
		t.Fatal("续租超过持久化硬期限")
	}
	db.AgentSession.UpdateOneID(session.ID).SetRunExpiresAt(time.Now().Add(-time.Second)).ExecX(ctx)
	if err := svc.renewTaskLease(work, session.ID, owner, time.Now(), hard); err == nil {
		t.Fatal("已过期租约被复活")
	}
}

func TestTaskSideEffectIntentPrecedesCommandOrMessage(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("intent").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetGroupID(g.ID).SetInitiator(commandgate.SystemActor).SetModel("m").SaveX(ctx)
	db.TaskRun.Create().SetTaskID("incident-backlog").SetGroupID(g.ID).SetSessionID(session.ID).SaveX(ctx)
	svc := &Service{DB: db}
	run, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	work, _, stop, err := svc.startTaskLease(run, session)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if _, err := svc.guardTool(work, session, "exec"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.guardTool(work, session, "query"); err != nil {
		t.Fatal(err)
	}
	if db.AgentSession.GetX(ctx, session.ID).RunReplaySafe {
		t.Fatal("后续只读调用恢复了可重跑标记")
	}
	if db.Command.Query().CountX(ctx) != 0 || db.SessionMessage.Query().CountX(ctx) != 0 {
		t.Fatal("用例必须覆盖指令/消息尚未写入的崩溃窗口")
	}
	now := time.Now()
	db.AgentSession.UpdateOneID(session.ID).SetRunExpiresAt(now.Add(-time.Second)).ExecX(ctx)
	if err := svc.recoverExpired(ctx, now, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if db.TaskRun.Query().OnlyX(ctx).Status != "failed" {
		t.Fatal("副作用意图尚未有回执也不能按纯读重跑")
	}
	if _, err := svc.guardTool(work, session, "remember"); err == nil {
		t.Fatal("旧执行者仍可写入")
	}
}
