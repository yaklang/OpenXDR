//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/report"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/piruntime"
	"openxdr/server/internal/schedule"
	"openxdr/server/internal/testdb"
)

func TestTaskCleanupHasBoundedSyncReplicationBudgetAndClearErrors(t *testing.T) {
	for _, mode := range []string{"release-failure", "terminal-failure", "runtime-and-release-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, db := testdb.New(t)
			g := db.Group.Create().SetName("cleanup-budget").SaveX(ctx)
			a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
			session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
			db.Task.Create().SetID(findings.FollowupTask).SetName("followup").SetSchedule("*/30 * * * *").SetPrompt("followup").SaveX(ctx)
			db.TaskRun.Create().SetTaskID(findings.FollowupTask).SetGroupID(g.ID).SetSessionID(session.ID).SetScheduledAt(time.Now()).SetStatus("running").SaveX(ctx)
			for i := 0; i < 3; i++ {
				db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey(fmt.Sprintf("task%d", i)).SetTitle("followup").SetWork(findings.EncodeWork(findings.Work{Version: 2, Plan: "original plan"})).ExecX(ctx)
			}
			clears := 0
			terminalSeen := false
			db.Finding.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
					if change, ok := m.(*ent.FindingMutation); ok && change.WorkSessionIDCleared() {
						clears++
						deadline, ok := ctx.Deadline()
						if !ok || time.Until(deadline) < 25*time.Second {
							t.Errorf("release still has insufficient SyncRep budget: %v %v", deadline, ok)
						}
						if mode != "terminal-failure" && clears == 2 {
							return nil, context.DeadlineExceeded
						}
					}
					return next.Mutate(ctx, m)
				})
			})
			db.AgentSession.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
					if change, ok := m.(*ent.AgentSessionMutation); ok {
						status, sets := change.Status()
						if sets && (status == "succeeded" || status == "failed") {
							terminalSeen = true
							deadline, ok := ctx.Deadline()
							if !ok || time.Until(deadline) < 25*time.Second {
								t.Errorf("terminal update still has insufficient SyncRep budget: %v %v", deadline, ok)
							}
							if mode == "terminal-failure" {
								return nil, context.DeadlineExceeded
							}
						}
					}
					return next.Mutate(ctx, m)
				})
			})
			original := errors.New("specific model failure")
			svc := &Service{DB: db, Runtime: fakeRunner{func(ctx context.Context, _ piruntime.Request, h piruntime.Handler, _ piruntime.Observer) (*piruntime.Result, error) {
				for i := 0; i < 3; i++ {
					args := fmt.Sprintf(`{"host":"%s","key":"task%d","title":"followup","detail":"verified current observation","severity":"medium","status":"open","next_step":"specific plan %d"}`, a.ID, i, i)
					if _, err := h(ctx, "track", json.RawMessage(args)); err != nil {
						return nil, err
					}
				}
				if _, err := h(ctx, "report", json.RawMessage(`{"title":"complete report","summary":"all three plans retained","markdown":"## 结论\n调查完成，保留后续计划\n## 需要人处理\n无\n## 未验证\n修复待后续验证","level":"attention"}`)); err != nil {
					return nil, err
				}
				if mode == "runtime-and-release-failure" {
					return nil, original
				}
				return &piruntime.Result{StopReason: "stop"}, nil
			}}}
			err := svc.RunTask(ctx, schedule.Job{Session: session, Prompt: "followup"})
			if err == nil || !errors.Is(err, context.DeadlineExceeded) || !terminalSeen {
				t.Fatalf("cleanup error disappeared: err=%v terminal=%v", err, terminalSeen)
			}
			if mode == "terminal-failure" {
				if !strings.Contains(err.Error(), "保存会话终态失败") {
					t.Fatal("bare terminal timeout", err)
				}
			} else if !strings.Contains(err.Error(), "释放待办租约失败") {
				t.Fatal("bare release timeout", err)
			}
			if mode == "runtime-and-release-failure" && !errors.Is(err, original) {
				t.Fatal("cleanup masked original task error", err)
			}
			if db.Report.Query().Where(report.SessionIDEQ(session.ID)).CountX(ctx) != 1 {
				t.Fatal("successful report was discarded")
			}
			got := db.AgentSession.GetX(ctx, session.ID)
			if mode == "terminal-failure" {
				if got.Status != "running" {
					t.Fatal("failed terminal write was declared successful", got.Status)
				}
			} else if got.Status != "failed" || got.Error == nil || !strings.Contains(*got.Error, "释放待办租约失败") {
				t.Fatalf("task status hid release failure %+v", got)
			}
			for _, f := range db.Finding.Query().AllX(ctx) {
				var work findings.Work
				_ = json.Unmarshal(f.Work, &work)
				if !strings.HasPrefix(work.Plan, "specific plan ") {
					t.Fatal("earlier completed plan lost", work)
				}
				if mode == "terminal-failure" {
					if f.WorkSessionID != nil || f.WorkLeaseUntil != nil {
						t.Fatal("successful release left partial leases", f)
					}
				} else if f.WorkSessionID == nil || *f.WorkSessionID != session.ID || f.WorkLeaseUntil == nil {
					t.Fatal("failed second update committed only part of batch", f)
				}
			}
			if db.Command.Query().CountX(ctx) != 0 {
				t.Fatal("cleanup failure replayed endpoint commands")
			}
		})
	}
}
