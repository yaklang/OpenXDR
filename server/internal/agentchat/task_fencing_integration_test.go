//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/piruntime"
	"openxdr/server/internal/schedule"
	"openxdr/server/internal/testdb"
)

// 模拟旧执行者仍在模型调用中、会话已被恢复器收走；旧回调不能继续写入。
func TestTaskLeaseRevokesStaleToolCallbacks(t *testing.T) {
	for _, name := range []string{"remember", "report"} {
		for _, revoked := range []bool{false, true} {
			label := name + "/active"
			if revoked {
				label = name + "/recovered"
			}
			t.Run(label, func(t *testing.T) {
				ctx, db := testdb.New(t)
				g := db.Group.Create().SetName("audit-fence").SaveX(ctx)
				session := db.AgentSession.Create().SetKind("task").SetGroupID(g.ID).SetInitiator(commandgate.SystemActor).SetModel("test").SaveX(ctx)
				db.TaskRun.Create().SetTaskID("incident-backlog").SetGroupID(g.ID).SetSessionID(session.ID).SaveX(ctx)
				svc := &Service{DB: db}
				called := false
				svc.Runtime = fakeRunner{func(work context.Context, _ piruntime.Request, h piruntime.Handler, _ piruntime.Observer) (*piruntime.Result, error) {
					called = true
					if revoked {
						now := time.Now()
						db.AgentSession.UpdateOneID(session.ID).SetRunExpiresAt(now.Add(-time.Minute)).ExecX(ctx)
						if err := svc.recoverExpired(ctx, now, time.Time{}); err != nil {
							t.Fatal(err)
						}
					}
					args := map[string]any{"content": "审计任务确认的环境事实"}
					if name == "report" {
						args = map[string]any{"title": "验收报告", "summary": "审计测试", "markdown": "## 结论\n审计测试\n## 需要人处理\n无\n## 未验证\n无", "level": "ok"}
					}
					raw, err := json.Marshal(args)
					if err != nil {
						t.Fatal(err)
					}
					_, err = h(work, name, raw)
					if revoked && err == nil {
						t.Error("已恢复/撤销的旧会话仍可调用写工具")
					}
					if !revoked && err != nil {
						t.Errorf("活跃会话被误拒绝: %v", err)
					}
					return nil, errors.New("审计测试正常停止")
				}}
				_ = svc.RunTask(ctx, schedule.Job{Session: session, Prompt: "只读调查的审计用例", ApprovalTimeout: time.Second})
				if !called {
					t.Fatal("没有经过真实RunTask运行入口")
				}
				count := db.Memory.Query().CountX(ctx)
				if name == "report" {
					count = db.Report.Query().CountX(ctx)
				}
				want := 1
				if revoked {
					want = 0
				}
				if count != want {
					t.Errorf("写入数量=%d，期望=%d", count, want)
				}
			})
		}
	}
}
