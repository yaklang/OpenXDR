//go:build integration

package commandgate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"openxdr/server/ent/approval"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/commandpolicy"
)

// AI 发起、命中名单的命令由审计员当场评审：批准即下发，拒绝与评审出错都不执行；三种结果都记审批与审计，决定人 ai-reviewer
func TestReviewerDecidesAICommands(t *testing.T) {
	for _, tc := range []struct {
		name    string
		approve bool
		err     error
		status  approval.Status
		verdict string
	}{
		{"批准", true, nil, approval.StatusConsumed, "approved: 只读核对"},
		{"拒绝", false, nil, approval.StatusRejected, "rejected: 只读核对"},
		{"评审出错按拒绝", true, errors.New("端点不可用"), approval.StatusRejected, "rejected: 审计员评审失败：端点不可用"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			var seen *Request
			f.gate.Reviewer = func(_ context.Context, req Request) (bool, string, error) {
				seen = &req
				return tc.approve, "只读核对", tc.err
			}
			cmd, err := f.gate.Issue(f.ctx, f.req)
			if seen == nil || *seen.Command.Cmd != *f.req.Command.Cmd {
				t.Fatal("命中名单的 AI 命令应交给审计员")
			}
			if tc.status == approval.StatusConsumed {
				if err != nil || cmd == nil {
					t.Fatalf("批准后应下发: %v", err)
				}
				<-f.ch
			} else {
				if err == nil || !strings.Contains(err.Error(), "AI 审计员没有批准") {
					t.Fatalf("应拒绝并说明: %v", err)
				}
				assertNoCommand(t, f)
			}
			a := f.db.Approval.Query().OnlyX(f.ctx)
			if a.Status != tc.status || a.DecidedBy == nil || *a.DecidedBy != ReviewerActor {
				t.Fatalf("审批记录不符: %s %v", a.Status, a.DecidedBy)
			}
			logs := f.db.AuditLog.Query().Where(auditlog.ActionEQ("approval_ai_reviewed"), auditlog.TargetEQ(a.ID.String())).AllX(f.ctx)
			if len(logs) != 1 || logs[0].Detail == nil || *logs[0].Detail != tc.verdict {
				t.Fatalf("审计应记结论与理由: %+v", logs)
			}
		})
	}
}

// 硬拒绝的操作即使不在组名单里也不执行，也不送审计员
func TestHardDeniedNeverReachesReviewer(t *testing.T) {
	f := setup(t)
	f.gate.Reviewer = func(context.Context, Request) (bool, string, error) {
		t.Fatal("硬拒绝的命令不应送审计员")
		return true, "", nil
	}
	cmd := "systemctl stop openxdr-agent"
	f.req.Command.Cmd = &cmd
	if _, err := f.gate.Issue(f.ctx, f.req); err == nil || !strings.Contains(err.Error(), "硬拒绝") {
		t.Fatalf("应硬拒绝: %v", err)
	}
	assertNoCommand(t, f)
	if n := f.db.Approval.Query().CountX(f.ctx); n != 0 {
		t.Fatalf("硬拒绝不留审批记录，得到 %d", n)
	}
}

func TestReclaimExceptionRequiresInternalAuthorizationAndExactTemplate(t *testing.T) {
	for _, mode := range []string{"generic", "flag-only", "non-template", "revoked", "disabled", "review-denied", "authorized"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			task := f.db.AgentSession.Create().SetKind("task").SetGroupID(f.req.GroupID).SetInitiator(SystemActor).SetModel("m").SaveX(f.ctx)
			f.req.System, f.req.SessionID = true, &task.ID
			// 受保护路径（/var/lib）上的回收：只有内部授权 + 精确模板能绕过硬拒绝；普通目录的删除本来就只交审计员
			cmd := "find -- /var/lib/apt/lists -xdev -type f -mtime +7 -delete"
			f.req.Command.Cmd = &cmd
			f.db.CommandPolicy.Create().SetGroupID(f.req.GroupID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern("find").ExecX(f.ctx)
			reviews, finals := 0, 0
			f.gate.Reviewer = func(context.Context, Request) (bool, string, error) {
				reviews++
				return mode != "review-denied", "已评审", nil
			}
			if mode != "generic" {
				f.req.AuthorizedRepair = true
			}
			if mode != "flag-only" {
				f.req.BeforeIssue = func(context.Context) error {
					finals++
					if mode == "revoked" {
						return errors.New("授权已撤销")
					}
					return nil
				}
			}
			if mode == "non-template" {
				cmd += "; id"
			}
			if mode == "disabled" {
				f.gate.Hub.Enabled = false
			}
			out, err := f.gate.Issue(f.ctx, f.req)
			if mode == "authorized" {
				if err != nil || out == nil || reviews != 1 || finals != 1 {
					t.Fatal(out, err, reviews, finals)
				}
				<-f.ch
			} else {
				if err == nil {
					t.Fatal("拒绝条件被绕过")
				}
				assertNoCommand(t, f)
				if (mode == "generic" || mode == "flag-only" || mode == "non-template" || mode == "disabled") && reviews != 0 {
					t.Fatal("拒绝路径进入审计员")
				}
				if mode == "review-denied" && finals != 0 {
					t.Fatal("审批拒绝后消费了预留")
				}
			}
		})
	}
}
