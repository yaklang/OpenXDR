//go:build integration

package commandgate

import (
	"strings"
	"testing"
	"time"

	"openxdr/server/ent/approval"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/commandpolicy"
)

// 系统身份只能在本组的任务会话里用；人不能冒用任务会话，系统也不能借用对话会话。
func TestSystemIdentity(t *testing.T) {
	f := setup(t)
	g := f.req.GroupID
	task := f.db.AgentSession.Create().SetKind("task").SetGroupID(g).SetInitiator(SystemActor).SetModel("m").SaveX(f.ctx)
	chat := f.db.AgentSession.Create().SetKind("chat").SetGroupID(g).SetInitiator("analyst").SetModel("m").SaveX(f.ctx)

	sys := f.req
	sys.System = true
	cases := map[string]Request{}
	noSession := sys
	cases["系统身份无会话"] = noSession
	onChat := sys
	onChat.SessionID = &chat.ID
	cases["系统身份借对话会话"] = onChat
	human := f.req
	human.SessionID = &task.ID
	cases["人冒用任务会话"] = human
	for name, req := range cases {
		if _, err := f.gate.Issue(f.ctx, req); err == nil {
			t.Errorf("%s 应被拒绝", name)
		}
	}
	assertNoCommand(t, f)
	// 审计记用户名而不是用户 ID，被拒的请求也一样留痕
	if n := f.db.AuditLog.Query().Where(auditlog.ActionEQ("exec_requested"), auditlog.UsernameEQ("analyst")).CountX(f.ctx); n != 1 {
		t.Errorf("人工请求应以用户名留痕 1 条，得到 %d", n)
	}

	ok := sys
	ok.SessionID = &task.ID
	direct := "uptime"
	ok.Command.Cmd = &direct
	cmd, err := f.gate.Issue(f.ctx, ok)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.IssuedBy != SystemActor {
		t.Errorf("issued_by 应为 system，得到 %s", cmd.IssuedBy)
	}
	<-f.ch

	// 命中高风险名单按任务自己的审批超时等待，超时不执行
	ok.Command.Cmd = f.req.Command.Cmd
	ok.ApprovalTimeout = 80 * time.Millisecond
	start := time.Now()
	_, err = f.gate.Issue(f.ctx, ok)
	if err == nil || !strings.Contains(err.Error(), "等待组管理员批准") {
		t.Fatalf("应审批超时，得到 %v", err)
	}
	if time.Since(start) > time.Second {
		t.Error("应按任务的审批超时而不是全局超时")
	}
	a := f.db.Approval.Query().OnlyX(f.ctx)
	if a.RequestedBy != SystemActor || a.Status != approval.StatusExpired {
		t.Errorf("审批记录不符：%s %s", a.RequestedBy, a.Status)
	}
	assertNoCommand(t, f)
}

// 定时任务被名单误伤的只读命令自动批准并照常留痕；系统不明的主机、会改东西的命令仍然等人审批。
func TestSystemAutoApprovesReadOnly(t *testing.T) {
	f := setup(t)
	task := f.db.AgentSession.Create().SetKind("task").SetGroupID(f.req.GroupID).SetInitiator(SystemActor).SetModel("m").SaveX(f.ctx)
	sys := f.req
	sys.System, sys.SessionID, sys.ApprovalTimeout = true, &task.ID, 80*time.Millisecond

	// 主机系统不明：只读也不知道按哪种 shell 解释，照常等审批
	if _, err := f.gate.Issue(f.ctx, sys); err == nil || !strings.Contains(err.Error(), "等待组管理员批准") {
		t.Fatalf("系统不明的主机应等审批，得到 %v", err)
	}
	assertNoCommand(t, f)

	f.db.Asset.UpdateOneID(sys.Command.AssetID).SetOs("linux").ExecX(f.ctx)
	cmd, err := f.gate.Issue(f.ctx, sys)
	if err != nil {
		t.Fatalf("只读命令应自动批准：%v", err)
	}
	<-f.ch
	auto := f.db.Approval.Query().Where(approval.StatusEQ(approval.StatusConsumed)).OnlyX(f.ctx)
	if auto.DecidedBy == nil || *auto.DecidedBy != SystemActor || auto.Cmd != *sys.Command.Cmd || cmd.IssuedBy != SystemActor {
		t.Errorf("自动批准的记录不符：%+v", auto)
	}
	if n := f.db.AuditLog.Query().Where(auditlog.ActionEQ("approval_auto"), auditlog.TargetEQ(auto.ID.String())).CountX(f.ctx); n != 1 {
		t.Errorf("自动批准应写审计 1 条，得到 %d", n)
	}

	// 同样命中名单、但会改东西：不自动批准
	destructive := "whoami; touch /tmp/x"
	sys.Command.Cmd = &destructive
	if _, err := f.gate.Issue(f.ctx, sys); err == nil || !strings.Contains(err.Error(), "等待组管理员批准") {
		t.Fatalf("非只读命令应等审批，得到 %v", err)
	}
	// 对话里的只读命令不走自动批准：有人在场，按原来的审批流程
	chat := f.db.AgentSession.Create().SetKind("chat").SetGroupID(f.req.GroupID).SetInitiator("analyst").SetModel("m").SaveX(f.ctx)
	human := f.req
	human.SessionID, human.ApprovalTimeout = &chat.ID, 80*time.Millisecond
	if _, err := f.gate.Issue(f.ctx, human); err == nil || !strings.Contains(err.Error(), "等待组管理员批准") {
		t.Fatalf("对话里的命令应照常等审批，得到 %v", err)
	}
	if n := f.db.Approval.Query().Where(approval.StatusEQ(approval.StatusConsumed)).CountX(f.ctx); n != 1 {
		t.Errorf("只应自动批准 1 次，得到 %d", n)
	}
}

func TestSystemAutoApprovesFirewallQueries(t *testing.T) {
	f := setup(t)
	task := f.db.AgentSession.Create().SetKind("task").SetGroupID(f.req.GroupID).SetInitiator(SystemActor).SetModel("m").SaveX(f.ctx)
	f.db.Asset.UpdateOneID(f.req.Command.AssetID).SetOs("linux").ExecX(f.ctx)
	f.db.CommandPolicy.Create().SetGroupID(f.req.GroupID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern("iptables|nft").ExecX(f.ctx)
	sys := f.req
	sys.System, sys.SessionID, sys.ApprovalTimeout = true, &task.ID, 80*time.Millisecond
	for _, query := range []string{"iptables -S", "iptables -L -n -v", "nft list ruleset"} {
		sys.Command.Cmd = &query
		if _, err := f.gate.Issue(f.ctx, sys); err != nil {
			t.Fatalf("防火墙查询未自动批准：%s: %v", query, err)
		}
		<-f.ch
	}
	if n := f.db.Approval.Query().Where(approval.StatusEQ(approval.StatusConsumed)).CountX(f.ctx); n != 3 {
		t.Fatalf("自动审批回执数量：%d", n)
	}
}
