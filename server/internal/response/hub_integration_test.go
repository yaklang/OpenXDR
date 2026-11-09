//go:build integration

package response

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

// Issue 三道闸门：能力未启用、资产无 agent、agent 未连接——三种都不得真执行。
func TestIssueGateways(t *testing.T) {
	ctx, client := testdb.New(t)

	agentID := uuid.New()
	asset, err := client.Asset.Create().
		SetHostname("victim").SetAgentID(agentID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 闸门一：RESPONSE_ENABLED=false，一律拒绝，且不落库
	off := NewHub(client, false)
	if _, err := off.Issue(ctx, Request{AssetID: asset.ID, Kind: "isolate_host", IssuedBy: "admin"}); err == nil {
		t.Fatal("能力未启用时 Issue 应拒绝")
	}
	if n, _ := client.Command.Query().Count(ctx); n != 0 {
		t.Fatalf("被拒绝的指令不应落库，实际 %d 条", n)
	}

	// 闸门二：资产没有 agent，无法下发
	noAgent, err := client.Asset.Create().SetHostname("orphan").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	on := NewHub(client, true)
	if _, err := on.Issue(ctx, Request{AssetID: noAgent.ID, Kind: "kill_process", IssuedBy: "admin"}); err == nil {
		t.Fatal("无 agent 的资产应拒绝下发")
	}

	// 闸门：只有 Windows 实现的动作，别的主机下发前就拒绝且不落库
	if _, err := on.Issue(ctx, Request{AssetID: asset.ID, Kind: "block_execution", Target: `C:\x\a.exe`, IssuedBy: "admin"}); err == nil ||
		!strings.Contains(err.Error(), "Windows") {
		t.Fatalf("非 Windows 主机应拒绝禁止执行：%v", err)
	}
	if n, _ := client.Command.Query().Count(ctx); n != 0 {
		t.Fatalf("被拒绝的指令不应落库，实际 %d 条", n)
	}

	// 闸门三：agent 在线但未连接指令通道（无 Router）→ 记 failed 而不是假装成功
	cmd, err := on.Issue(ctx, Request{AssetID: asset.ID, Kind: "isolate_host", IssuedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := client.Command.Get(ctx, cmd.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "failed" {
		t.Errorf("agent 未连接应记 failed，实际 %q", stored.Status)
	}
	if stored.CompletedAt == nil {
		t.Error("failed 指令应记录完成时间")
	}
}

// exec 全链路：下发带命令行、回执落输出；非 exec 回执不写输出字段。
func TestExecRoundTrip(t *testing.T) {
	ctx, client := testdb.New(t)

	agentID := uuid.New()
	asset, err := client.Asset.Create().SetHostname("web-01").SetAgentID(agentID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hub := NewHub(client, true)
	ch := hub.Attach(agentID)

	line := "uname -a"
	cmd, err := hub.IssueExec(ctx, Request{AssetID: asset.ID, Kind: "exec", Cmd: &line, TimeoutMS: 5000, IssuedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	sent := <-ch
	if sent.Kind != pb.CommandKind_EXEC || sent.Cmd != line || sent.TimeoutMs != 5000 {
		t.Fatalf("下发内容不符: %+v", sent)
	}
	// 推给 agent 的是签名信封：绑定这台 agent，内容就是这条指令
	var env pb.SignedCommand
	if !ed25519.Verify(hub.SignerPublic(), append([]byte(signContext), sent.Envelope...), sent.Signature) ||
		proto.Unmarshal(sent.Envelope, &env) != nil ||
		env.AgentId != agentID.String() || env.Command.GetId() != cmd.ID.String() || env.Command.GetCmd() != line {
		t.Fatalf("签名信封不符: %+v", &env)
	}
	if replay := hub.ToProto(cmd); replay.Cmd != line || replay.TimeoutMs != 5000 {
		t.Fatalf("序列化丢了命令行: %+v", replay)
	}

	hub.Complete(ctx, agentID, &pb.CommandResult{
		AgentId: agentID.String(), CommandId: cmd.ID.String(),
		Status: pb.CommandResult_SUCCEEDED, Detail: "退出码 2",
		ExitCode: 2, Stdout: "Linux", Stderr: "warn", Truncated: true,
	})
	got, err := client.Command.Get(ctx, cmd.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "succeeded" || got.ExitCode == nil || *got.ExitCode != 2 ||
		*got.Stdout != "Linux" || *got.Stderr != "warn" || !got.Truncated {
		t.Fatalf("exec 结果未完整回写: %+v", got)
	}

	kill, err := hub.Issue(ctx, Request{AssetID: asset.ID, Kind: "kill_process", PID: 1, IssuedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	<-ch
	hub.Complete(ctx, agentID, &pb.CommandResult{CommandId: kill.ID.String(), Status: pb.CommandResult_SUCCEEDED, Detail: "已结束 pid 1"})
	if got, _ := client.Command.Get(ctx, kill.ID); got.ExitCode != nil {
		t.Errorf("非 exec 指令不应写退出码: %v", *got.ExitCode)
	}
}

// 回执归属只相信已验证的流身份，不能伪造消息内 AgentId 污染别的资产。
func TestResultBoundToAgentAndFirstTerminal(t *testing.T) {
	ctx, db := testdb.New(t)
	agentID, other := uuid.New(), uuid.New()
	a := db.Asset.Create().SetHostname("bound").SetAgentID(agentID).SaveX(ctx)
	h := NewHub(db, true)
	ch := h.Attach(agentID)
	line := "whoami"
	cmd, err := h.IssueExec(ctx, Request{AssetID: a.ID, Kind: "exec", Cmd: &line})
	if err != nil {
		t.Fatal(err)
	}
	<-ch
	res := &pb.CommandResult{CommandId: cmd.ID.String(), AgentId: agentID.String(), Status: pb.CommandResult_SUCCEEDED, Stdout: "正确结果"}
	h.Complete(ctx, other, res)
	if got := db.Command.GetX(ctx, cmd.ID); got.Status != "sent" || got.Stdout != nil {
		t.Fatalf("跨资产回执被接受: %+v", got)
	}
	h.Complete(ctx, agentID, res)
	res.Status = pb.CommandResult_FAILED
	res.Stdout = "重复回执"
	h.Complete(ctx, agentID, res)
	got := db.Command.GetX(ctx, cmd.ID)
	if got.Status != "succeeded" || *got.Stdout != "正确结果" {
		t.Fatalf("终态被覆盖: %+v", got)
	}
}

type completingRouter struct {
	hub      *Hub
	fail     bool
	complete bool
}

func (r completingRouter) Attach(uuid.UUID, func(*pb.Command) error) func() { return func() {} }
func (r completingRouter) Online(context.Context, uuid.UUID) bool           { return true }
func (r completingRouter) Close()                                           {}
func (r completingRouter) Deliver(ctx context.Context, id uuid.UUID, c *pb.Command) error {
	if r.complete {
		r.hub.Complete(ctx, id, &pb.CommandResult{CommandId: c.Id, Status: pb.CommandResult_SUCCEEDED, Stdout: "done"})
	}
	if r.fail {
		return errors.New("投递确认超时")
	}
	return nil
}

func TestDeliveryCannotOverwriteEarlyResult(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			ctx, db := testdb.New(t)
			id := uuid.New()
			a := db.Asset.Create().SetHostname("remote").SetAgentID(id).SaveX(ctx)
			h := NewHub(db, true)
			h.Router = completingRouter{hub: h, fail: fail, complete: true}
			line := "whoami"
			cmd, err := h.IssueExec(ctx, Request{AssetID: a.ID, Kind: "exec", Cmd: &line})
			if err != nil {
				t.Fatal(err)
			}
			if cmd.Status != "succeeded" || cmd.Stdout == nil || *cmd.Stdout != "done" {
				t.Fatalf("快速回执被覆盖: %+v", cmd)
			}
		})
	}
}
func TestAllActionsUnknownDelivery(t *testing.T) {
	for kind := range Kinds {
		t.Run(kind, func(t *testing.T) {
			ctx, db := testdb.New(t)
			id := uuid.New()
			// Windows 主机才收得下全部动作（禁止执行只在 Windows 上实现）
			a := db.Asset.Create().SetHostname("remote").SetOs("windows").SetAgentID(id).SaveX(ctx)
			h := NewHub(db, true)
			h.Router = completingRouter{hub: h, fail: true}
			line := "whoami"
			issue := h.Issue
			if kind == "exec" {
				issue = h.IssueExec
			}
			cmd, err := issue(ctx, Request{AssetID: a.ID, Kind: kind, Cmd: &line})
			if err != nil {
				t.Fatal(err)
			}
			if cmd.Status != "unknown" || cmd.CompletedAt != nil {
				t.Fatalf("未知投递被当成终态: %+v", cmd)
			}
			h.Complete(ctx, id, &pb.CommandResult{CommandId: cmd.ID.String(), Status: pb.CommandResult_SUCCEEDED})
			if got := db.Command.GetX(ctx, cmd.ID); got.Status != "succeeded" || got.CompletedAt == nil {
				t.Fatal("未知投递应接受迟到的合法回执")
			}
		})
	}
}

func TestUnknownReceiptAllowsLaterResult(t *testing.T) {
	ctx, db := testdb.New(t)
	id := uuid.New()
	a := db.Asset.Create().SetHostname("unknown-result").SetAgentID(id).SaveX(ctx)
	h := NewHub(db, true)
	ch := h.Attach(id)
	line := "whoami"
	cmd, err := h.IssueExec(ctx, Request{AssetID: a.ID, Kind: "exec", Cmd: &line})
	if err != nil {
		t.Fatal(err)
	}
	<-ch
	h.Complete(ctx, id, &pb.CommandResult{CommandId: cmd.ID.String(), Status: pb.CommandResult_Status(999), Stdout: "不能认定为执行完成"})
	got := db.Command.GetX(ctx, cmd.ID)
	if got.Status != "unknown" || got.CompletedAt != nil || got.ExitCode != nil || got.Stdout != nil {
		t.Fatalf("未知回执制造终态: %+v", got)
	}
	h.Complete(ctx, id, &pb.CommandResult{CommandId: cmd.ID.String(), Status: pb.CommandResult_SUCCEEDED, Stdout: "真实回执"})
	got = db.Command.GetX(ctx, cmd.ID)
	if got.Status != "succeeded" || got.Stdout == nil || *got.Stdout != "真实回执" {
		t.Fatal("迟到回执未覆盖未知状态")
	}
}

// 连接断开时还缓冲在通道里的指令确定没送到：记失败而不是永远停在 sent；写流出错的记 unknown
func TestUndeliveredCommandsSettle(t *testing.T) {
	ctx, db := testdb.New(t)
	agentID := uuid.New()
	a := db.Asset.Create().SetHostname("undelivered").SetAgentID(agentID).SaveX(ctx)
	h := NewHub(db, true)
	ch := h.Attach(agentID)
	queued, err := h.Issue(ctx, Request{AssetID: a.ID, Kind: "isolate_host", IssuedBy: "admin"})
	if err != nil || queued.Status != "sent" {
		t.Fatalf("下发失败: %v %v", err, queued)
	}
	h.Detach(agentID, ch)
	h.Abandon(ch)
	if got := db.Command.GetX(ctx, queued.ID); got.Status != "failed" || got.CompletedAt == nil {
		t.Fatalf("未写入的指令应记失败，实际 %s", got.Status)
	}

	ch = h.Attach(agentID)
	sent, err := h.Issue(ctx, Request{AssetID: a.ID, Kind: "kill_process", PID: 1, IssuedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	h.SendFailed(<-ch, errors.New("broken pipe"))
	if got := db.Command.GetX(ctx, sent.ID).Status; got != "unknown" {
		t.Fatalf("写流失败应记 unknown，实际 %s", got)
	}
	// 已有回执的终态不被覆盖
	h.settle(ctx, queued.ID.String(), "unknown", "x")
	if got := db.Command.GetX(ctx, queued.ID).Status; got != "failed" {
		t.Fatalf("终态被覆盖为 %s", got)
	}
}

// 新动作把目标落库、原样送到 agent；能力未启用时同样被拦
func TestTargetedActionsCarryTarget(t *testing.T) {
	ctx, db := testdb.New(t)
	agentID := uuid.New()
	a := db.Asset.Create().SetHostname("targeted").SetAgentID(agentID).SaveX(ctx)
	if _, err := NewHub(db, false).Issue(ctx, Request{AssetID: a.ID, Kind: "block_network", Target: "45.9.148.10", IssuedBy: "admin"}); err == nil {
		t.Fatal("RESPONSE_ENABLED 关闭时不得下发")
	}
	h := NewHub(db, true)
	ch := h.Attach(agentID)
	for kind, target := range map[string]string{"block_network": "45.9.148.0/24", "quarantine_file": "/tmp/x.sh", "disable_account": "deploy"} {
		cmd, err := h.Issue(ctx, Request{AssetID: a.ID, Kind: kind, Target: target, IssuedBy: "admin"})
		if err != nil || cmd.Target == nil || *cmd.Target != target {
			t.Fatalf("%s 下发或落库不对: %v %+v", kind, err, cmd)
		}
		sent := <-ch
		if sent.Kind != Kinds[kind] || sent.Target != target || h.ToProto(cmd).Target != target {
			t.Fatalf("%s 送到 agent 的指令不对: %+v", kind, sent)
		}
	}
}
