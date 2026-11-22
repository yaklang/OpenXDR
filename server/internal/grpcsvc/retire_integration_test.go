//go:build integration

package grpcsvc

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/internal/assetretire"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

// 下线：agent_id 清掉、挂着的处置结束；旧证书注册不回来，探针也不行；恢复后重新注册拿新的 agent_id
func TestRetiredHostCannotComeBack(t *testing.T) {
	ctx, client := testdb.New(t)
	srv := &Server{DB: client}
	resp, err := srv.Register(ctxWithCN("host:web01"), &pb.RegisterRequest{Hostname: "web01"})
	if err != nil {
		t.Fatal(err)
	}
	a := client.Asset.Query().OnlyX(ctx)
	mk := func(state entcontainment.State) *entcontainment.State {
		c := client.Containment.Create().SetAssetID(a.ID).SetKind("block_network").SetTarget("203.0.113.7").SetKey(uuid.NewString()).
			SetSignal("ai:verdict").SetAlertID(uuid.New()).SetRole(entcontainment.RoleHost).SetState(state).SetReason("原因").
			SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
		return &c.State
	}
	mk(entcontainment.StateProposed)
	mk(entcontainment.StateActive)
	if _, err := assetretire.Retire(ctx, client, a, "admin", "", time.Now()); err != assetretire.ErrNoReason {
		t.Fatalf("下线必须写原因：%v", err)
	}
	retired, err := assetretire.Retire(ctx, client, a, "admin", "VM 已删除", time.Now())
	if err != nil || retired.AgentID != nil || retired.RetiredAt == nil {
		t.Fatalf("下线后应清掉 agent_id：%v %v", retired, err)
	}
	states := map[entcontainment.State]int{}
	for _, c := range client.Containment.Query().AllX(ctx) {
		states[c.State]++
	}
	if states[entcontainment.StateDeclined] != 1 || states[entcontainment.StateLifted] != 1 {
		t.Fatalf("待审批应作废、生效中的应解除：%v", states)
	}
	if _, err := srv.Register(ctxWithCN("host:web01"), &pb.RegisterRequest{Hostname: "web01"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("旧证书不能注册回来：%v", err)
	}
	if err := srv.verifyAgentID(ctxWithCN("host:web01"), uuid.MustParse(resp.AgentId)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("旧 agent_id 的事件流应被拒：%v", err)
	}
	if _, err := assetretire.Retire(ctx, client, retired, "admin", "再来", time.Now()); err != assetretire.ErrRetired {
		t.Fatalf("不能重复下线：%v", err)
	}
	if _, err := assetretire.Restore(ctx, client, retired); err != nil {
		t.Fatal(err)
	}
	again, err := srv.Register(ctxWithCN("host:web01"), &pb.RegisterRequest{Hostname: "web01"})
	if err != nil || again.AgentId == resp.AgentId {
		t.Fatalf("恢复后应拿新的 agent_id：%v %v", again, err)
	}
}

// 退役资产跳过 Register 直接调用其余 gRPC RPC 时，无论是绑定证书还是通用/明文通道，均须返回 PermissionDenied。
func TestRetiredAssetRejectedOnAllAgentRPCs(t *testing.T) {
	ctx, client := testdb.New(t)
	agentID := uuid.New()
	client.Asset.Create().SetHostname("retired-host").SetAgentID(agentID).SetRetiredAt(time.Now()).SaveX(ctx)
	srv := &Server{DB: client, Hub: response.NewHub(client, true)}

	healthJSON, _ := json.Marshal(collectorHealth{
		BootID: uuid.NewString(), Sequence: 1, ReportedUnixMs: time.Now().UnixMilli(),
		Capabilities: map[string]capability{"process": {Path: "poll", State: "active"}},
	})
	checkAll := func(name string, rpcCtx context.Context) {
		t.Helper()
		evStream := &fakeAgentStream{
			ctx: rpcCtx,
			events: []*pb.AgentEvent{{
				AgentId: agentID.String(), TsUnixNs: time.Now().UnixNano(), ClassUid: 1007,
				ProcessGuid: uuid.NewString(), RawJson: `{"process":{"cmd_line":"id"}}`,
			}},
		}
		if err := srv.ReportEvents(evStream); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s ReportEvents 应 PermissionDenied，实际 %v", name, err)
		}
		cmdStream := newFakeCommandsStream(rpcCtx, []*pb.CommandResult{{AgentId: agentID.String()}})
		if err := srv.Commands(cmdStream); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s Commands 应 PermissionDenied，实际 %v", name, err)
		}
		if _, err := srv.ReportHealth(rpcCtx, &pb.HealthRequest{AgentId: agentID.String(), HealthJson: string(healthJSON)}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s ReportHealth 应 PermissionDenied，实际 %v", name, err)
		}
		if _, err := srv.ReportCommandResult(rpcCtx, &pb.CommandResult{
			AgentId: agentID.String(), CommandId: uuid.NewString(), Status: pb.CommandResult_SUCCEEDED,
		}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s ReportCommandResult 应 PermissionDenied，实际 %v", name, err)
		}
		if _, err := srv.ReportSSHKeys(rpcCtx, &pb.ReportSSHKeysRequest{AgentId: agentID.String()}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s ReportSSHKeys 应 PermissionDenied，实际 %v", name, err)
		}
	}

	checkAll("绑定证书", ctxWithCN("host:retired-host"))
	checkAll("通用证书", ctxWithCN("openxdr-collector"))
	checkAll("明文连接", ctx)
}
