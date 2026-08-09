//go:build integration

package grpcsvc

import (
	"context"
	"io"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

// fakeCommandsStream 是 Commands 双向流的可控 fake。
// Recv: 首条返回 agent 认领，随后返回一个命令结果，最后 EOF。
// Send: 记录推送给 agent 的指令。
type fakeCommandsStream struct {
	ctx     context.Context
	msgs    []*pb.CommandResult
	recved  int
	sent    []*pb.Command
	done    chan struct{} // 收到 Send 时通知
	sendBuf []*pb.Command
}

func newFakeCommandsStream(ctx context.Context, msgs []*pb.CommandResult) *fakeCommandsStream {
	return &fakeCommandsStream{ctx: ctx, msgs: msgs, done: make(chan struct{}, 16)}
}

func (f *fakeCommandsStream) Recv() (*pb.CommandResult, error) {
	if f.recved >= len(f.msgs) {
		return nil, io.EOF
	}
	m := f.msgs[f.recved]
	f.recved++
	return m, nil
}
func (f *fakeCommandsStream) Send(c *pb.Command) error {
	f.sent = append(f.sent, c)
	f.sendBuf = append(f.sendBuf, c)
	f.done <- struct{}{}
	return nil
}
func (f *fakeCommandsStream) Context() context.Context     { return f.ctx }
func (f *fakeCommandsStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeCommandsStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeCommandsStream) SetTrailer(metadata.MD)       {}
func (f *fakeCommandsStream) SendMsg(any) error            { return nil }
func (f *fakeCommandsStream) RecvMsg(any) error            { return nil }

var _ grpc.BidiStreamingServer[pb.CommandResult, pb.Command] = (*fakeCommandsStream)(nil)

// 断线重连后补发未回执指令 + agent 执行后 Complete 回写审计。
func TestAgentCommandsReplayAndComplete(t *testing.T) {
	ctx, client := testdb.New(t)
	agentID := uuid.New()

	asset, err := client.Asset.Create().SetHostname("web01").SetAgentID(agentID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hub := response.NewHub(client, true)

	// 已下发未回执的指令（status=sent）应补发给重连的 agent。
	// 直接落一条 sent 指令，模拟“早已推给 agent 但连接断了”的状态。
	cmd, err := client.Command.Create().
		SetKind("isolate_host").
		SetDryRun(true).
		SetAssetID(asset.ID).
		SetStatus("sent").
		SetIssuedBy("admin").
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{Hub: hub}
	// agent 认领后返回执行结果
	agentClaim := &pb.CommandResult{AgentId: agentID.String()}
	result := &pb.CommandResult{
		AgentId: agentID.String(), CommandId: cmd.ID.String(),
		Status: pb.CommandResult_SUCCEEDED, Detail: "ok",
	}
	stream := newFakeCommandsStream(ctx, []*pb.CommandResult{agentClaim, result})

	if err := s.Commands(stream); err != nil {
		t.Fatalf("Commands 失败: %v", err)
	}

	// 补发的指令应推给 agent 且内容正确
	if len(stream.sent) != 1 {
		t.Fatalf("应补发 1 条指令，实际 %d", len(stream.sent))
	}
	pushed := stream.sent[0]
	if pushed.Kind != pb.CommandKind_ISOLATE_HOST || pushed.Id != cmd.ID.String() {
		t.Errorf("补发指令内容错误: %+v", pushed)
	}

	// 库中状态应更新为 succeeded，且 detail 落库
	got, err := client.Command.Get(ctx, cmd.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "succeeded" {
		t.Errorf("指令状态应为 succeeded，实际 %q", got.Status)
	}
	if got.Detail == nil || *got.Detail != "ok" {
		t.Errorf("detail 应回写为 ok，实际 %v", got.Detail)
	}
}
