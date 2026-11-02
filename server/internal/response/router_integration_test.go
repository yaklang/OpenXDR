//go:build integration

package response

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/pb"
)

func TestNATSRouterCrossNode(t *testing.T) {
	url := os.Getenv("NATS_URL")
	if url == "" {
		t.Skip("NATS_URL 未配置")
	}
	a, err := NewNATSRouter(url, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewNATSRouter(url, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	agentID := uuid.New()
	delivered := make(chan *pb.Command, 1)
	detach := a.Attach(agentID, func(cmd *pb.Command) error { delivered <- cmd; return nil })
	defer detach()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !b.Online(ctx, agentID) {
		t.Fatal("另一节点应看到 agent 在线")
	}
	if err := b.Deliver(ctx, agentID, &pb.Command{Id: uuid.NewString(), Cmd: "whoami"}); err != nil {
		t.Fatal(err)
	}
	select {
	case cmd := <-delivered:
		if cmd.Cmd != "whoami" {
			t.Fatal("指令内容未保留")
		}
	case <-ctx.Done():
		t.Fatal("跨节点指令未送达")
	}

	// 同一 agent 在 node-b 重连：node-a 的半开旧通道被广播挤掉，后续指令只走 node-b
	evictedA := make(chan struct{}, 1)
	detachA2 := a.Attach(agentID, func(cmd *pb.Command) error {
		if cmd == nil {
			evictedA <- struct{}{}
			return nil
		}
		delivered <- cmd
		return nil
	})
	defer detachA2()
	deliveredB := make(chan *pb.Command, 1)
	detachB := b.Attach(agentID, func(cmd *pb.Command) error {
		if cmd != nil {
			deliveredB <- cmd
		}
		return nil
	})
	defer detachB()
	select {
	case <-evictedA:
	case <-ctx.Done():
		t.Fatal("node-a 旧连接未被跨节点重连挤掉")
	}
	if err := a.Deliver(ctx, agentID, &pb.Command{Id: uuid.NewString(), Cmd: "id"}); err != nil {
		t.Fatal(err)
	}
	select {
	case cmd := <-deliveredB:
		if cmd.Cmd != "id" {
			t.Fatal("重连后指令内容未保留")
		}
	case <-ctx.Done():
		t.Fatal("重连后指令未送达新节点")
	}
}
