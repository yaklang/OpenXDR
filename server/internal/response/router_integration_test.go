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
	if err := b.Deliver(ctx, agentID, &pb.Command{Id: uuid.NewString(), DryRun: true}); err != nil {
		t.Fatal(err)
	}
	select {
	case cmd := <-delivered:
		if !cmd.DryRun {
			t.Fatal("指令内容未保留")
		}
	case <-ctx.Done():
		t.Fatal("跨节点指令未送达")
	}
}
