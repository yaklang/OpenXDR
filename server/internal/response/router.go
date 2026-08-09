package response

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"openxdr/server/pb"
)

// Router 把指令送到持有目标 agent gRPC 长连接的任意 server 实例。
type Router interface {
	Attach(uuid.UUID, func(*pb.Command) error) func()
	Deliver(context.Context, uuid.UUID, *pb.Command) error
	Online(context.Context, uuid.UUID) bool
	Close()
}

type NATSRouter struct{ nc *nats.Conn }

func NewNATSRouter(url, instance string) (*NATSRouter, error) {
	nc, err := nats.Connect(url, nats.Name("openxdr-command-"+instance), nats.MaxReconnects(-1), nats.ReconnectWait(time.Second))
	if err != nil {
		return nil, err
	}
	return &NATSRouter{nc: nc}, nil
}

func (r *NATSRouter) Attach(agentID uuid.UUID, deliver func(*pb.Command) error) func() {
	subject := "openxdr.commands." + agentID.String()
	sub, err := r.nc.QueueSubscribe(subject, "agent-"+agentID.String(), func(msg *nats.Msg) {
		var cmd pb.Command
		if proto.Unmarshal(msg.Data, &cmd) != nil {
			_ = msg.Respond([]byte("invalid"))
			return
		}
		if err := deliver(&cmd); err != nil {
			_ = msg.Respond([]byte(err.Error()))
			return
		}
		_ = msg.Respond([]byte("ok"))
	})
	if err != nil {
		return func() {}
	}
	presence, err := r.nc.QueueSubscribe("openxdr.presence."+agentID.String(), "presence-"+agentID.String(), func(msg *nats.Msg) {
		_ = msg.Respond([]byte("ok"))
	})
	if err != nil {
		_ = sub.Unsubscribe()
		return func() {}
	}
	_ = r.nc.Flush()
	return func() { _ = sub.Unsubscribe(); _ = presence.Unsubscribe() }
}

func (r *NATSRouter) Online(ctx context.Context, agentID uuid.UUID) bool {
	reply, err := r.nc.RequestWithContext(ctx, "openxdr.presence."+agentID.String(), nil)
	return err == nil && string(reply.Data) == "ok"
}

func (r *NATSRouter) Deliver(ctx context.Context, agentID uuid.UUID, cmd *pb.Command) error {
	body, err := proto.Marshal(cmd)
	if err != nil {
		return err
	}
	reply, err := r.nc.RequestWithContext(ctx, "openxdr.commands."+agentID.String(), body)
	if err != nil {
		if err == nats.ErrNoResponders || err == context.DeadlineExceeded {
			return fmt.Errorf("agent 未连接任何集群节点")
		}
		return fmt.Errorf("跨节点指令投递失败: %w", err)
	}
	if string(reply.Data) != "ok" {
		return fmt.Errorf("跨节点指令被拒绝: %s", reply.Data)
	}
	return nil
}

func (r *NATSRouter) Close() { r.nc.Close() }
