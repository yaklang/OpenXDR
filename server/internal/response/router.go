package response

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"openxdr/server/internal/natsretry"
	"openxdr/server/pb"
)

// Router 把指令送到持有目标 agent gRPC 长连接的任意 server 实例。
// 同一 agent 在另一节点重连时，旧节点的 deliver 会收到 nil，用于通知 Hub 关闭半开旧通道。
type Router interface {
	Attach(uuid.UUID, func(*pb.Command) error) func()
	Deliver(context.Context, uuid.UUID, *pb.Command) error
	Online(context.Context, uuid.UUID) bool
	Close()
}

type NATSRouter struct {
	nc    *nats.Conn
	retry natsretry.Policy
}

func NewNATSRouter(url, instance string) (*NATSRouter, error) {
	nc, err := nats.Connect(url, nats.Name("openxdr-command-"+instance), nats.MaxReconnects(-1), nats.ReconnectWait(time.Second))
	if err != nil {
		return nil, err
	}
	return &NATSRouter{nc: nc, retry: natsretry.Default}, nil
}

func (r *NATSRouter) Attach(agentID uuid.UUID, deliver func(*pb.Command) error) func() {
	id := agentID.String()
	token := uuid.NewString()
	subject := "openxdr.commands." + id
	sub, err := r.nc.QueueSubscribe(subject, "agent-"+id, func(msg *nats.Msg) {
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
	presence, err := r.nc.QueueSubscribe("openxdr.presence."+id, "presence-"+id, func(msg *nats.Msg) {
		_ = msg.Respond([]byte("ok"))
	})
	if err != nil {
		_ = sub.Unsubscribe()
		return func() {}
	}
	// 同一 agent 换节点重连时，广播挤掉其它节点残留的半开连接与队列订阅，避免指令落入死连接。
	evictSubject := "openxdr.evict." + id
	evict, err := r.nc.Subscribe(evictSubject, func(msg *nats.Msg) {
		if string(msg.Data) == token {
			return
		}
		_ = sub.Unsubscribe()
		_ = presence.Unsubscribe()
		_ = msg.Sub.Unsubscribe()
		_ = deliver(nil)
	})
	if err != nil {
		_ = sub.Unsubscribe()
		_ = presence.Unsubscribe()
		return func() {}
	}
	_ = r.nc.Publish(evictSubject, []byte(token))
	_ = r.nc.Flush()
	return func() {
		_ = sub.Unsubscribe()
		_ = presence.Unsubscribe()
		_ = evict.Unsubscribe()
	}
}

func (r *NATSRouter) Online(ctx context.Context, agentID uuid.UUID) bool {
	reply, err := r.nc.RequestWithContext(ctx, "openxdr.presence."+agentID.String(), nil)
	return err == nil && string(reply.Data) == "ok"
}

// Deliver 选主或 agent 重连换节点的空档里，只对能证明没下发的失败（undelivered）有界重试；
// 超时、连接中断等可能已经下发的失败立即返回，由 Hub 记 unknown，绝不重发。
func (r *NATSRouter) Deliver(ctx context.Context, agentID uuid.UUID, cmd *pb.Command) error {
	body, err := proto.Marshal(cmd)
	if err != nil {
		return err
	}
	subject := "openxdr.commands." + agentID.String()
	return r.retry.Do(ctx, func() error { return r.request(ctx, subject, body) }, undelivered)
}

func (r *NATSRouter) request(ctx context.Context, subject string, body []byte) error {
	reply, err := r.nc.RequestWithContext(ctx, subject, body)
	if errors.Is(err, nats.ErrNoResponders) {
		return fmt.Errorf("agent 未连接任何集群节点: %w", err)
	}
	if err != nil {
		return fmt.Errorf("跨节点指令投递失败: %w", err)
	}
	switch string(reply.Data) {
	case "ok":
		return nil
	case errConnGone.Error():
		return fmt.Errorf("跨节点指令被拒绝: %w", errConnGone)
	}
	return fmt.Errorf("跨节点指令被拒绝: %s", reply.Data)
}

// undelivered 能证明指令没有进任何 agent 通道的失败：
//   - no responders：NATS 服务端查不到订阅才直接回这个状态，消息没有交给任何订阅者
//   - 持有订阅的节点回 errConnGone：同一队列组只投一个成员，这个成员没把指令放进通道
//
// 其它拒绝（队列已满、解码失败）同样没下发，但重试改变不了结果，维持原口径。
func undelivered(err error) bool {
	return errors.Is(err, nats.ErrNoResponders) || errors.Is(err, errConnGone)
}

func (r *NATSRouter) Close() { r.nc.Close() }
