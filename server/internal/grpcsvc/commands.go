package grpcsvc

import (
	"errors"
	"io"
	"log/slog"

	"github.com/google/uuid"

	"openxdr/server/pb"
)

// Commands 双向指令流。agent 连上后先发一条只带 agent_id 的消息认领连接，
// 之后 server 单向推指令、agent 回执行结果。
func (s *Server) Commands(stream pb.AgentService_CommandsServer) error {
	ctx := stream.Context()
	if s.Hub == nil {
		return errors.New("响应能力未启用")
	}

	first, err := stream.Recv()
	if err != nil {
		return err
	}
	agentID, err := uuid.Parse(first.AgentId)
	if err != nil {
		return errors.New("首条消息必须带合法的 agent_id")
	}

	outbound := s.Hub.Attach(agentID)
	defer s.Hub.Detach(agentID, outbound)
	slog.Info("agent 指令通道已连接", "agent", agentID)

	// 断线重连后补发未回执的指令，否则它们会永远停在"已下发"
	for _, cmd := range s.Hub.PendingFor(ctx, agentID) {
		select {
		case outbound <- s.Hub.ToProto(cmd):
		default:
		}
	}

	// 收执行结果：Recv 阻塞，单独跑一个 goroutine
	recvErr := make(chan error, 1)
	go func() {
		for {
			res, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			s.Hub.Complete(ctx, res)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case cmd, ok := <-outbound:
			if !ok {
				return nil // 同一 agent 重连，本连接被顶掉
			}
			if err := stream.Send(cmd); err != nil {
				return err
			}
		}
	}
}
