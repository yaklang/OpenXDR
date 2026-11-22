package grpcsvc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/asset"
	"openxdr/server/pb"
)

// heartbeatInterval 指令通道在线期间刷新 last_seen 的周期。agent 一直挂着指令流，
// 流在就说明 agent 活着，不需要额外的心跳 RPC。
const heartbeatInterval = time.Minute

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
	// 指令流是响应处置的下发通道，冒领等于劫持隔离/杀进程指令
	if err := s.verifyAgentID(ctx, agentID); err != nil {
		return err
	}

	outbound := s.Hub.Attach(agentID)
	defer func() {
		s.Hub.Detach(agentID, outbound)
		s.Hub.Abandon(outbound)
	}()
	slog.Info("agent 指令通道已连接", "agent", agentID)
	s.touch(ctx, agentID)
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()

	// 不重放旧指令：隔离意图可能过期，PID 可能复用；迟到回执仍可正常入库。

	// 收执行结果：Recv 阻塞，单独跑一个 goroutine
	recvErr := make(chan error, 1)
	go func() {
		for {
			res, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if err := s.Hub.Complete(ctx, agentID, res); err != nil {
				slog.Warn("指令回执未持久化", "agent", agentID, "err", err)
				recvErr <- errors.New("指令回执未持久化，执行结果仍需核实")
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-heartbeat.C:
			s.touch(ctx, agentID)
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
				s.Hub.SendFailed(cmd, err)
				return err
			}
		}
	}
}

func (s *Server) touch(ctx context.Context, agentID uuid.UUID) {
	if err := s.DB.Asset.Update().Where(asset.AgentIDEQ(agentID), asset.RetiredAtIsNil()).SetLastSeen(time.Now()).Exec(ctx); err != nil {
		slog.Warn("刷新 agent 心跳失败", "agent", agentID, "err", err)
	}
}
