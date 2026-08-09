// Package response 响应指令的下发与审计。
//
// 这是系统里唯一能对被监控主机造成实际影响的部分，三道闸门都在这里：
//   - 全局开关 RESPONSE_ENABLED，默认关闭
//   - 指令默认 dry_run，要真执行必须显式声明
//   - 每条指令连同下发者与执行结果落库，可追溯
package response

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	entcommand "openxdr/server/ent/command"
	"openxdr/server/pb"
)

// 单个 agent 的指令缓冲。满了说明 agent 卡住，此时拒绝新指令而不是无限堆积
const pendingPerAgent = 32

type Hub struct {
	DB      *ent.Client
	Enabled bool
	Router  Router

	mu          sync.RWMutex
	conns       map[uuid.UUID]chan *pb.Command // agent_id -> 指令通道
	routeDetach map[uuid.UUID]func()
}

func NewHub(db *ent.Client, enabled bool) *Hub {
	if !enabled {
		slog.Warn("响应能力未启用：RESPONSE_ENABLED 为 false，指令一律拒绝下发")
	}
	return &Hub{DB: db, Enabled: enabled, conns: map[uuid.UUID]chan *pb.Command{}, routeDetach: map[uuid.UUID]func(){}}
}

// Online 报告某个 agent 当前是否挂着指令通道。
func (h *Hub) Online(agentID uuid.UUID) bool {
	h.mu.RLock()
	_, ok := h.conns[agentID]
	h.mu.RUnlock()
	if ok || h.Router == nil {
		return ok
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	return h.Router.Online(ctx, agentID)
}

// Attach 认领一个 agent 的指令通道。
func (h *Hub) Attach(agentID uuid.UUID) chan *pb.Command {
	ch := make(chan *pb.Command, pendingPerAgent)
	h.mu.Lock()
	// 同一 agent 重连时挤掉旧连接，避免指令发给已经断开的那条
	if old, ok := h.conns[agentID]; ok {
		close(old)
	}
	if detach := h.routeDetach[agentID]; detach != nil {
		detach()
	}
	h.conns[agentID] = ch
	if h.Router != nil {
		h.routeDetach[agentID] = h.Router.Attach(agentID, func(cmd *pb.Command) error {
			select {
			case ch <- cmd:
				return nil
			default:
				return fmt.Errorf("agent 指令队列已满")
			}
		})
	}
	h.mu.Unlock()
	return ch
}

// Detach 连接结束时摘除通道，只摘自己那条。
func (h *Hub) Detach(agentID uuid.UUID, ch chan *pb.Command) {
	h.mu.Lock()
	if cur, ok := h.conns[agentID]; ok && cur == ch {
		delete(h.conns, agentID)
		if detach := h.routeDetach[agentID]; detach != nil {
			detach()
			delete(h.routeDetach, agentID)
		}
	}
	h.mu.Unlock()
}

// Issue 下发一条指令。agent 不在线时直接失败——指令攒着等主机上线才执行，
// 到时候的处置意图很可能已经过期，比不执行更危险。
func (h *Hub) Issue(ctx context.Context, req Request) (*ent.Command, error) {
	if !h.Enabled {
		return nil, fmt.Errorf("响应能力未启用")
	}
	a, err := h.DB.Asset.Get(ctx, req.AssetID)
	if err != nil {
		return nil, fmt.Errorf("资产不存在: %w", err)
	}
	if a.AgentID == nil {
		return nil, fmt.Errorf("该资产没有 agent，无法下发指令")
	}

	create := h.DB.Command.Create().
		SetKind(req.Kind).
		SetDryRun(req.DryRun).
		SetAssetID(a.ID).
		SetIssuedBy(req.IssuedBy).
		SetNillableIncidentID(req.IncidentID).
		SetNillableProcessGUID(req.ProcessGUID)
	cmd, err := create.Save(ctx)
	if err != nil {
		return nil, err
	}

	h.mu.RLock()
	ch, online := h.conns[*a.AgentID]
	h.mu.RUnlock()
	if !online {
		if h.Router == nil {
			return h.finish(ctx, cmd.ID, "failed", "agent 未连接指令通道")
		}
		if err := h.Router.Deliver(ctx, *a.AgentID, req.toProto(cmd.ID)); err != nil {
			return h.finish(ctx, cmd.ID, "failed", err.Error())
		}
		return h.mark(ctx, cmd.ID, "sent")
	}

	select {
	case ch <- req.toProto(cmd.ID):
		return h.mark(ctx, cmd.ID, "sent")
	default:
		return h.finish(ctx, cmd.ID, "failed", "agent 指令队列已满")
	}
}

type Request struct {
	AssetID     uuid.UUID
	Kind        string
	DryRun      bool
	IncidentID  *uuid.UUID
	ProcessGUID *uuid.UUID
	PID         uint32
	IssuedBy    string
	// 隔离时必须放行的地址，务必包含 server 自身，否则解除隔离的指令再也送不进去
	AllowEndpoints []string
}

func (r Request) toProto(id uuid.UUID) *pb.Command {
	cmd := &pb.Command{
		Id:             id.String(),
		Kind:           kindToProto(r.Kind),
		DryRun:         r.DryRun,
		Pid:            r.PID,
		AllowEndpoints: r.AllowEndpoints,
	}
	if r.ProcessGUID != nil {
		cmd.ProcessGuid = r.ProcessGUID.String()
	}
	return cmd
}

// Kinds 支持的动作，同时用于 API 参数校验。
var Kinds = map[string]pb.CommandKind{
	"kill_process":   pb.CommandKind_KILL_PROCESS,
	"isolate_host":   pb.CommandKind_ISOLATE_HOST,
	"unisolate_host": pb.CommandKind_UNISOLATE_HOST,
}

func kindToProto(kind string) pb.CommandKind {
	return Kinds[kind]
}

func (h *Hub) mark(ctx context.Context, id uuid.UUID, status string) (*ent.Command, error) {
	return h.DB.Command.UpdateOneID(id).SetStatus(status).Save(ctx)
}

func (h *Hub) finish(ctx context.Context, id uuid.UUID, status, detail string) (*ent.Command, error) {
	return h.DB.Command.UpdateOneID(id).
		SetStatus(status).
		SetDetail(detail).
		SetCompletedAt(time.Now()).
		Save(ctx)
}

// ToProto 把库里的指令还原成下发消息，用于断线重连后补发。
func (h *Hub) ToProto(cmd *ent.Command) *pb.Command {
	out := &pb.Command{
		Id:     cmd.ID.String(),
		Kind:   kindToProto(cmd.Kind),
		DryRun: cmd.DryRun,
	}
	if cmd.ProcessGUID != nil {
		out.ProcessGuid = cmd.ProcessGUID.String()
	}
	return out
}

// Complete 回写执行结果。agent 上报的 command_id 必须能对上库里的记录，
// 对不上就丢弃——不接受来路不明的执行结果污染审计。
func (h *Hub) Complete(ctx context.Context, res *pb.CommandResult) {
	if res.CommandId == "" {
		return // 认领连接的首条消息
	}
	id, err := uuid.Parse(res.CommandId)
	if err != nil {
		return
	}
	status := map[pb.CommandResult_Status]string{
		pb.CommandResult_SUCCEEDED:   "succeeded",
		pb.CommandResult_FAILED:      "failed",
		pb.CommandResult_UNSUPPORTED: "unsupported",
	}[res.Status]
	if status == "" {
		status = "failed"
	}
	if _, err := h.finish(ctx, id, status, res.Detail); err != nil {
		slog.Warn("回写指令结果失败", "command", id, "err", err)
	} else {
		slog.Info("指令执行完毕", "command", id, "status", status, "detail", res.Detail)
	}
}

// PendingFor 取回某 agent 已下发但未回执的指令。断线重连后补发，
// 否则指令会随连接一起消失，界面上永远停在"已下发"。
func (h *Hub) PendingFor(ctx context.Context, agentID uuid.UUID) []*ent.Command {
	a, err := h.DB.Asset.Query().Where(asset.AgentIDEQ(agentID)).First(ctx)
	if err != nil {
		return nil
	}
	cmds, err := h.DB.Command.Query().
		Where(entcommand.AssetIDEQ(a.ID), entcommand.StatusEQ("sent")).
		Order(ent.Asc(entcommand.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil
	}
	return cmds
}
