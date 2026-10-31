// Package response 响应指令的下发与审计。
//
// 这是系统里唯一能对被监控主机造成实际影响的部分，闸门都在这里：
//   - 全局开关 RESPONSE_ENABLED，默认关闭；指令一律真执行，没有演练
//   - 每条指令连同下发者与执行结果落库，可追溯
package response

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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

// ErrDeliveryUnknown 表示已尝试投递，调用方不能将其当作未执行并重试。
var ErrDeliveryUnknown = errors.New("指令投递结果未知")

// errConnGone 指令没进通道：agent 连接已断或已被重连挤掉。跨节点回复里原样带回，
// 投递方据此认定这条指令肯定没下发
var errConnGone = errors.New("agent 指令连接已失效")

// ErrReceiptRejected 回执对不上本 agent 名下的指令：重传不会改变结果，agent 应当丢弃
var ErrReceiptRejected = errors.New("指令不存在或不属于当前 agent")

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
			if cmd == nil {
				h.evict(agentID, ch)
				return nil
			}
			_, err := h.enqueue(agentID, ch, cmd)
			return err
		})
	}
	h.mu.Unlock()
	return ch
}

// evict 另一集群节点认领同一 agent 时，关闭本节点的半开旧通道并摘除路由订阅。
func (h *Hub) evict(agentID uuid.UUID, ch chan *pb.Command) {
	h.mu.Lock()
	var detach func()
	if cur, ok := h.conns[agentID]; ok && cur == ch {
		delete(h.conns, agentID)
		close(ch)
		detach = h.routeDetach[agentID]
		delete(h.routeDetach, agentID)
	}
	h.mu.Unlock()
	if detach != nil {
		detach()
	}
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

// Issue 下发一条非 exec 指令。exec 必须经 commandgate 的来源、组权限、名单与
// 审批，这里一律拒绝，新增调用点也绕不过去。
func (h *Hub) Issue(ctx context.Context, req Request) (*ent.Command, error) {
	if req.Kind == "exec" {
		return nil, errors.New("exec 必须经 commandgate 下发")
	}
	return h.issue(ctx, req)
}

// IssueExec 仅供 commandgate.Gate.Issue 调用：它已完成判权并写入 IssuedBy。
func (h *Hub) IssueExec(ctx context.Context, req Request) (*ent.Command, error) {
	if req.Kind != "exec" {
		return nil, errors.New("IssueExec 只处理 exec")
	}
	return h.issue(ctx, req)
}

// issue 真正的下发：agent 不在线时直接失败——指令攒着等主机上线才执行，
// 到时候的处置意图很可能已经过期，比不执行更危险。
func (h *Hub) issue(ctx context.Context, req Request) (*ent.Command, error) {
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

	var automaticID uuid.UUID
	if req.automatic {
		if req.Kind != "isolate_host" || req.IncidentID == nil || *req.IncidentID == uuid.Nil {
			return nil, fmt.Errorf("自动响应必须绑定事件与隔离动作")
		}
		automaticID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("openxdr:auto-isolate|"+req.IncidentID.String()+"|"+a.ID.String()))
	}
	create := h.DB.Command.Create().
		SetKind(req.Kind).
		SetAssetID(a.ID).
		SetIssuedBy(req.IssuedBy).
		SetNillableIncidentID(req.IncidentID).
		SetNillableProcessGUID(req.ProcessGUID).
		SetNillableCmd(req.Cmd).
		SetTimeoutMs(req.TimeoutMS).SetPid(req.PID).SetAllowEndpoints(req.AllowEndpoints)
	if req.Target != "" {
		create.SetTarget(req.Target)
	}
	if automaticID != uuid.Nil {
		create.SetID(automaticID)
	}
	cmd, err := create.Save(ctx)
	if err != nil {
		if automaticID != uuid.Nil && ent.IsConstraintError(err) {
			prior, lookupErr := h.DB.Command.Get(ctx, automaticID)
			if lookupErr == nil && prior.Kind == req.Kind && prior.AssetID == a.ID && prior.IncidentID != nil && *prior.IncidentID == *req.IncidentID && prior.IssuedBy == req.IssuedBy {
				return prior, nil
			}
		}
		return nil, err
	}

	online, err := h.enqueue(*a.AgentID, nil, req.toProto(cmd.ID))
	if online {
		if err != nil {
			return h.finish(ctx, cmd.ID, "failed", err.Error())
		}
		return h.mark(ctx, cmd.ID, "sent")
	}
	if h.Router == nil {
		return h.finish(ctx, cmd.ID, "failed", "agent 未连接指令通道")
	}
	if err := h.Router.Deliver(ctx, *a.AgentID, req.toProto(cmd.ID)); err != nil {
		// 能证明没下发的瞬断 Router 内部已经重试过；走到这里的要么可能已下发（响应丢失不能证明
		// 远端没有执行），要么重试超限，一律记 unknown，所有动作都不能据此自动重试。
		status := "unknown"
		out, finishErr := h.finish(ctx, cmd.ID, status, err.Error())
		if finishErr != nil {
			return cmd, fmt.Errorf("%w：命令 %s 可能已投递，状态回写失败，禁止自动重试: %v", ErrDeliveryUnknown, cmd.ID, finishErr)
		}
		return out, finishErr
	}
	return h.mark(ctx, cmd.ID, "sent")
}

// enqueue 与重连关闭通道共用锁；旧 Router 回调不能向新连接投递。
func (h *Hub) enqueue(agentID uuid.UUID, expected chan *pb.Command, cmd *pb.Command) (bool, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ch, ok := h.conns[agentID]
	if !ok || (expected != nil && ch != expected) {
		return false, errConnGone
	}
	select {
	case ch <- cmd:
		return true, nil
	default:
		return true, fmt.Errorf("agent 指令队列已满")
	}
}

type Request struct {
	// 仅 Auto 可设置；不接受 HTTP/模型提供的幂等身份。
	automatic   bool
	AssetID     uuid.UUID
	Kind        string
	IncidentID  *uuid.UUID
	ProcessGUID *uuid.UUID
	PID         uint32
	IssuedBy    string
	// 隔离时必须放行的地址，务必包含 server 自身，否则解除隔离的指令再也送不进去
	AllowEndpoints []string
	// exec 用：命令行与超时（0 交给 agent 默认值）
	Cmd       *string
	TimeoutMS uint32
	// 封锁、隔离文件、锁定账号的目标，下发前须经 NormalizeTarget
	Target string
}

func (r Request) toProto(id uuid.UUID) *pb.Command {
	cmd := &pb.Command{
		Id:             id.String(),
		Kind:           kindToProto(r.Kind),
		Pid:            r.PID,
		AllowEndpoints: r.AllowEndpoints,
		TimeoutMs:      r.TimeoutMS,
		Target:         r.Target,
	}
	if r.Cmd != nil {
		cmd.Cmd = *r.Cmd
	}
	if r.ProcessGUID != nil {
		cmd.ProcessGuid = r.ProcessGUID.String()
	}
	return cmd
}

// Kinds 支持的动作，同时用于 API 参数校验。
var Kinds = map[string]pb.CommandKind{
	"kill_process":    pb.CommandKind_KILL_PROCESS,
	"isolate_host":    pb.CommandKind_ISOLATE_HOST,
	"unisolate_host":  pb.CommandKind_UNISOLATE_HOST,
	"exec":            pb.CommandKind_EXEC,
	"block_network":   pb.CommandKind_BLOCK_NETWORK,
	"unblock_network": pb.CommandKind_UNBLOCK_NETWORK,
	"quarantine_file": pb.CommandKind_QUARANTINE_FILE,
	"restore_file":    pb.CommandKind_RESTORE_FILE,
	"disable_account": pb.CommandKind_DISABLE_ACCOUNT,
	"enable_account":  pb.CommandKind_ENABLE_ACCOUNT,
}

func kindToProto(kind string) pb.CommandKind {
	return Kinds[kind]
}

// resultStatus 不把无法识别的回执解释成已知失败。
func resultStatus(st pb.CommandResult_Status) string {
	if s, ok := map[pb.CommandResult_Status]string{
		pb.CommandResult_SUCCEEDED:   "succeeded",
		pb.CommandResult_FAILED:      "failed",
		pb.CommandResult_UNSUPPORTED: "unsupported",
	}[st]; ok {
		return s
	}
	return "unknown"
}

func (h *Hub) mark(ctx context.Context, id uuid.UUID, status string) (*ent.Command, error) {
	// 快速回执可能先于投递确认到达，不能把终态改回 sent。
	if _, err := h.DB.Command.Update().Where(entcommand.IDEQ(id), entcommand.StatusEQ("pending")).SetStatus(status).Save(ctx); err != nil {
		return nil, fmt.Errorf("%w：命令 %s 可能已下发，状态回写失败，禁止自动重试: %v", ErrDeliveryUnknown, id, err)
	}
	cmd, err := h.DB.Command.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w：命令 %s 已投递，读取状态失败，禁止自动重试: %v", ErrDeliveryUnknown, id, err)
	}
	return cmd, nil
}

func (h *Hub) finish(ctx context.Context, id uuid.UUID, status, detail string) (*ent.Command, error) {
	update := h.DB.Command.Update().Where(entcommand.IDEQ(id), entcommand.StatusEQ("pending")).SetStatus(status).SetDetail(detail)
	if status != "unknown" {
		update.SetCompletedAt(time.Now())
	}
	if _, err := update.Save(ctx); err != nil {
		return nil, err
	}
	return h.DB.Command.Get(ctx, id)
}

// Abandon 连接结束时还缓冲在通道里、没写进指令流的指令：确定没送到 agent，记失败。
// 必须在 Detach 之后调用，此后不会再有指令进这个通道
func (h *Hub) Abandon(ch chan *pb.Command) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		select {
		case cmd, ok := <-ch:
			if !ok {
				return
			}
			h.settle(ctx, cmd.Id, "failed", "指令通道断开，指令未写入、未下发")
		default:
			return
		}
	}
}

// SendFailed 写指令流出错：可能已经到了 agent，记 unknown 交人核实，不重放
func (h *Hub) SendFailed(cmd *pb.Command, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h.settle(ctx, cmd.Id, "unknown", "写入指令通道失败，执行情况未知："+err.Error())
}

// settle 只改尚未有回执的指令：已经回执的终态不覆盖
func (h *Hub) settle(ctx context.Context, id, status, detail string) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return
	}
	upd := h.DB.Command.Update().Where(entcommand.IDEQ(uid), entcommand.StatusIn("pending", "sent")).SetStatus(status).SetDetail(detail)
	if status != "unknown" {
		upd.SetCompletedAt(time.Now())
	}
	if err := upd.Exec(ctx); err != nil {
		slog.Warn("回写未送达指令失败", "command", uid, "err", err)
	}
}

// ToProto 还原指令参数；不代表允许自动重放。
func (h *Hub) ToProto(cmd *ent.Command) *pb.Command {
	out := &pb.Command{
		Id:             cmd.ID.String(),
		Kind:           kindToProto(cmd.Kind),
		TimeoutMs:      cmd.TimeoutMs,
		Pid:            cmd.Pid,
		AllowEndpoints: append([]string(nil), cmd.AllowEndpoints...),
	}
	if cmd.Cmd != nil {
		out.Cmd = *cmd.Cmd
	}
	if cmd.Target != nil {
		out.Target = *cmd.Target
	}
	if cmd.ProcessGUID != nil {
		out.ProcessGuid = cmd.ProcessGUID.String()
	}
	return out
}

// Complete 回写执行结果。agent 上报的 command_id 必须能对上库里的记录，
// 来源不匹配或持久化失败明确返回错误；不接受来路不明的结果污染审计。
func (h *Hub) Complete(ctx context.Context, agentID uuid.UUID, res *pb.CommandResult) error {
	if res == nil {
		return errors.New("指令回执不能为空")
	}
	if res.CommandId == "" {
		return nil // 兼容连接认领消息。
	}
	id, err := uuid.Parse(res.CommandId)
	if err != nil || id == uuid.Nil {
		return errors.New("指令回执 ID 无效")
	}
	scope := entcommand.HasAssetWith(asset.AgentIDEQ(agentID))
	cmd, err := h.DB.Command.Query().Where(entcommand.IDEQ(id), scope).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrReceiptRejected
		}
		return fmt.Errorf("读取指令回执目标失败: %w", err)
	}
	status := resultStatus(res.Status)
	// 并发/重复回执只能完成非终态；终态保持首次记录。
	upd := h.DB.Command.Update().Where(entcommand.IDEQ(id), scope, entcommand.StatusIn("pending", "sent", "unknown")).SetStatus(status).SetDetail(storable(res.Detail))
	if status != "unknown" {
		upd.SetCompletedAt(time.Now())
	}
	if cmd.Kind == "exec" && status != "unknown" {
		upd.SetExitCode(res.ExitCode).SetStdout(storable(res.Stdout)).SetStderr(storable(res.Stderr)).SetTruncated(res.Truncated)
	}
	changed, err := upd.Save(ctx)
	if err != nil {
		return fmt.Errorf("持久化指令回执失败: %w", err)
	}
	if changed == 0 {
		// 资产换绑/记录删除不能伪装为成功；合法终态重投则幂等接受。
		current, err := h.DB.Command.Query().Where(entcommand.IDEQ(id), scope).Only(ctx)
		if ent.IsNotFound(err) {
			return ErrReceiptRejected
		}
		if err != nil {
			return fmt.Errorf("读取指令回执目标失败: %w", err)
		}
		// 结果未知的回执（执行被 agent 停机打断）遇上已有终态：以已有终态为准，同样确认
		if status != "unknown" && current.Status != "succeeded" && current.Status != "failed" && current.Status != "unsupported" {
			return errors.New("回执未写入，指令状态仍未确定")
		}
		return nil
	}
	slog.Info("指令回执已记录", "command", id, "status", status)
	return nil
}

// storable 命令输出入库前的整理：Postgres 文本列不收 NUL 字节和非法 UTF-8，读 /proc/*/cmdline 之类的输出常带这些，
// 原样写会整条回执失败、命令一直卡在已下发。NUL 换成可见的 ␀，非法字节换成替换字符，内容仍可读、不丢
func storable(s string) string {
	return strings.ReplaceAll(strings.ToValidUTF8(s, "\uFFFD"), "\x00", "␀")
}
