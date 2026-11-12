package grpcsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"openxdr/server/ent/asset"
	"openxdr/server/pb"
)

type capability struct {
	Path  string `json:"path"`
	State string `json:"state"`
	// Reason 降级原因：agent 活性检测发现通道开着却收不到事件时给出，只能跟着 degraded
	Reason string `json:"reason,omitempty"`
	// Rebuilds 本轮静默里 agent 已自动重建采集几次仍未恢复，只能跟着 Reason
	Rebuilds uint32 `json:"rebuilds,omitempty"`
	// Recoveries 本次运行里静默后靠自动重建恢复的次数，任何状态都可以带
	Recoveries uint32 `json:"recoveries,omitempty"`
}
type receiptHealth struct {
	Pending    uint64 `json:"pending"`
	Incomplete uint64 `json:"incomplete"`
}
type collectorHealth struct {
	Receipts        *receiptHealth        `json:"receipts,omitempty"`
	BootID          string                `json:"bootId"`
	Sequence        uint64                `json:"sequence"`
	ReportedUnixMs  int64                 `json:"reportedUnixMs"`
	QueueBytes      uint64                `json:"queueBytes"`
	QueueBatches    uint64                `json:"queueBatches"`
	QueueLimitBytes uint64                `json:"queueLimitBytes"`
	DroppedEvents   uint64                `json:"droppedEvents"`
	WriteBlocked    bool                  `json:"writeBlocked"`
	Capabilities    map[string]capability `json:"capabilities"`
}

// safeInteger 前端用 JSON number 读计数，超过 2^53 就失真
const safeInteger = 1<<53 - 1

// decodeHealth 严格解析状态快照：大小有界、不认识的字段直接拒绝、只能有一个 JSON 值。
func decodeHealth(raw string, v any) error {
	if len(raw) > 16*1024 {
		return status.Error(codes.InvalidArgument, "采集状态超过大小上限")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(v) != nil || decoder.Decode(new(any)) != io.EOF {
		return status.Error(codes.InvalidArgument, "采集状态格式无效")
	}
	return nil
}

// checkSnapshot agent 与 sensor 共用的快照头：启动标识、序号、采样时刻与组件状态。
func checkSnapshot(bootID string, sequence uint64, reportedMs int64, caps map[string]capability, known func(string) bool, now time.Time) error {
	if _, err := uuid.Parse(bootID); err != nil || sequence == 0 || sequence > safeInteger || len(caps) > 16 {
		return status.Error(codes.InvalidArgument, "采集状态字段越界")
	}
	reported := time.UnixMilli(reportedMs)
	if reported.Before(now.Add(-5*time.Minute)) || reported.After(now.Add(5*time.Minute)) {
		return status.Error(codes.InvalidArgument, "状态时间与服务端相差超过 5 分钟，请校准时钟")
	}
	for name, cap := range caps {
		if !known(name) {
			return status.Error(codes.InvalidArgument, "未知采集组件")
		}
		switch cap.State {
		case "active", "degraded", "unavailable", "disabled", "unknown":
		default:
			return status.Error(codes.InvalidArgument, "未知采集状态")
		}
		if len(cap.Path) > 64 {
			return status.Error(codes.InvalidArgument, "采集路径过长")
		}
		if len(cap.Reason) > 256 || (cap.Reason != "" && cap.State != "degraded") {
			return status.Error(codes.InvalidArgument, "降级原因无效")
		}
		if cap.Rebuilds > 0 && cap.Reason == "" {
			return status.Error(codes.InvalidArgument, "重建次数无效")
		}
	}
	return nil
}

func parseHealth(raw string, now time.Time) (collectorHealth, error) {
	var h collectorHealth
	if err := decodeHealth(raw, &h); err != nil {
		return h, err
	}
	if h.QueueBytes > safeInteger || h.QueueLimitBytes > safeInteger || h.DroppedEvents > safeInteger || h.QueueBatches > 8192 {
		return h, status.Error(codes.InvalidArgument, "采集状态字段越界")
	}
	if r := h.Receipts; r != nil && (r.Pending > 256 || r.Incomplete > 256 || r.Pending+r.Incomplete > 256) {
		return h, status.Error(codes.InvalidArgument, "回执缓存数量越界")
	}
	known := func(name string) bool {
		switch name {
		case "process", "files", "network", "dns", "auth", "inventory", "local-accounts", "persist", "kmod", "powershell", "software", "ssh-keys":
			return true
		}
		return false
	}
	return h, checkSnapshot(h.BootID, h.Sequence, h.ReportedUnixMs, h.Capabilities, known, now)
}

// newerSnapshot 只放行比库里更新的快照：同一次启动比序号；启动变化时要求采样时刻不倒退。
// column 是常量列名，不来自请求。
func newerSnapshot(column, bootID string, sequence uint64, reportedMs int64) func(*sql.Selector) {
	return func(sel *sql.Selector) {
		sel.Where(sql.P(func(b *sql.Builder) {
			b.WriteString("(" + column + " IS NULL OR " + column + " = 'null'::jsonb OR ((" + column + "->>'bootId' = ").Arg(bootID)
			b.WriteString(" AND (" + column + "->>'sequence')::numeric < ").Arg(sequence)
			b.WriteString(") OR (" + column + "->>'bootId' <> ").Arg(bootID)
			b.WriteString(" AND (" + column + "->>'reportedUnixMs')::bigint < ").Arg(reportedMs).WriteString(")))")
		}))
	}
}

// ReportHealth 不依赖事件总线。先验证证书归属，再原子拒绝重复或倒序状态。
func (s *Server) ReportHealth(ctx context.Context, req *pb.HealthRequest) (*pb.HealthAck, error) {
	id, err := uuid.Parse(req.AgentId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "agent_id 无效")
	}
	if err := s.verifyAgentID(ctx, id); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	h, err := parseHealth(req.HealthJson, now)
	if err != nil {
		return nil, err
	}
	snapshot := struct {
		collectorHealth
		ReceivedAt time.Time `json:"receivedAt"`
	}{h, now}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, status.Error(codes.Internal, "状态编码失败")
	}
	n, err := s.DB.Asset.Update().Where(asset.AgentIDEQ(id), newerSnapshot(asset.FieldCollectorHealth, h.BootID, h.Sequence, h.ReportedUnixMs)).
		SetCollectorHealth(raw).SetLastSeen(now).Save(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "采集状态保存失败")
	}
	if n == 0 {
		exists, err := s.DB.Asset.Query().Where(asset.AgentIDEQ(id)).Exist(ctx)
		if err != nil {
			return nil, status.Error(codes.Internal, "资产核对失败")
		}
		if !exists {
			return nil, status.Error(codes.NotFound, "agent 尚未注册")
		}
	}
	return &pb.HealthAck{}, nil
}
