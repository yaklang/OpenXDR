package grpcsvc

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/pb"
)

// 探针的注册、抓包状态与升级。身份是「主机名上的探针」：绑定证书（CN sensor:<主机名>）只能
// 以这个主机名行事；通用证书与明文连接沿用旧口径，信任上报的主机名。
// 探针挂在同名资产上，与 agent 共用一条资产记录，但版本、心跳、状态各记各的。

// sensorHost 核对请求里的主机名与证书绑定一致。
func sensorHost(ctx context.Context, claimed string) (string, error) {
	if claimed == "" || len(claimed) > 253 {
		return "", status.Error(codes.InvalidArgument, "主机名无效")
	}
	if host, bound := sensorHostname(ctx); bound && host != claimed {
		return "", status.Error(codes.PermissionDenied, "主机名与探针证书绑定的主机不符")
	}
	return claimed, nil
}

func (s *SensorServer) Register(ctx context.Context, req *pb.SensorRegisterRequest) (*pb.SensorRegisterResponse, error) {
	host, err := sensorHost(ctx, req.Hostname)
	if err != nil {
		return nil, err
	}
	// 老版本探针不报操作系统，那时只有 Linux 版
	osName := req.Os
	if osName == "" {
		osName = "linux"
	}
	a, err := s.DB.Asset.Query().Where(asset.HostnameEQ(host)).First(ctx)
	if ent.IsNotFound(err) {
		a, err = s.DB.Asset.Create().SetHostname(host).SetOs(osName).Save(ctx)
	}
	if err != nil {
		return nil, err
	}
	upd := a.Update().SetSensorVersion(req.Version).SetSensorSeen(time.Now())
	// 同机有 agent 时地址以 agent 为准；只有探针的主机由探针登记地址，
	// 这台机器自己的流量才归得到它身上
	if a.AgentID == nil && len(req.IpAddrs) > 0 && len(req.IpAddrs) <= 64 {
		upd.SetIPAddrs(req.IpAddrs)
	}
	if a.Os == nil {
		upd.SetOs(osName)
	}
	if err := upd.Exec(ctx); err != nil {
		return nil, err
	}
	resp := &pb.SensorRegisterResponse{}
	if platform := s.Dist.Platform(osName, req.Arch); s.AutoUpgrade && req.BinarySha256 != "" && platform != "" {
		if want := s.Dist.SHA256(platform); want != "" && want != req.BinarySha256 {
			resp.UpgradeSha256, resp.UpgradePlatform = want, platform
			slog.Info("下发 sensor 升级", "host", host, "from", req.Version, "platform", platform)
		}
	}
	return resp, nil
}

// DownloadSensor 与 agent 同一套分块下载，哈希不符就拒绝。
func (s *SensorServer) DownloadSensor(req *pb.SensorDownloadRequest, stream pb.SensorService_DownloadSensorServer) error {
	return sendDist(s.Dist, req.Platform, req.Sha256, func(b []byte) error {
		return stream.Send(&pb.SensorChunk{Data: b})
	})
}

// sensorHealth 探针的抓包状态。快照头与 agent 的采集状态同一口径（启动标识、序号、采样时刻、组件状态），
// 组件只有 capture 一项，path 写「后端:网卡」；其余是抓包计数与速率，计数都是本次启动的累计值。
type sensorHealth struct {
	BootID         string                `json:"bootId"`
	Sequence       uint64                `json:"sequence"`
	ReportedUnixMs int64                 `json:"reportedUnixMs"`
	Iface          string                `json:"iface"`
	Backend        string                `json:"backend"`
	Workers        uint64                `json:"workers"`
	WorkersAlive   uint64                `json:"workersAlive"`
	Packets        uint64                `json:"packets"`
	Flows          uint64                `json:"flows"`
	KernelDrops    uint64                `json:"kernelDrops"`
	QueueDrops     uint64                `json:"queueDrops"`
	PacketRate     uint64                `json:"packetRate"`
	FlowRate       uint64                `json:"flowRate"`
	Capabilities   map[string]capability `json:"capabilities"`
}

func parseSensorHealth(raw string, now time.Time) (sensorHealth, error) {
	var h sensorHealth
	if err := decodeHealth(raw, &h); err != nil {
		return h, err
	}
	for _, n := range []uint64{h.Packets, h.Flows, h.KernelDrops, h.QueueDrops, h.PacketRate, h.FlowRate} {
		if n > safeInteger {
			return h, status.Error(codes.InvalidArgument, "抓包计数越界")
		}
	}
	if len(h.Iface) > 15 || (h.Backend != "afpacket" && h.Backend != "afxdp") || h.Workers > 1024 || h.WorkersAlive > h.Workers {
		return h, status.Error(codes.InvalidArgument, "抓包状态字段无效")
	}
	return h, checkSnapshot(h.BootID, h.Sequence, h.ReportedUnixMs, h.Capabilities, func(name string) bool { return name == "capture" }, now)
}

// ReportHealth 只写比库里更新的快照，同时刷新探针心跳；不碰 agent 的 last_seen。
func (s *SensorServer) ReportHealth(ctx context.Context, req *pb.SensorHealthRequest) (*pb.SensorHealthAck, error) {
	host, err := sensorHost(ctx, req.Hostname)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	h, err := parseSensorHealth(req.HealthJson, now)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(struct {
		sensorHealth
		ReceivedAt time.Time `json:"receivedAt"`
	}{h, now})
	if err != nil {
		return nil, status.Error(codes.Internal, "状态编码失败")
	}
	a, err := s.DB.Asset.Query().Where(asset.HostnameEQ(host), asset.SensorSeenNotNil()).First(ctx)
	if ent.IsNotFound(err) {
		return nil, status.Error(codes.NotFound, "探针尚未注册")
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "资产核对失败")
	}
	if _, err := s.DB.Asset.Update().Where(asset.IDEQ(a.ID), newerSnapshot(asset.FieldSensorHealth, h.BootID, h.Sequence, h.ReportedUnixMs)).
		SetSensorHealth(raw).SetSensorSeen(now).Save(ctx); err != nil {
		return nil, status.Error(codes.Internal, "抓包状态保存失败")
	}
	return &pb.SensorHealthAck{}, nil
}
