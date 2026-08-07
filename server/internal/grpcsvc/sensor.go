package grpcsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/sigma"
	"openxdr/server/pb"
)

// OCSF class：网络活动 / DNS 活动
const (
	classNetworkActivity = 4001
	classDNSActivity     = 4003
)

const protoTCP = 6

// SensorServer 流量探针接入：会话记录归一化成 OCSF 事件入库并过规则。
type SensorServer struct {
	pb.UnimplementedSensorServiceServer
	DB    *ent.Client
	Rules *sigma.Engine
}

func (s *SensorServer) ReportFlows(stream pb.SensorService_ReportFlowsServer) error {
	ctx := stream.Context()
	var received uint64

	for {
		batch, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&pb.FlowAck{Received: received})
		}
		if err != nil {
			return err
		}
		if batch.DroppedPackets > 0 {
			slog.Warn("探针丢包", "sensor", batch.SensorId, "dropped", batch.DroppedPackets)
		}
		if err := s.ingest(ctx, batch); err != nil {
			return err
		}
		received += uint64(len(batch.Flows))
	}
}

func (s *SensorServer) ingest(ctx context.Context, batch *pb.FlowBatch) error {
	// 网络事件按源 IP 归属资产，让 NTA 数据和 EDR 数据落到同一实体上。
	// 资产数量是主机量级，每批建一次索引即可。
	assetByIP, err := s.assetIPIndex(ctx)
	if err != nil {
		return err
	}

	var eventCreates []*ent.EventCreate
	var alertCreates []*ent.AlertCreate

	for _, f := range batch.Flows {
		classUID := classNetworkActivity
		if f.DnsQuery != "" {
			classUID = classDNSActivity
		}
		raw := flowRaw(f)
		var rawMap map[string]any
		_ = json.Unmarshal(raw, &rawMap)

		eventID := uuid.Must(uuid.NewV7())
		ts := time.Unix(0, f.StartUnixNs)
		assetID := assetByIP[f.SrcIp]
		ec := s.DB.Event.Create().
			SetID(eventID).
			SetTs(ts).
			SetClassUID(classUID).
			SetSource("sensor").
			SetNillableAssetID(assetID).
			SetConnTuple(connTuple(f)).
			SetRaw(raw)
		eventCreates = append(eventCreates, ec)

		for _, rule := range s.Rules.Evaluate(classUID, rawMap) {
			alertCreates = append(alertCreates, s.DB.Alert.Create().
				SetTs(ts).
				SetRuleID(rule.ID).
				SetSeverity(rule.Severity).
				SetEventID(eventID).
				SetNillableAssetID(assetID).
				SetLastTs(ts))
		}
	}

	if len(eventCreates) > 0 {
		if _, err := s.DB.Event.CreateBulk(eventCreates...).Save(ctx); err != nil {
			return err
		}
	}
	if len(alertCreates) > 0 {
		if _, err := s.DB.Alert.CreateBulk(alertCreates...).Save(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *SensorServer) assetIPIndex(ctx context.Context) (map[string]*uuid.UUID, error) {
	assets, err := s.DB.Asset.Query().Where(asset.IPAddrsNotNil()).All(ctx)
	if err != nil {
		return nil, err
	}
	index := make(map[string]*uuid.UUID, len(assets))
	for _, a := range assets {
		id := a.ID
		for _, ip := range a.IPAddrs {
			index[ip] = &id
		}
	}
	return index, nil
}

func connTuple(f *pb.FlowRecord) string {
	name := "udp"
	if f.Protocol == protoTCP {
		name = "tcp"
	}
	return fmt.Sprintf("%s:%s:%d>%s:%d", name, f.SrcIp, f.SrcPort, f.DstIp, f.DstPort)
}

// flowRaw 会话记录 -> OCSF 事件体。字段路径与 agent 侧保持同一套约定，
// 规则可以直接写 network.dst_endpoint.port 这样的 dot path。
func flowRaw(f *pb.FlowRecord) json.RawMessage {
	body := map[string]any{
		"activity_id": 6, // OCSF: Traffic
		"duration_ms": (f.EndUnixNs - f.StartUnixNs) / 1_000_000,
		"connection_info": map[string]any{
			"protocol_num": f.Protocol,
			"tcp_flags":    f.TcpFlags,
		},
		"src_endpoint": map[string]any{
			"ip":   f.SrcIp,
			"port": f.SrcPort,
		},
		"dst_endpoint": map[string]any{
			"ip":   f.DstIp,
			"port": f.DstPort,
		},
		"traffic": map[string]any{
			"packets":     f.SrcPackets + f.DstPackets,
			"bytes":       f.SrcBytes + f.DstBytes,
			"packets_out": f.SrcPackets,
			"bytes_out":   f.SrcBytes,
			"packets_in":  f.DstPackets,
			"bytes_in":    f.DstBytes,
		},
	}
	if f.DnsQuery != "" {
		body["query"] = map[string]any{"hostname": f.DnsQuery}
	}
	if f.TlsSni != "" {
		body["tls"] = map[string]any{"sni": f.TlsSni}
	}
	data, _ := json.Marshal(body)
	return data
}
