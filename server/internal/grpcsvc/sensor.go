package grpcsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	// 注册 gzip 编码器：探针开了 SENSOR_GRPC_COMPRESSION=gzip 后上行消息带
	// grpc-encoding: gzip，没有这个空导入 grpc-go 会以 "Decompressor is not installed" 拒收。
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/dedup"
	"openxdr/server/internal/enroll"
	"openxdr/server/internal/eventbus"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
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
	DB          *ent.Client
	Rules       sigma.Catalog
	DedupWindow time.Duration
	Suppress    *suppress.Store
	Intel       *intel.Store
	Events      eventbus.Bus
	// sensor 安装包与自动升级开关，与 agent 共用 AGENT_DIST_DIR / AGENT_AUTO_UPGRADE
	Dist        *enroll.Dist
	AutoUpgrade bool
}

func (s *SensorServer) ReportFlows(stream pb.SensorService_ReportFlowsServer) error {
	ctx := stream.Context()
	var received uint64

	// 一台探针覆盖多个资产，指纹要带 asset。去重状态跨批保留，直到连接结束
	deduper := dedup.New(s.DedupWindow)

	for {
		batch, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&pb.FlowAck{Received: received})
		}
		if err != nil {
			return err
		}
		if host, bound := sensorHostname(ctx); bound && host != batch.SensorId {
			return status.Error(codes.PermissionDenied, "sensor_id 与探针证书绑定的主机不符")
		}
		if batch.DroppedPackets > 0 {
			slog.Warn("探针丢包", "sensor", batch.SensorId, "dropped", batch.DroppedPackets)
		}
		var ingestErr error
		if s.Events != nil {
			ingestErr = s.enqueue(ctx, batch)
		} else {
			ingestErr = s.ingest(ctx, batch, deduper)
		}
		if ingestErr != nil {
			return ingestErr
		}
		received += uint64(len(batch.Flows))
	}
}

func (s *SensorServer) enqueue(ctx context.Context, batch *pb.FlowBatch) error {
	assetByIP, osByIP, err := s.assetIPIndex(ctx)
	if err != nil {
		return err
	}
	var pending []ingest.Envelope
	bytes := 0
	for _, f := range batch.Flows {
		classUID := classNetworkActivity
		if f.DnsQuery != "" {
			classUID = classDNSActivity
		}
		raw := flowRaw(f)
		assetID, assetOS := flowAsset(f, assetByIP, osByIP)
		partitionKey := f.SrcIp
		if assetID != nil {
			partitionKey = assetID.String()
		}
		id := ingest.StableID(batch.SensorId, strconv.FormatInt(f.StartUnixNs, 10),
			strconv.FormatInt(f.EndUnixNs, 10), connTuple(f), string(raw))
		pending = append(pending, ingest.Envelope{
			Version: ingest.EnvelopeVersion, ID: id, PartitionKey: partitionKey,
			Timestamp: time.Unix(0, f.StartUnixNs), ClassUID: classUID, Source: "sensor",
			AssetID: assetID, AssetOS: assetOS, ConnTuple: connTuple(f), Raw: raw,
		})
		bytes += len(raw)
		if len(pending) >= eventbus.BatchSize(s.Events) || bytes >= 256<<10 {
			if err := eventbus.PublishBatch(ctx, s.Events, pending); err != nil {
				return fmt.Errorf("流事件入队: %w", err)
			}
			pending = nil
			bytes = 0
		}
	}
	return eventbus.PublishBatch(ctx, s.Events, pending)
}

func (s *SensorServer) ingest(ctx context.Context, batch *pb.FlowBatch, deduper *dedup.Deduper) error {
	// 网络事件按地址归属资产，让 NTA 数据和 EDR 数据落到同一实体上。
	// 资产数量是主机量级，每批建一次索引即可。
	assetByIP, osByIP, err := s.assetIPIndex(ctx)
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
		assetID, assetOS := flowAsset(f, assetByIP, osByIP)
		ec := s.DB.Event.Create().
			SetID(eventID).
			SetTs(ts).
			SetClassUID(classUID).
			SetSource("sensor").
			SetNillableAssetID(assetID).
			SetConnTuple(connTuple(f)).
			SetRaw(sanitizeRawJSON(raw))
		eventCreates = append(eventCreates, ec)

		for _, h := range intel.Detections(s.Rules.Evaluate(classUID, assetOS, rawMap), s.Intel.Match(rawMap, ts)) {
			if s.Suppress.Suppressed(h.RuleID, assetID, rawMap, ts) {
				continue
			}
			fingerprint := h.RuleID + "|" + f.SrcIp
			if assetID != nil {
				fingerprint = h.RuleID + "|" + assetID.String()
			}
			if deduper.Hit(fingerprint, ts) {
				continue
			}
			alertID := uuid.Must(uuid.NewV7())
			alertCreates = append(alertCreates, s.DB.Alert.Create().
				SetID(alertID).
				SetTs(ts).
				SetRuleID(h.RuleID).
				SetSeverity(h.Severity).
				SetEventID(eventID).
				SetNillableAssetID(assetID).
				SetLastTs(ts))
			deduper.Track(fingerprint, alertID, ts)
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
	return deduper.Flush(ctx, s.DB)
}

// assetIPIndex 建立 IP -> 资产 的索引，同时带出操作系统，
// 规则的 logsource product 要靠它过滤。
func (s *SensorServer) assetIPIndex(ctx context.Context) (map[string]*uuid.UUID, map[string]string, error) {
	assets, err := s.DB.Asset.Query().Where(asset.IPAddrsNotNil()).All(ctx)
	if err != nil {
		return nil, nil, err
	}
	index := make(map[string]*uuid.UUID, len(assets))
	osIndex := make(map[string]string, len(assets))
	for _, a := range assets {
		id := a.ID
		for _, ip := range a.IPAddrs {
			index[ip] = &id
			if a.Os != nil {
				osIndex[ip] = strings.ToLower(*a.Os)
			}
		}
	}
	return index, osIndex, nil
}

// flowAsset 会话归属：源地址是纳管资产就归源（出站、内网互访，与以往一致）；否则看目的地址——
// 公网打进反代网关的会话归到网关上，组视图与研判才看得见，与 agent 记录入站连接同一口径。
// 两头都不是纳管资产就不归属。归到目的端的事件体里源地址不是资产自己的，资产图谱据此按入站处理。
func flowAsset(f *pb.FlowRecord, assetByIP map[string]*uuid.UUID, osByIP map[string]string) (*uuid.UUID, string) {
	if id := assetByIP[f.SrcIp]; id != nil {
		return id, osByIP[f.SrcIp]
	}
	return assetByIP[f.DstIp], osByIP[f.DstIp]
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
		// rcode_id 为 0 可能是 NOERROR，也可能是没抓到应答（proto3 uint32 无零值区分）
		body["query"] = map[string]any{"hostname": f.DnsQuery, "rcode_id": f.DnsRcode}
		if len(f.DnsAnswers) > 0 {
			// 应答 IP 用键名 ip，情报碰撞按键名递归收集时自动生效
			answers := make([]map[string]any, 0, len(f.DnsAnswers))
			for _, ip := range f.DnsAnswers {
				answers = append(answers, map[string]any{"ip": ip})
			}
			body["answers"] = answers
		}
	}
	if f.TlsSni != "" || f.Ja3 != "" || f.Ja3S != "" || f.TlsVersion != "" || f.TlsAlpn != "" || f.TlsCertSubject != "" || f.TlsHandshakeOnly {
		tls := map[string]any{}
		if f.TlsSni != "" {
			tls["sni"] = f.TlsSni
		}
		if f.TlsVersion != "" {
			tls["version"] = f.TlsVersion
		}
		if f.TlsAlpn != "" {
			tls["alpn"] = f.TlsAlpn
		}
		if f.Ja3 != "" {
			tls["ja3_hash"] = f.Ja3
		}
		if f.Ja3S != "" {
			tls["ja3s_hash"] = f.Ja3S
		}
		if f.TlsHandshakeOnly {
			// 只握手不发请求：扫描器、证书探测、存活检查的典型形态。只陈述事实，不单独告警
			tls["handshake_only"] = true
		}
		if f.TlsCertSubject != "" {
			// 仅 TLS ≤1.2 可见；self_signed 是 subject/issuer 相等的启发式，非签名验证
			tls["cert"] = map[string]any{
				"subject":     f.TlsCertSubject,
				"issuer":      f.TlsCertIssuer,
				"self_signed": f.TlsCertSelfSigned,
				"not_before":  f.TlsCertNotBefore,
				"not_after":   f.TlsCertNotAfter,
			}
		}
		body["tls"] = tls
	}
	if f.HttpHost != "" || f.HttpUri != "" {
		body["http_request"] = map[string]any{
			"hostname":   f.HttpHost,
			"url":        map[string]any{"path": f.HttpUri},
			"user_agent": f.HttpUserAgent,
		}
	}
	data, _ := json.Marshal(body)
	return data
}
