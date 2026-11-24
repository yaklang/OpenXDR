// Package grpcsvc 实现 agent 专属 gRPC 通道：注册 + 事件流上报。
package grpcsvc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/enroll"
	"openxdr/server/internal/eventbus"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sshkeys"
	"openxdr/server/internal/suppress"
	"openxdr/server/pb"
)

type Server struct {
	pb.UnimplementedAgentServiceServer
	DB *ent.Client
	// LXC 名字 → 同名资产，见 guest.go
	guests guestCache
	// SQL 与 Suppress 供未注入 SSHKeys 服务时的兜底构造使用，见 sshkeys.go
	SQL      *sql.DB
	Hub      *response.Hub
	Suppress *suppress.Store
	Events   eventbus.Bus
	// agent 安装包与自动升级开关
	Dist        *enroll.Dist
	AutoUpgrade bool
	SSHKeys     *sshkeys.Service
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// 绑定证书只能注册自己的主机名，防止认领他人身份拿走 agent_id
	if host, bound := certHostname(ctx); bound && host != req.Hostname {
		return nil, status.Error(codes.PermissionDenied, "hostname 与证书绑定的主机不符")
	}
	a, err := s.DB.Asset.Query().Where(asset.HostnameEQ(req.Hostname)).First(ctx)
	if ent.IsNotFound(err) {
		a, err = s.DB.Asset.Create().SetHostname(req.Hostname).Save(ctx)
	}
	if err != nil {
		return nil, err
	}
	// 下线的主机接不回来：没有证书吊销，旧证书只能在这里挡住。要回来得用接入令牌重新接入
	if a.RetiredAt != nil {
		return nil, status.Error(codes.PermissionDenied, "主机已下线，需用接入令牌重新接入")
	}

	agentID := uuid.Must(uuid.NewV7())
	if a.AgentID != nil {
		agentID = *a.AgentID
	}
	if err := a.Update().
		SetOs(req.Os).
		SetAgentID(agentID).
		SetIPAddrs(req.IpAddrs).
		SetAgentVersion(req.AgentVersion).
		SetLastSeen(time.Now()).
		Exec(ctx); err != nil {
		return nil, err
	}
	// 采集配置随注册下发：agent 断线重连会重新注册，改配置最迟一次重连后生效
	resp := &pb.RegisterResponse{
		AgentId:    agentID.String(),
		ConfigJson: string(a.Config),
	}
	if s.Hub != nil {
		resp.CommandSigner = s.Hub.SignerPublic()
	}
	// 自动升级：分发目录里的版本与 agent 自身不同就让它换。不报哈希的老 agent 不会升级，也不会被要求
	if platform := s.Dist.Platform(req.Os, req.Arch); s.AutoUpgrade && req.BinarySha256 != "" && platform != "" {
		if want := s.Dist.SHA256(platform); want != "" && want != req.BinarySha256 {
			resp.UpgradeSha256, resp.UpgradePlatform = want, platform
			resp.UpgradeSignature = s.Dist.Signature(platform)
			slog.Info("下发 agent 升级", "host", req.Hostname, "from", req.AgentVersion, "platform", platform)
		}
	}
	return resp, nil
}

// downloadChunk 每块 256 KiB，远小于 gRPC 默认的 4 MiB 消息上限
const downloadChunk = 256 << 10

// DownloadAgent 分块推送安装包。哈希不符说明分发目录刚换了版本，拒绝后 agent 下次注册拿新哈希重来。
func (s *Server) DownloadAgent(req *pb.DownloadRequest, stream pb.AgentService_DownloadAgentServer) error {
	return sendDist(s.Dist, req.Platform, req.Sha256, func(b []byte) error {
		return stream.Send(&pb.AgentChunk{Data: b})
	})
}

// sendDist agent 与 sensor 共用的分块下载：只发与期望哈希一致的安装包。
func sendDist(dist *enroll.Dist, platform, sha256 string, send func([]byte) error) error {
	if want := dist.SHA256(platform); want == "" || want != sha256 {
		return status.Error(codes.FailedPrecondition, "分发版本已变化或不存在")
	}
	f, err := dist.Open(platform)
	if err != nil {
		return status.Error(codes.NotFound, "安装包不存在")
	}
	defer f.Close()
	buf := make([]byte, downloadChunk)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if serr := send(buf[:n]); serr != nil {
				return serr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
	}
}

// 定时冲刷未满批的事件，避免低流量 agent 长时间积压在内存里。
const flushInterval = 2 * time.Second

func (s *Server) ReportEvents(stream pb.AgentService_ReportEventsServer) error {
	ctx := stream.Context()
	recvCh := recvAgentEvents(ctx, stream)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	st := &agentStream{
		s: s, ctx: ctx,
		verifiedIDs: map[string]bool{},
	}
	for {
		select {
		case <-ticker.C:
			if err := st.flush(); err != nil {
				return err
			}
		case result, ok := <-recvCh:
			if !ok {
				return ctx.Err()
			}
			if errors.Is(result.err, io.EOF) {
				if err := st.flush(); err != nil {
					return err
				}
				return stream.SendAndClose(&pb.ReportAck{Received: st.received})
			}
			if result.err != nil {
				_ = st.flush() // 断流前尽力保住已收的
				return result.err
			}
			if err := st.handle(result.ev); err != nil {
				return err
			}
		}
	}
}

type recvResult struct {
	ev  *pb.AgentEvent
	err error
}

// recvAgentEvents stream.Recv 是阻塞调用，挪进 goroutine 才能和定时 flush 一起 select
func recvAgentEvents(ctx context.Context, stream pb.AgentService_ReportEventsServer) <-chan recvResult {
	recvCh := make(chan recvResult)
	go func() {
		defer close(recvCh)
		for {
			ev, err := stream.Recv()
			select {
			case recvCh <- recvResult{ev, err}:
				if err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return recvCh
}

// agentStream 一条上报流的状态，只在 ReportEvents 的循环里单线程使用。
type agentStream struct {
	s           *Server
	ctx         context.Context
	received    uint64
	assetID     *uuid.UUID
	assetOS     string
	lastDropped uint64
	// 每个 agent_id 首次出现时核对证书身份，之后放行；假 id 直接断流
	verifiedIDs  map[string]bool
	queuedEvents []ingest.Envelope
	queuedBytes  int
}

func (st *agentStream) flush() error {
	if len(st.queuedEvents) == 0 {
		return nil
	}
	if err := eventbus.PublishBatch(st.ctx, st.s.Events, st.queuedEvents); err != nil {
		return status.Errorf(codes.Unavailable, "事件入队失败: %v", err)
	}
	st.received += uint64(len(st.queuedEvents))
	st.queuedEvents = nil
	st.queuedBytes = 0
	return nil
}

// handle 处理一条事件并写入事件队列。
func (st *agentStream) handle(ev *pb.AgentEvent) error {
	if err := st.verify(ev); err != nil {
		return err
	}

	// 累计值只在增长时报，避免每条事件刷屏
	if ev.DroppedEvents > st.lastDropped {
		slog.Warn("agent 采集队列溢出",
			"agent", ev.AgentId, "dropped", ev.DroppedEvents)
		st.lastDropped = ev.DroppedEvents
	}

	if st.assetID == nil {
		st.resolveAsset(ev.AgentId)
	}

	raw := json.RawMessage(ev.RawJson)
	var rawMap map[string]any
	if json.Unmarshal(raw, &rawMap) != nil {
		raw = json.RawMessage("{}")
		rawMap = map[string]any{}
	}

	return st.publish(ev, raw, rawMap, time.Unix(0, ev.TsUnixNs))
}

// verify 每个 agent_id 首次出现时核对证书身份。
func (st *agentStream) verify(ev *pb.AgentEvent) error {
	if st.verifiedIDs[ev.AgentId] {
		return nil
	}
	id, err := uuid.Parse(ev.AgentId)
	if err != nil {
		return status.Error(codes.InvalidArgument, "agent_id 不是合法 UUID")
	}
	if err := st.s.verifyAgentID(st.ctx, id); err != nil {
		_ = st.flush() // 断流前保住此前已核验的事件
		return err
	}
	st.verifiedIDs[ev.AgentId] = true
	return nil
}

// resolveAsset 按 agent_id 找到所属资产；找不到下条事件再试。
func (st *agentStream) resolveAsset(agentID string) {
	agentGUID, err := uuid.Parse(agentID)
	if err != nil {
		return
	}
	a, err := st.s.DB.Asset.Query().Where(asset.AgentIDEQ(agentGUID), asset.RetiredAtIsNil()).First(st.ctx)
	if err != nil {
		return
	}
	st.assetID = &a.ID
	if a.Os != nil {
		st.assetOS = strings.ToLower(*a.Os)
	}
}

// fileFingerprintSuffix 文件事件的实体键是路径：同一规则命中不同文件是不同的事，不能被合并；
// 进程/网络事件保持粗指纹，那正是防告警风暴的设计
func fileFingerprintSuffix(classUID uint32, rawMap map[string]any) string {
	if classUID != 1001 {
		return ""
	}
	if f, ok := rawMap["file"].(map[string]any); ok {
		if p, ok := f["path"].(string); ok {
			return "|" + p
		}
	}
	return ""
}

// publish 事件入队，检测与落库交给队列消费端。
func (st *agentStream) publish(ev *pb.AgentEvent, raw json.RawMessage, rawMap map[string]any, ts time.Time) error {
	if st.s.Events == nil {
		return status.Error(codes.Unavailable, "事件总线未配置")
	}
	assetID, assetOS, raw := st.attribute(raw, rawMap)
	partitionKey := ev.AgentId
	if assetID != nil {
		partitionKey = assetID.String()
	}
	var processGUID, parentGUID *uuid.UUID
	if id, parseErr := uuid.Parse(ev.ProcessGuid); parseErr == nil {
		processGUID = &id
	}
	if id, parseErr := uuid.Parse(ev.ParentProcessGuid); parseErr == nil {
		parentGUID = &id
	}
	eventID := ingest.StableID(ev.AgentId, strconv.FormatInt(ev.TsUnixNs, 10),
		strconv.FormatUint(uint64(ev.ClassUid), 10), ev.ProcessGuid, ev.ParentProcessGuid,
		ev.ConnTuple, string(raw))
	envelope := ingest.Envelope{
		Version: ingest.EnvelopeVersion, ID: eventID, PartitionKey: partitionKey,
		Timestamp: ts, ClassUID: int(ev.ClassUid), Source: "agent", AssetID: assetID,
		AssetOS: assetOS, ProcessGUID: processGUID, ParentProcessGUID: parentGUID,
		Username: ev.Username, ConnTuple: ev.ConnTuple, FingerprintSuffix: fileFingerprintSuffix(ev.ClassUid, rawMap),
		Raw: sanitizeRawJSON(raw),
	}
	st.queuedEvents = append(st.queuedEvents, envelope)
	st.queuedBytes += len(envelope.Raw)
	if len(st.queuedEvents) >= eventbus.BatchSize(st.s.Events) || st.queuedBytes >= 256<<10 {
		return st.flush()
	}
	return nil
}
