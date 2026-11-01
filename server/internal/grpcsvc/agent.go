// Package grpcsvc 实现 agent 专属 gRPC 通道：注册 + 事件流上报。
package grpcsvc

import (
	"context"
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
	"openxdr/server/internal/automation"
	"openxdr/server/internal/cmdorigin"
	"openxdr/server/internal/dedup"
	"openxdr/server/internal/enroll"
	"openxdr/server/internal/eventbus"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/pb"
)

type Server struct {
	pb.UnimplementedAgentServiceServer
	DB *ent.Client
	// SQL 核对平台指令标记与可信来源用；不配置时两者都不认，照常告警
	SQL interface {
		cmdorigin.Querier
		automation.Querier
	}
	Rules       sigma.Catalog
	DedupWindow time.Duration
	Hub         *response.Hub
	Suppress    *suppress.Store
	Intel       *intel.Store
	Events      eventbus.Bus
	// agent 安装包与自动升级开关
	Dist        *enroll.Dist
	AutoUpgrade bool
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
	// 自动升级：分发目录里的版本与 agent 自身不同就让它换。不报哈希的老 agent 不会升级，也不会被要求
	if platform := s.Dist.Platform(req.Os, req.Arch); s.AutoUpgrade && req.BinarySha256 != "" && platform != "" {
		if want := s.Dist.SHA256(platform); want != "" && want != req.BinarySha256 {
			resp.UpgradeSha256, resp.UpgradePlatform = want, platform
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

// 攒批落库的两个触发条件：满 batchSize 条，或距上次落库超过 flushInterval。
// 只按条数会让低流量的 agent 长时间不落库，事件在 server 内存里干等。
const (
	batchSize     = 500
	flushInterval = 2 * time.Second
)

func (s *Server) ReportEvents(stream pb.AgentService_ReportEventsServer) error {
	ctx := stream.Context()
	recvCh := recvAgentEvents(ctx, stream)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	st := &agentStream{
		s: s, ctx: ctx,
		verifiedIDs: map[string]bool{},
		deduper:     dedup.New(s.DedupWindow),
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
	eventCreates []*ent.EventCreate
	alertCreates []*ent.AlertCreate
	// 一条流对应一台主机，告警指纹 (rule_id, asset_id) 在流内就是 rule_id
	deduper *dedup.Deduper
}

func (st *agentStream) flush() error {
	if len(st.queuedEvents) > 0 {
		if err := eventbus.PublishBatch(st.ctx, st.s.Events, st.queuedEvents); err != nil {
			return status.Errorf(codes.Unavailable, "事件入队失败: %v", err)
		}
		st.received += uint64(len(st.queuedEvents))
		st.queuedEvents = nil
		st.queuedBytes = 0
	}
	if len(st.eventCreates) > 0 {
		if _, err := st.s.DB.Event.CreateBulk(st.eventCreates...).Save(st.ctx); err != nil {
			return err
		}
		st.eventCreates = nil
	}
	if len(st.alertCreates) > 0 {
		if _, err := st.s.DB.Alert.CreateBulk(st.alertCreates...).Save(st.ctx); err != nil {
			return err
		}
		st.alertCreates = nil
	}
	return st.deduper.Flush(st.ctx, st.s.DB)
}

// handle 处理一条事件：配了事件队列就入队，否则就地检测并攒批落库。
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

	ts := time.Unix(0, ev.TsUnixNs)
	if st.s.Events != nil {
		return st.publish(ev, raw, rawMap, ts)
	}
	eventID := uuid.Must(uuid.NewV7())
	st.queueEvent(ev, eventID, ts, raw)
	if err := st.detect(ev, eventID, rawMap, ts); err != nil {
		return err
	}
	if err := st.checkBruteforce(ev, eventID, rawMap, ts); err != nil {
		return err
	}

	// 长连接流，攒批落库
	if st.received++; st.received%batchSize == 0 {
		return st.flush()
	}
	return nil
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
	a, err := st.s.DB.Asset.Query().Where(asset.AgentIDEQ(agentGUID)).First(st.ctx)
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
	partitionKey := ev.AgentId
	if st.assetID != nil {
		partitionKey = st.assetID.String()
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
		Timestamp: ts, ClassUID: int(ev.ClassUid), Source: "agent", AssetID: st.assetID,
		AssetOS: st.assetOS, ProcessGUID: processGUID, ParentProcessGUID: parentGUID,
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

// queueEvent 事件加入待落库批次。
func (st *agentStream) queueEvent(ev *pb.AgentEvent, eventID uuid.UUID, ts time.Time, raw json.RawMessage) {
	ec := st.s.DB.Event.Create().
		SetID(eventID).
		SetTs(ts).
		SetClassUID(int(ev.ClassUid)).
		SetSource("agent").
		SetNillableAssetID(st.assetID).
		SetRaw(sanitizeRawJSON(raw))
	if pg, err := uuid.Parse(ev.ProcessGuid); err == nil {
		ec.SetProcessGUID(pg)
	}
	if ppg, err := uuid.Parse(ev.ParentProcessGuid); err == nil {
		ec.SetParentProcessGUID(ppg)
	}
	if ev.Username != "" {
		ec.SetUsername(ev.Username)
	}
	if ev.ConnTuple != "" {
		ec.SetConnTuple(ev.ConnTuple)
	}
	st.eventCreates = append(st.eventCreates, ec)
}

// detect 规则与情报命中，经抑制、去重后生成告警。
func (st *agentStream) detect(ev *pb.AgentEvent, eventID uuid.UUID, rawMap map[string]any, ts time.Time) error {
	fpSuffix := fileFingerprintSuffix(ev.ClassUid, rawMap)

	sigma.WithActor(rawMap, ev.Username)
	rules := st.s.Rules.Evaluate(int(ev.ClassUid), st.assetOS, rawMap)
	hits := intel.Detections(rules, st.s.Intel.Match(rawMap, ts))
	var command, source *uuid.UUID
	if len(hits) > 0 {
		var err error
		if command, err = cmdorigin.Of(st.ctx, st.s.SQL, rawMap, st.assetID, ts); err != nil {
			return status.Errorf(codes.Unavailable, "核对平台指令失败: %v", err)
		}
		// 平台指令优先，其次是登记的可信自动化来源
		if command == nil {
			if source, err = automation.Of(st.ctx, st.s.SQL, rawMap, st.assetID, ts); err != nil {
				return status.Errorf(codes.Unavailable, "核对可信来源失败: %v", err)
			}
		}
	}
	for _, h := range hits {
		// 抑制先于去重：被压掉的命中不该占用去重槽位
		if st.s.Suppress.Suppressed(h.RuleID, st.assetID, rawMap, ts) {
			continue
		}
		fingerprint := h.RuleID + fpSuffix
		if command != nil {
			fingerprint += "|cmd:" + command.String()
		}
		if source != nil {
			fingerprint += "|auto:" + source.String()
		}
		if st.deduper.Hit(fingerprint, ts) {
			continue
		}
		alertID := uuid.Must(uuid.NewV7())
		st.alertCreates = append(st.alertCreates, st.s.DB.Alert.Create().
			SetID(alertID).
			SetTs(ts).
			SetRuleID(h.RuleID).
			SetSeverity(h.Severity).
			SetEventID(eventID).
			SetNillableAssetID(st.assetID).
			SetNillableCommandID(command).
			SetNillableAutomationID(source).
			SetAutomationWatch(source != nil && automation.Watch(h.RuleID, rules)).
			SetLastTs(ts))
		st.deduper.Track(fingerprint, alertID, ts)
	}
	return nil
}

// checkBruteforce 爆破得手跨事件升级：成功登录前的窗口内同用户多次失败。
// 先 flush 让同批未落库的失败事件可见，再回查——成功登录稀少，不构成负担
func (st *agentStream) checkBruteforce(ev *pb.AgentEvent, eventID uuid.UUID, rawMap map[string]any, ts time.Time) error {
	if int(ev.ClassUid) != classAuth || authStatus(rawMap) != authStatusSuccess ||
		st.assetID == nil || ev.Username == "" {
		return nil
	}
	if err := st.flush(); err != nil {
		return err
	}
	if st.s.countAuthFailures(st.ctx, *st.assetID, ev.Username, ts) < bruteforceThreshold ||
		st.s.Suppress.Suppressed(sigma.RuleBruteforceSuccess, st.assetID, rawMap, ts) {
		return nil
	}
	fingerprint := sigma.RuleBruteforceSuccess + "|" + ev.Username
	if st.deduper.Hit(fingerprint, ts) {
		return nil
	}
	alertID := uuid.Must(uuid.NewV7())
	st.alertCreates = append(st.alertCreates, st.s.DB.Alert.Create().
		SetID(alertID).
		SetTs(ts).
		SetRuleID(sigma.RuleBruteforceSuccess).
		SetSeverity(5).
		SetEventID(eventID).
		SetAssetID(*st.assetID).
		SetLastTs(ts))
	st.deduper.Track(fingerprint, alertID, ts)
	return nil
}
