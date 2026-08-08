// Package grpcsvc 实现 agent 专属 gRPC 通道：注册 + 事件流上报。
package grpcsvc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/dedup"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/pb"
)

type Server struct {
	pb.UnimplementedAgentServiceServer
	DB          *ent.Client
	Rules       *sigma.Engine
	DedupWindow time.Duration
	Hub         *response.Hub
	Suppress    *suppress.Store
	Intel       *intel.Store
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
		SetLastSeen(time.Now()).
		Exec(ctx); err != nil {
		return nil, err
	}
	// 采集配置随注册下发：agent 断线重连会重新注册，改配置最迟一次重连后生效
	return &pb.RegisterResponse{
		AgentId:    agentID.String(),
		ConfigJson: string(a.Config),
	}, nil
}

// 攒批落库的两个触发条件：满 batchSize 条，或距上次落库超过 flushInterval。
// 只按条数会让低流量的 agent 长时间不落库，事件在 server 内存里干等。
const (
	batchSize     = 500
	flushInterval = 2 * time.Second
)

func (s *Server) ReportEvents(stream pb.AgentService_ReportEventsServer) error {
	ctx := stream.Context()

	// stream.Recv 是阻塞调用，挪进 goroutine 才能和定时 flush 一起 select
	type recvResult struct {
		ev  *pb.AgentEvent
		err error
	}
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

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	var received uint64
	var assetID *uuid.UUID
	var assetOS string
	var lastDropped uint64
	// 每个 agent_id 首次出现时核对证书身份，之后放行；假 id 直接断流
	verifiedIDs := map[string]bool{}
	var eventCreates []*ent.EventCreate
	var alertCreates []*ent.AlertCreate

	// 一条流对应一台主机，告警指纹 (rule_id, asset_id) 在流内就是 rule_id
	deduper := dedup.New(s.DedupWindow)

	flush := func() error {
		if len(eventCreates) > 0 {
			if _, err := s.DB.Event.CreateBulk(eventCreates...).Save(ctx); err != nil {
				return err
			}
			eventCreates = nil
		}
		if len(alertCreates) > 0 {
			if _, err := s.DB.Alert.CreateBulk(alertCreates...).Save(ctx); err != nil {
				return err
			}
			alertCreates = nil
		}
		return deduper.Flush(ctx, s.DB)
	}

	for {
		var ev *pb.AgentEvent
		select {
		case <-ticker.C:
			if err := flush(); err != nil {
				return err
			}
			continue
		case result, ok := <-recvCh:
			if !ok {
				return ctx.Err()
			}
			if errors.Is(result.err, io.EOF) {
				if err := flush(); err != nil {
					return err
				}
				return stream.SendAndClose(&pb.ReportAck{Received: received})
			}
			if result.err != nil {
				_ = flush() // 断流前尽力保住已收的
				return result.err
			}
			ev = result.ev
		}

		if !verifiedIDs[ev.AgentId] {
			id, err := uuid.Parse(ev.AgentId)
			if err != nil {
				return status.Error(codes.InvalidArgument, "agent_id 不是合法 UUID")
			}
			if err := s.verifyAgentID(ctx, id); err != nil {
				_ = flush() // 断流前保住此前已核验的事件
				return err
			}
			verifiedIDs[ev.AgentId] = true
		}

		// 累计值只在增长时报，避免每条事件刷屏
		if ev.DroppedEvents > lastDropped {
			slog.Warn("agent 采集队列溢出",
				"agent", ev.AgentId, "dropped", ev.DroppedEvents)
			lastDropped = ev.DroppedEvents
		}

		if assetID == nil {
			if agentGUID, err := uuid.Parse(ev.AgentId); err == nil {
				if a, err := s.DB.Asset.Query().Where(asset.AgentIDEQ(agentGUID)).First(ctx); err == nil {
					assetID = &a.ID
					if a.Os != nil {
						assetOS = strings.ToLower(*a.Os)
					}
				}
			}
		}

		raw := json.RawMessage(ev.RawJson)
		var rawMap map[string]any
		if json.Unmarshal(raw, &rawMap) != nil {
			raw = json.RawMessage("{}")
			rawMap = map[string]any{}
		}

		eventID := uuid.Must(uuid.NewV7())
		ts := time.Unix(0, ev.TsUnixNs)
		ec := s.DB.Event.Create().
			SetID(eventID).
			SetTs(ts).
			SetClassUID(int(ev.ClassUid)).
			SetSource("agent").
			SetNillableAssetID(assetID).
			SetRaw(raw)
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
		eventCreates = append(eventCreates, ec)

		// 文件事件的实体键是路径：同一规则命中不同文件是不同的事，不能被合并；
		// 进程/网络事件保持粗指纹，那正是防告警风暴的设计
		fpSuffix := ""
		if ev.ClassUid == 1001 {
			if f, ok := rawMap["file"].(map[string]any); ok {
				if p, ok := f["path"].(string); ok {
					fpSuffix = "|" + p
				}
			}
		}

		for _, h := range intel.Detections(s.Rules.Evaluate(int(ev.ClassUid), assetOS, rawMap), s.Intel.Match(rawMap, ts)) {
			// 抑制先于去重：被压掉的命中不该占用去重槽位
			if s.Suppress.Suppressed(h.RuleID, assetID, ts) {
				continue
			}
			fingerprint := h.RuleID + fpSuffix
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

		// 爆破得手跨事件升级：成功登录前的窗口内同用户多次失败。
		// 先 flush 让同批未落库的失败事件可见，再回查——成功登录稀少，不构成负担
		if int(ev.ClassUid) == classAuth && authStatus(rawMap) == authStatusSuccess &&
			assetID != nil && ev.Username != "" {
			if err := flush(); err != nil {
				return err
			}
			if s.countAuthFailures(ctx, *assetID, ev.Username, ts) >= bruteforceThreshold &&
				!s.Suppress.Suppressed(sigma.RuleBruteforceSuccess, assetID, ts) {
				fingerprint := sigma.RuleBruteforceSuccess + "|" + ev.Username
				if !deduper.Hit(fingerprint, ts) {
					alertID := uuid.Must(uuid.NewV7())
					alertCreates = append(alertCreates, s.DB.Alert.Create().
						SetID(alertID).
						SetTs(ts).
						SetRuleID(sigma.RuleBruteforceSuccess).
						SetSeverity(5).
						SetEventID(eventID).
						SetAssetID(*assetID).
						SetLastTs(ts))
					deduper.Track(fingerprint, alertID, ts)
				}
			}
		}

		// 长连接流，攒批落库
		if received++; received%batchSize == 0 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
}
