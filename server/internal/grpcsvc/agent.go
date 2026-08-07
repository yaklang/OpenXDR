// Package grpcsvc 实现 agent 专属 gRPC 通道：注册 + 事件流上报。
package grpcsvc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/sigma"
	"openxdr/server/pb"
)

type Server struct {
	pb.UnimplementedAgentServiceServer
	DB          *ent.Client
	Rules       *sigma.Engine
	DedupWindow time.Duration
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
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
	return &pb.RegisterResponse{AgentId: agentID.String()}, nil
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
	var lastDropped uint64
	var eventCreates []*ent.EventCreate
	var alertCreates []*ent.AlertCreate

	// 一条流对应一台主机，告警指纹 (rule_id, asset_id) 在流内就是 rule_id
	dedup := newDeduper(s.DedupWindow)

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
		return dedup.flush(ctx, s.DB)
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

		for _, rule := range s.Rules.Evaluate(int(ev.ClassUid), rawMap) {
			if dedup.hit(rule.ID, ts) {
				continue
			}
			alertID := uuid.Must(uuid.NewV7())
			alertCreates = append(alertCreates, s.DB.Alert.Create().
				SetID(alertID).
				SetTs(ts).
				SetRuleID(rule.ID).
				SetSeverity(rule.Severity).
				SetEventID(eventID).
				SetNillableAssetID(assetID).
				SetLastTs(ts))
			dedup.track(rule.ID, alertID, ts)
		}

		// 长连接流，攒批落库
		if received++; received%batchSize == 0 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
}
