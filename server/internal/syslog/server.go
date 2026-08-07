package syslog

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/dedup"
	"openxdr/server/internal/sigma"
)

// ClassApplicationActivity 应用日志事件的 class。
// OCSF 尚未给通用 syslog 定义类别，这里用私有段编号，
// 换成标准编号时只需改这一处和 sigma 的 categoryMap。
const ClassApplicationActivity = 100001

// 单条报文长度上限，超出截断。UDP 侧同时是读缓冲大小
const maxMessageLen = 64 * 1024

// 攒批落库：满 batchSize 条或到 flushInterval 就写一次
const (
	batchSize     = 500
	flushInterval = 2 * time.Second
)

type Server struct {
	DB          *ent.Client
	Rules       *sigma.Engine
	Addr        string
	DedupWindow time.Duration
}

// 从网络收上来的一条报文，带来源地址用于归属资产
type incoming struct {
	line string
	from net.IP
}

func (s *Server) Run(ctx context.Context) {
	if s.Addr == "" {
		slog.Warn("Syslog 接入未启用：未配置 SYSLOG_ADDR")
		return
	}
	queue := make(chan incoming, 4096)

	go s.listenUDP(ctx, queue)
	go s.listenTCP(ctx, queue)
	s.consume(ctx, queue)
}

func (s *Server) listenUDP(ctx context.Context, queue chan<- incoming) {
	conn, err := net.ListenPacket("udp", s.Addr)
	if err != nil {
		slog.Error("Syslog UDP 监听失败", "addr", s.Addr, "err", err)
		return
	}
	defer conn.Close()
	slog.Info("Syslog UDP 启动", "addr", s.Addr)
	go func() { <-ctx.Done(); conn.Close() }()

	buf := make([]byte, maxMessageLen)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		// 队列满时丢弃，绝不阻塞收包
		select {
		case queue <- incoming{line: string(buf[:n]), from: addrIP(addr)}:
		default:
		}
	}
}

func (s *Server) listenTCP(ctx context.Context, queue chan<- incoming) {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		slog.Error("Syslog TCP 监听失败", "addr", s.Addr, "err", err)
		return
	}
	defer ln.Close()
	slog.Info("Syslog TCP 启动", "addr", s.Addr)
	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			ip := addrIP(conn.RemoteAddr())
			scanner := bufio.NewScanner(conn)
			scanner.Buffer(make([]byte, 4096), maxMessageLen)
			for scanner.Scan() {
				select {
				case queue <- incoming{line: scanner.Text(), from: ip}:
				default:
				}
			}
		}()
	}
}

// consume 单协程消费，攒批落库。多协程写同一批没有意义，反而要加锁。
func (s *Server) consume(ctx context.Context, queue <-chan incoming) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	// 一台主机反复报同一条日志（暴力破解、刷屏应用）只留一行告警并计数
	deduper := dedup.New(s.DedupWindow)

	var events []*ent.EventCreate
	var alerts []*ent.AlertCreate
	flush := func() {
		if len(events) > 0 {
			if _, err := s.DB.Event.CreateBulk(events...).Save(ctx); err != nil {
				slog.Error("Syslog 事件落库失败", "err", err)
			}
			events = nil
		}
		if len(alerts) > 0 {
			if _, err := s.DB.Alert.CreateBulk(alerts...).Save(ctx); err != nil {
				slog.Error("Syslog 告警落库失败", "err", err)
			}
			alerts = nil
		}
		if err := deduper.Flush(ctx, s.DB); err != nil {
			slog.Error("Syslog 告警计数更新失败", "err", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-ticker.C:
			flush()
		case in := <-queue:
			e, a := s.build(ctx, in, deduper)
			events = append(events, e)
			alerts = append(alerts, a...)
			if len(events) >= batchSize {
				flush()
			}
		}
	}
}

func (s *Server) build(ctx context.Context, in incoming, deduper *dedup.Deduper) (*ent.EventCreate, []*ent.AlertCreate) {
	msg := Parse(in.line, time.Now())
	assetID, assetOS := s.resolveAsset(ctx, msg.Hostname, in.from)

	raw, _ := json.Marshal(map[string]any{
		"activity_id": 1,
		"severity_id": msg.Severity,
		"message":     msg.Content,
		"metadata": map[string]any{
			"product":  map[string]any{"name": msg.AppName},
			"log_name": msg.MsgID,
		},
		"actor":    map[string]any{"process": map[string]any{"pid": msg.ProcID}},
		"device":   map[string]any{"hostname": msg.Hostname},
		"facility": msg.Facility,
	})

	eventID := uuid.Must(uuid.NewV7())
	ec := s.DB.Event.Create().
		SetID(eventID).
		SetTs(msg.Ts).
		SetClassUID(ClassApplicationActivity).
		SetSource("syslog").
		SetNillableAssetID(assetID).
		SetRaw(raw)

	var rawMap map[string]any
	_ = json.Unmarshal(raw, &rawMap)

	// 指纹带主机，不同主机的同类日志不能被合并成一条
	origin := msg.Hostname
	if origin == "" && in.from != nil {
		origin = in.from.String()
	}

	var created []*ent.AlertCreate
	for _, rule := range s.Rules.Evaluate(ClassApplicationActivity, assetOS, rawMap) {
		fingerprint := rule.ID + "|" + origin
		if deduper.Hit(fingerprint, msg.Ts) {
			continue
		}
		alertID := uuid.Must(uuid.NewV7())
		created = append(created, s.DB.Alert.Create().
			SetID(alertID).
			SetTs(msg.Ts).
			SetRuleID(rule.ID).
			SetSeverity(rule.Severity).
			SetEventID(eventID).
			SetNillableAssetID(assetID).
			SetLastTs(msg.Ts))
		deduper.Track(fingerprint, alertID, msg.Ts)
	}
	return ec, created
}

// resolveAsset 先按主机名匹配，再退回源 IP。两者都对不上就留空，
// 关联引擎会把这类告警归到统一的未归属 incident。
func (s *Server) resolveAsset(ctx context.Context, hostname string, from net.IP) (*uuid.UUID, string) {
	if hostname != "" {
		if a, err := s.DB.Asset.Query().Where(asset.HostnameEQ(hostname)).First(ctx); err == nil {
			return &a.ID, osOf(a)
		}
	}
	if from != nil {
		ip := from.String()
		assets, err := s.DB.Asset.Query().Where(asset.IPAddrsNotNil()).All(ctx)
		if err == nil {
			for _, a := range assets {
				for _, addr := range a.IPAddrs {
					if addr == ip {
						return &a.ID, osOf(a)
					}
				}
			}
		}
	}
	return nil, ""
}

func osOf(a *ent.Asset) string {
	if a.Os == nil {
		return ""
	}
	return strings.ToLower(*a.Os)
}

func addrIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	}
	return nil
}
