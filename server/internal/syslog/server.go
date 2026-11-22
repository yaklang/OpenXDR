package syslog

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/dedup"
	"openxdr/server/internal/eventbus"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/redact"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

// ClassApplicationActivity 应用日志事件的 class。
// OCSF 尚未给通用 syslog 定义类别，这里用私有段编号，
// 换成标准编号时只需改这一处和 sigma 的 categoryMap。
const ClassApplicationActivity = 100001

// 单条报文长度上限，超出截断。UDP 侧同时是读缓冲大小
const maxMessageLen = 64 * 1024

// 攒批落库与网络保护阈值
const (
	batchSize            = 500
	flushInterval        = 2 * time.Second
	maxTCPConns          = 256
	tcpIdleTimeout       = 2 * time.Minute
	shutdownFlushTimeout = 5 * time.Second
	defaultAssetCacheTTL = 30 * time.Second
)

type assetRef struct {
	id uuid.UUID
	os string
}

type assetIndex struct {
	mu     sync.RWMutex
	byIP   map[string]assetRef
	byHost map[string]assetRef
	at     time.Time
}

type Server struct {
	monitor       monitor
	assets        assetIndex
	DB            *ent.Client
	Rules         sigma.Catalog
	Addr          string
	DedupWindow   time.Duration
	Suppress      *suppress.Store
	Intel         *intel.Store
	Events        eventbus.Bus
	TrustedRelays []string // 允许按报文 hostname 归属的受信 syslog 转发器 IP

	// 测试覆写项；零值使用默认常量
	maxConns      int
	idleTimeout   time.Duration
	assetCacheTTL time.Duration
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
		s.listening(false, false, err)
		slog.Error("Syslog UDP 监听失败", "addr", s.Addr, "err", err)
		return
	}
	defer conn.Close()
	s.listening(false, true, nil)
	defer s.listening(false, false, nil)
	slog.Info("Syslog UDP 启动", "addr", s.Addr)
	go func() { <-ctx.Done(); conn.Close() }()

	buf := make([]byte, maxMessageLen)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		// 队列满时丢弃，绝不阻塞收包
		s.receive(queue, incoming{line: string(buf[:n]), from: addrIP(addr)})
	}
}

func (s *Server) tcpLimit() int {
	if s.maxConns > 0 {
		return s.maxConns
	}
	return maxTCPConns
}

func (s *Server) tcpIdle() time.Duration {
	if s.idleTimeout > 0 {
		return s.idleTimeout
	}
	return tcpIdleTimeout
}

func (s *Server) cacheTTL() time.Duration {
	if s.assetCacheTTL > 0 {
		return s.assetCacheTTL
	}
	return defaultAssetCacheTTL
}

func (s *Server) listenTCP(ctx context.Context, queue chan<- incoming) {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		s.listening(true, false, err)
		slog.Error("Syslog TCP 监听失败", "addr", s.Addr, "err", err)
		return
	}
	defer ln.Close()
	s.listening(true, true, nil)
	defer s.listening(true, false, nil)
	slog.Info("Syslog TCP 启动", "addr", s.Addr)

	var (
		mu     sync.Mutex
		active = map[net.Conn]struct{}{}
		closed bool
		wg     sync.WaitGroup
	)
	go func() {
		<-ctx.Done()
		ln.Close()
		mu.Lock()
		closed = true
		for c := range active {
			c.Close()
		}
		mu.Unlock()
	}()
	defer wg.Wait()

	limit := s.tcpLimit()
	idle := s.tcpIdle()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		mu.Lock()
		wasClosed := closed
		if wasClosed || len(active) >= limit {
			mu.Unlock()
			conn.Close()
			if !wasClosed {
				slog.Warn("Syslog TCP 连接数达到上限，已拒绝新连接", "limit", limit, "remote", conn.RemoteAddr())
			}
			continue
		}
		active[conn] = struct{}{}
		mu.Unlock()

		wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				mu.Lock()
				delete(active, c)
				mu.Unlock()
				c.Close()
				wg.Done()
			}()
			ip := addrIP(c.RemoteAddr())
			scanner := bufio.NewScanner(c)
			scanner.Buffer(make([]byte, 4096), maxMessageLen)
			_ = c.SetReadDeadline(time.Now().Add(idle))
			for scanner.Scan() {
				s.receive(queue, incoming{line: scanner.Text(), from: ip})
				_ = c.SetReadDeadline(time.Now().Add(idle))
			}
		}(conn)
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
	flush := func(fctx context.Context) {
		if len(events) > 0 {
			if _, err := s.DB.Event.CreateBulk(events...).Save(fctx); err != nil {
				slog.Error("Syslog 事件落库失败", "err", err)
			}
			events = nil
		}
		if len(alerts) > 0 {
			if _, err := s.DB.Alert.CreateBulk(alerts...).Save(fctx); err != nil {
				slog.Error("Syslog 告警落库失败", "err", err)
			}
			alerts = nil
		}
		if err := deduper.Flush(fctx, s.DB); err != nil {
			slog.Error("Syslog 告警计数更新失败", "err", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			// 停机时使用独立短超时上下文，确保最后一批事件、告警与计数能落库
			fctx, cancel := context.WithTimeout(context.Background(), shutdownFlushTimeout)
			flush(fctx)
			cancel()
			return
		case <-ticker.C:
			flush(ctx)
		case in := <-queue:
			if s.Events != nil {
				err := s.enqueue(ctx, in)
				s.published(err)
				if err != nil {
					slog.Error("Syslog 事件入队失败", "err", err)
				}
				continue
			}
			e, a := s.build(ctx, in, deduper)
			events = append(events, e)
			alerts = append(alerts, a...)
			if len(events) >= batchSize {
				flush(ctx)
			}
		}
	}
}

func (s *Server) enqueue(ctx context.Context, in incoming) error {
	msg := Parse(in.line, time.Now())
	msg.Content = redact.String(msg.Content)
	assetID, assetOS := s.resolveAsset(ctx, msg.Hostname, in.from)
	if assetID == nil {
		s.unassigned()
	}
	raw, _ := json.Marshal(map[string]any{
		"activity_id": 1, "severity_id": msg.Severity, "message": msg.Content,
		"metadata": map[string]any{"product": map[string]any{"name": msg.AppName}, "log_name": msg.MsgID},
		"actor":    map[string]any{"process": map[string]any{"pid": msg.ProcID}},
		"device":   map[string]any{"hostname": msg.Hostname}, "facility": msg.Facility,
	})
	raw = withAuditFields(withAuthSource(raw, msg), msg)
	origin := msg.Hostname
	if origin == "" && in.from != nil {
		origin = in.from.String()
	}
	partitionKey := origin
	if assetID != nil {
		partitionKey = assetID.String()
	}
	id := ingest.StableID("syslog", origin, msg.Ts.UTC().Format(time.RFC3339Nano), msg.AppName, msg.ProcID, msg.Content)
	return s.Events.Publish(ctx, ingest.Envelope{
		Version: ingest.EnvelopeVersion, ID: id, PartitionKey: partitionKey,
		Timestamp: msg.Ts, ClassUID: ClassApplicationActivity, Source: "syslog",
		AssetID: assetID, AssetOS: assetOS, Raw: raw,
	})
}

func (s *Server) build(ctx context.Context, in incoming, deduper *dedup.Deduper) (*ent.EventCreate, []*ent.AlertCreate) {
	msg := Parse(in.line, time.Now())
	msg.Content = redact.String(msg.Content)
	assetID, assetOS := s.resolveAsset(ctx, msg.Hostname, in.from)
	if assetID == nil {
		s.unassigned()
	}

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
	raw = withAuditFields(withAuthSource(raw, msg), msg)

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
	for _, h := range intel.Detections(s.Rules.Evaluate(ClassApplicationActivity, assetOS, rawMap), s.Intel.Match(rawMap, msg.Ts)) {
		if s.Suppress.Suppressed(h.RuleID, assetID, rawMap, msg.Ts) {
			continue
		}
		fingerprint := h.RuleID + "|" + origin
		if deduper.Hit(fingerprint, msg.Ts) {
			continue
		}
		alertID := uuid.Must(uuid.NewV7())
		created = append(created, s.DB.Alert.Create().
			SetID(alertID).
			SetTs(msg.Ts).
			SetRuleID(h.RuleID).
			SetSeverity(h.Severity).
			SetEventID(eventID).
			SetNillableAssetID(assetID).
			SetLastTs(msg.Ts))
		deduper.Track(fingerprint, alertID, msg.Ts)
	}
	return ec, created
}

// snapshotAssets 读取或刷新短期资产索引缓存（仅选归属所需字段，锁外查库避免阻塞）。
func (s *Server) snapshotAssets(ctx context.Context) (map[string]assetRef, map[string]assetRef) {
	now := time.Now()
	s.assets.mu.RLock()
	if !s.assets.at.IsZero() && now.Sub(s.assets.at) < s.cacheTTL() {
		byIP, byHost := s.assets.byIP, s.assets.byHost
		s.assets.mu.RUnlock()
		return byIP, byHost
	}
	s.assets.mu.RUnlock()

	if s.DB == nil {
		return nil, nil
	}
	rows, err := s.DB.Asset.Query().
		Where(asset.RetiredAtIsNil()).
		Select(asset.FieldID, asset.FieldHostname, asset.FieldOs, asset.FieldIPAddrs).
		All(ctx)
	if err != nil {
		// 查库失败时保留上次缓存（若有），避免短暂抖动导致全部日志丢失归属
		s.assets.mu.RLock()
		byIP, byHost := s.assets.byIP, s.assets.byHost
		s.assets.mu.RUnlock()
		return byIP, byHost
	}
	byIP := make(map[string]assetRef, len(rows))
	byHost := make(map[string]assetRef, len(rows))
	for _, a := range rows {
		ref := assetRef{id: a.ID, os: osOf(a)}
		if a.Hostname != "" {
			if _, exists := byHost[a.Hostname]; !exists {
				byHost[a.Hostname] = ref
			}
		}
		for _, addr := range a.IPAddrs {
			if addr != "" {
				if _, exists := byIP[addr]; !exists {
					byIP[addr] = ref
				}
			}
		}
	}
	s.assets.mu.Lock()
	s.assets.byIP, s.assets.byHost, s.assets.at = byIP, byHost, time.Now()
	s.assets.mu.Unlock()
	return byIP, byHost
}

// resolveAsset 优先按源 IP 归属资产（防止已知主机伪造报文 hostname 嫁祸他机）；
// 仅当源 IP 为受信转发器或未在资产表命中 IP 时，才按报文 hostname 匹配。两者都对不上就留空。
func (s *Server) resolveAsset(ctx context.Context, hostname string, from net.IP) (*uuid.UUID, string) {
	byIP, byHost := s.snapshotAssets(ctx)
	if from != nil {
		ip := from.String()
		if !slices.Contains(s.TrustedRelays, ip) {
			if ref, ok := byIP[ip]; ok {
				id := ref.id
				return &id, ref.os
			}
		}
	}
	if hostname != "" {
		if ref, ok := byHost[hostname]; ok {
			id := ref.id
			return &id, ref.os
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
