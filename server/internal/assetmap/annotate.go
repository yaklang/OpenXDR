package assetmap

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/assetlink"
	"openxdr/server/ent/processbaseline"
	"openxdr/server/ent/zone"
	"openxdr/server/internal/triage"
)

const (
	// 每轮最多标注几台，模型调用慢，别让一轮拖太久
	annotatePerRound = 3
	// 事实变了也至少隔这么久再标，避免依赖边抖动时反复调模型
	annotateDebounce = time.Hour
	maxPrograms      = 80
	maxPeers         = 40
	maxPublic        = 30
)

// Lockable 人工可改的标注字段；改过即锁定，AI 不再覆盖
var Lockable = []string{"role", "summary", "criticality"}

// Facts 喂给模型的事实。指纹只取相对稳定的部分：程序清单会随新进程不断增长，
// 公网目的地址经常变化，都不进指纹，否则会反复触发标注。
type Facts struct {
	Hostname  string   `json:"hostname"`
	OS        string   `json:"os"`
	IPs       []string `json:"ips"`
	Zone      Zone     `json:"zone"`
	Exposure  string   `json:"exposure"`
	Cloud     *Cloud   `json:"cloud,omitempty"`
	Listening []string `json:"listening"`
	// 端口表认不出、也还没有调查或人工结论的对外监听，请模型凭进程名与路径命名
	UnknownServices []string `json:"unknownServices,omitempty"`
	unknownKeys     []string
	// 本机主动连接的内网对端（主机名或 IP:端口 ← 进程）
	Outbound []string `json:"outbound"`
	// 连到本机的对端（主机名或 IP → 端口）
	Inbound []string `json:"inbound"`
	// 公网目的地址个数；连接量最多的 maxPublic 个连同反向解析与 VirusTotal 信息给模型认用途
	PublicDestinations int          `json:"publicDestinations"`
	Public             []PublicDest `json:"public,omitempty"`
	Programs           []string     `json:"programs"`
	// 模型给关系说明时只能引用这些对端
	Peers []string `json:"-"`
	// 按对端汇总的连接次数与最近一次时间，只给详情页看：次数一直在涨，进事实会让指纹天天变、反复触发标注
	OutboundDetails []string            `json:"-"`
	InboundDetails  []string            `json:"-"`
	OutboundStats   map[string]PeerStat `json:"-"`
	InboundStats    map[string]PeerStat `json:"-"`
}

// PeerStat 与一个对端之间的连接次数（各端口、进程合计）与最近一次时间
type PeerStat struct {
	Count    int64     `json:"count"`
	LastSeen time.Time `json:"lastSeen"`
}

func addStat(m map[string]PeerStat, peer string, count int64, last time.Time) {
	s := m[peer]
	s.Count += count
	if last.After(s.LastSeen) {
		s.LastSeen = last
	}
	m[peer] = s
}

func (f Facts) fingerprint() string {
	h := sha256.New()
	_ = json.NewEncoder(h).Encode([]any{f.Hostname, f.OS, f.Zone.Kind, f.Zone.Name, f.Exposure, f.Cloud, f.Listening, f.Outbound, f.Inbound, f.UnknownServices})
	return hex.EncodeToString(h.Sum(nil))
}

// annotateDue 人工要求的、刚入库从没标过的每轮都处理；事实变化与定时刷新要逐台重算指纹，
// 按 checkEvery 周期做。失败的资产隔一个周期再试，模型出问题时不至于每分钟打一遍
func (e *Engine) annotateDue(ctx context.Context) {
	requested, err := e.DB.Asset.Query().Where(asset.AnnotateRequestedAtNotNil()).All(ctx)
	if err != nil {
		slog.Error("读取待标注资产失败", "err", err)
		return
	}
	// 刚接入时清单还没到，只凭主机名标注等于让模型猜：等清单到了，最多等一个检查周期
	fresh, err := e.DB.Asset.Query().Where(asset.AnnotatedAtIsNil(), asset.AnnotateRequestedAtIsNil(),
		asset.Or(asset.InventoryAtNotNil(), asset.FirstSeenLT(time.Now().Add(-checkEvery)))).
		Order(ent.Asc(asset.FieldFirstSeen)).All(ctx)
	if err != nil {
		slog.Error("读取待标注资产失败", "err", err)
		return
	}
	var todo []*ent.Asset
	for _, a := range append(requested, fresh...) {
		if len(todo) < annotatePerRound && (a.AnnotateRequestedAt != nil || time.Since(e.failed[a.ID]) >= checkEvery) {
			todo = append(todo, a)
		}
	}
	check := time.Since(e.lastCheck) >= checkEvery
	if len(todo) == 0 && !check {
		return
	}
	w, err := LoadWorld(ctx, e.DB)
	if err != nil {
		slog.Error("读取资产失败", "err", err)
		return
	}
	if check {
		e.lastCheck = time.Now()
		for _, a := range w.Assets {
			if len(todo) == annotatePerRound {
				break
			}
			if a.AnnotatedAt == nil || a.AnnotateRequestedAt != nil || time.Since(e.failed[a.ID]) < checkEvery {
				continue
			}
			due, err := e.due(ctx, w, a)
			if err != nil {
				slog.Error("计算资产事实失败", "host", a.Hostname, "err", err)
				continue
			}
			if due {
				todo = append(todo, a)
			}
		}
	}
	for _, a := range todo {
		if err := e.annotate(ctx, w, a); err != nil {
			slog.Warn("资产标注失败", "host", a.Hostname, "err", err)
			if e.failed == nil {
				e.failed = map[uuid.UUID]time.Time{}
			}
			e.failed[a.ID] = time.Now()
			_ = e.DB.Asset.UpdateOneID(a.ID).ClearAnnotateRequestedAt().Exec(ctx)
		}
	}
}

func (e *Engine) due(ctx context.Context, w *World, a *ent.Asset) (bool, error) {
	if e.Refresh > 0 && time.Since(*a.AnnotatedAt) >= e.Refresh {
		return true, nil
	}
	if time.Since(*a.AnnotatedAt) < annotateDebounce {
		return false, nil
	}
	f, err := FactsOf(ctx, e.DB, w, a)
	if err != nil {
		return false, err
	}
	return a.AnnotatedFacts == nil || *a.AnnotatedFacts != f.fingerprint(), nil
}

// FactsOf 汇总一台资产的事实：清单、区域、内外依赖与见过的程序
func FactsOf(ctx context.Context, db *ent.Client, w *World, a *ent.Asset) (Facts, error) {
	var zones []*ent.Zone
	if a.GroupID != nil {
		var err error
		if zones, err = db.Zone.Query().Where(zone.GroupIDEQ(*a.GroupID)).All(ctx); err != nil {
			return Facts{}, err
		}
	}
	z, exposure := ZoneOf(a, zones)
	f := Facts{Hostname: a.Hostname, IPs: a.IPAddrs, Zone: z, Exposure: exposure, Cloud: cloudOf(a),
		OutboundStats: map[string]PeerStat{}, InboundStats: map[string]PeerStat{}}
	if a.Os != nil {
		f.OS = *a.Os
	}
	for _, l := range listenersOf(a) {
		s := fmt.Sprintf("%s/%d %s", l.Proto, l.Port, l.Process)
		if l.Loopback() {
			s += "（仅本机）"
		}
		f.Listening = append(f.Listening, strings.TrimSpace(s))
	}
	notes := NotesOf(a)
	for _, l := range listenersOf(a) {
		key := serviceKey(l.Proto, l.Port)
		if l.Loopback() || ServiceOf(l.Proto, l.Port).Name != "" || slices.Contains(f.unknownKeys, key) || sourceRank[notes[key].Source] > sourceRank["ai"] {
			continue
		}
		f.unknownKeys = append(f.unknownKeys, key)
		f.UnknownServices = append(f.UnknownServices, strings.TrimSpace(key+" "+l.Process+" "+l.Path))
	}

	label := func(ip string) string {
		if addr, err := netip.ParseAddr(ip); err == nil {
			if peer := w.ByIP[addr]; peer != nil {
				return peer.Hostname
			}
		}
		return ip
	}
	since := time.Now().Add(-linkTTL)
	out, err := db.AssetLink.Query().Where(assetlink.SrcAssetIDEQ(a.ID), assetlink.LastSeenGT(since)).All(ctx)
	if err != nil {
		return Facts{}, err
	}
	public := map[string]bool{}
	var publicHits []hit
	// 同一对端端口合成一条，进程并列；有已知进程就不再写「?」（旧版 agent 留下的边没有进程名）
	procs := map[string][]string{}
	for _, l := range out {
		if addr, err := netip.ParseAddr(l.DstIP); err == nil && Public(addr) && w.ByIP[addr] == nil {
			public[l.DstIP] = true
			publicHits = append(publicHits, hitOf(l, l.DstIP))
			continue
		}
		peer := label(l.DstIP)
		target := fmt.Sprintf("%s:%d", peer, l.DstPort)
		if l.Process != "" && !slices.Contains(procs[target], l.Process) {
			procs[target] = append(procs[target], l.Process)
		} else if procs[target] == nil {
			procs[target] = []string{}
		}
		f.Peers = append(f.Peers, peer)
		addStat(f.OutboundStats, peer, l.Count, l.LastSeen)
	}
	for target, names := range procs {
		slices.Sort(names)
		f.Outbound = append(f.Outbound, target+" ← "+cmp.Or(strings.Join(names, ", "), "?"))
	}
	f.PublicDestinations = len(public)
	info, err := loadInfo(ctx, db, slices.Collect(maps.Keys(public)))
	if err != nil {
		return Facts{}, err
	}
	f.Public = publicDests(publicHits, info, maxPublic)
	in, err := db.AssetLink.Query().Where(assetlink.DstIPIn(a.IPAddrs...), assetlink.LastSeenGT(since)).All(ctx)
	if err != nil {
		return Facts{}, err
	}
	for _, l := range in {
		peer := label(l.SrcIP)
		if p := w.ByID[ptr(l.SrcAssetID)]; p != nil {
			peer = p.Hostname
		}
		f.Inbound = append(f.Inbound, fmt.Sprintf("%s → %d", peer, l.DstPort))
		f.Peers = append(f.Peers, peer)
		addStat(f.InboundStats, peer, l.Count, l.LastSeen)
	}
	// 详情页保留全部关系；模型事实仍按名称稳定截断，计数变化不影响指纹。
	slices.Sort(f.Outbound)
	slices.Sort(f.Inbound)
	f.OutboundDetails = slices.Compact(f.Outbound)
	f.InboundDetails = slices.Compact(f.Inbound)
	f.Outbound, f.Inbound, f.Peers = capSorted(f.OutboundDetails), capSorted(f.InboundDetails), capSorted(f.Peers)

	programs, err := db.ProcessBaseline.Query().Where(processbaseline.AssetIDEQ(a.ID)).
		Order(ent.Asc(processbaseline.FieldFirstSeen)).Limit(maxPrograms).All(ctx)
	if err != nil {
		return Facts{}, err
	}
	for _, p := range programs {
		f.Programs = append(f.Programs, p.ExePath)
	}
	return f, nil
}

// capSorted 去重、排序、截断，保证指纹稳定
func capSorted(s []string) []string {
	slices.Sort(s)
	s = slices.Compact(s)
	if len(s) > maxPeers {
		s = s[:maxPeers]
	}
	return s
}

const annotatePrompt = `你是资产梳理助手。根据给出的一台主机的事实（监听端口、对内对外的依赖、见过的程序、所在区域），判断它是做什么的、有多重要。
只依据事实判断，事实不足就说明不足，不要编造服务或业务。
重要程度 criticality 取 1-5：
5 核心：失陷或宕机影响全局，如域控、核心数据库、虚拟化宿主机、堡垒机、CI/CD、备份、安全与监控平台；
4 重要业务系统或被多台主机依赖的服务；
3 一般业务；
2 辅助、开发测试；
1 临时或无业务。
只输出一个 JSON 对象，不要其他文字：
{"role":"不超过 16 字的角色，如 PostgreSQL 数据库","summary":"不超过 120 字的功能说明","criticality":1-5,"reason":"不超过 150 字的重要程度依据","relations":[{"peer":"对端，必须原样取自 outbound 或 inbound 里的主机名或 IP","note":"不超过 30 字的关系说明，如 读写业务库"}],"services":[{"port":"原样取自 unknownServices 开头的 协议/端口","name":"不超过 16 字的服务名，如 Corosync 集群通信","note":"不超过 60 字的用途"}]}
services 只为 unknownServices 里的端口命名；凭进程名与路径认不出就不要写，不要猜。
public 是本机连过的公网地址（按连接量取前若干个），带端口、发起进程、反向解析 ptr、VirusTotal 给的归属 owner、国家 country、
判恶意的引擎数 malicious 与历史解析域名 domains。在上面的 JSON 里再加一个字段为认得出的地址写用途：
"egress":[{"ip":"原样取自 public 的 ip","purpose":"不超过 20 字的用途，如 Debian 软件源、Tailscale 中继、NTP 授时"}]
只依据进程名、端口、域名与归属判断，依据不足的地址不要写；malicious 大于 0 的在用途里照实写明可疑。`

// Annotation 模型给出的标注，已校验
type Annotation struct {
	Role        string            `json:"role"`
	Summary     string            `json:"summary"`
	Criticality int               `json:"criticality"`
	Reason      string            `json:"reason"`
	Relations   map[string]string `json:"relations"`
	Services    map[string]ServiceNote
}

func (e *Engine) annotate(ctx context.Context, w *World, a *ent.Asset) error {
	f, err := FactsOf(ctx, e.DB, w, a)
	if err != nil {
		return err
	}
	facts, _ := json.Marshal(f)
	reply, err := e.LLM.Chat(ctx, []triage.Message{
		{Role: "system", Content: annotatePrompt},
		{Role: "user", Content: string(facts)},
	}, nil)
	if err != nil {
		return err
	}
	ips := make([]string, len(f.Public))
	for i, d := range f.Public {
		ips[i] = d.IP
	}
	ann, err := parseAnnotation(reply.Content, f.Peers, f.unknownKeys, ips)
	if err != nil {
		return err
	}
	// 只覆盖 AI 自己写过的说明；调查与人工结论排在前面，不受影响
	for key, n := range ann.Services {
		if err := SetServiceNote(ctx, e.DB, a.ID, key, n); err != nil && !IsLowerSource(err) {
			return err
		}
	}
	locked := func(field string) bool { return slices.Contains(a.LockedFields, field) }
	upd := e.DB.Asset.UpdateOneID(a.ID).
		SetRelationNotes(ann.Relations).
		SetAnnotatedAt(time.Now()).
		SetAnnotatedFacts(f.fingerprint()).
		ClearAnnotateRequestedAt()
	if !locked("role") {
		upd.SetRole(ann.Role)
	}
	if !locked("summary") {
		upd.SetSummary(ann.Summary)
	}
	if !locked("criticality") {
		upd.SetCriticality(ann.Criticality).SetAnnotationReason(ann.Reason)
	}
	return upd.Exec(ctx)
}

// parseAnnotation 模型输出不可信：取第一个 JSON 对象，逐字段校验与截断，
// 关系说明只保留事实里出现过的对端，公网用途只保留 public 里给过的地址（同记在关系说明里，键是地址）
func parseAnnotation(answer string, peers, unknown, public []string) (Annotation, error) {
	start, end := strings.Index(answer, "{"), strings.LastIndex(answer, "}")
	if start < 0 || end <= start {
		return Annotation{}, fmt.Errorf("输出不含 JSON")
	}
	var raw struct {
		Role        string `json:"role"`
		Summary     string `json:"summary"`
		Criticality int    `json:"criticality"`
		Reason      string `json:"reason"`
		Relations   []struct {
			Peer string `json:"peer"`
			Note string `json:"note"`
		} `json:"relations"`
		Services []struct {
			Port string `json:"port"`
			Name string `json:"name"`
			Note string `json:"note"`
		} `json:"services"`
		Egress []struct {
			IP      string `json:"ip"`
			Purpose string `json:"purpose"`
		} `json:"egress"`
	}
	if err := json.Unmarshal([]byte(answer[start:end+1]), &raw); err != nil {
		return Annotation{}, fmt.Errorf("输出不是合法 JSON: %w", err)
	}
	ann := Annotation{Role: clean(raw.Role, 32), Summary: clean(raw.Summary, 300), Criticality: raw.Criticality,
		Reason: clean(raw.Reason, 400), Relations: map[string]string{}, Services: map[string]ServiceNote{}}
	if ann.Role == "" || ann.Criticality < 1 || ann.Criticality > 5 {
		return Annotation{}, fmt.Errorf("角色为空或重要程度越界")
	}
	for _, r := range raw.Relations {
		if note := clean(r.Note, 60); note != "" && slices.Contains(peers, r.Peer) && len(ann.Relations) < maxPeers {
			ann.Relations[r.Peer] = note
		}
	}
	for _, eg := range raw.Egress {
		if purpose := clean(eg.Purpose, 40); purpose != "" && slices.Contains(public, eg.IP) {
			ann.Relations[eg.IP] = purpose
		}
	}
	for _, sv := range raw.Services {
		if name, port := clean(sv.Name, 32), servicePort(sv.Port); name != "" && slices.Contains(unknown, port) {
			ann.Services[port] = ServiceNote{Name: name, Note: clean(sv.Note, 120), Source: "ai"}
		}
	}
	return ann, nil
}

func listenersOf(a *ent.Asset) []Listener {
	var l []Listener
	_ = json.Unmarshal(a.Listening, &l)
	return l
}

func cloudOf(a *ent.Asset) *Cloud {
	var c *Cloud
	if len(a.Cloud) > 0 {
		_ = json.Unmarshal(a.Cloud, &c)
	}
	return c
}

// World 全部资产按 IP 与 ID 的索引，解析连接对端用
type World struct {
	Assets []*ent.Asset
	ByIP   map[netip.Addr]*ent.Asset
	ByID   map[uuid.UUID]*ent.Asset
}

// LoadWorld 登记的 IP 与云上公网 IP 都算资产地址
func LoadWorld(ctx context.Context, db *ent.Client) (*World, error) {
	assets, err := db.Asset.Query().Order(ent.Asc(asset.FieldHostname)).All(ctx)
	if err != nil {
		return nil, err
	}
	w := &World{Assets: assets, ByIP: map[netip.Addr]*ent.Asset{}, ByID: map[uuid.UUID]*ent.Asset{}}
	for _, a := range assets {
		w.ByID[a.ID] = a
		for _, ip := range parseIPs(a.IPAddrs) {
			w.ByIP[ip] = a
		}
		if c := cloudOf(a); c != nil && c.PublicIP != "" {
			if ip, err := netip.ParseAddr(c.PublicIP); err == nil {
				w.ByIP[ip] = a
			}
		}
	}
	return w, nil
}

func ptr(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	return *id
}

// servicePort 模型常把 unknownServices 整条抄回来（「udp/5405 corosync」），也有人写成「5405/udp」：取第一段并统一成 协议/端口
func servicePort(s string) string {
	first, _, _ := strings.Cut(strings.TrimSpace(s), " ")
	if a, b, ok := strings.Cut(first, "/"); ok && (b == "tcp" || b == "udp") {
		return b + "/" + a
	}
	return first
}
