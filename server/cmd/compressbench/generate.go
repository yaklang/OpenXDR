// 合成数据与 --input 解析。合成画像按 docs/events.md 的字段形态构造：
// agent 事件带 raw_json 与真实采集端的信封字段；sensor 只有 FlowRecord。
// 所有随机都来自 --seed 固定的 PCG，同一 seed 必须逐字节复现。
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"time"

	"openxdr/server/pb"
)

// ---------- 公共随机工具 ----------

func pick[T any](r *rand.Rand, xs []T) T {
	return xs[r.IntN(len(xs))]
}

func randomHex(r *rand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return hex.EncodeToString(b)
}

func randomUUID(r *rand.Rand) string {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:8], r.Uint64())
	binary.LittleEndian.PutUint64(b[8:16], r.Uint64())
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// marshalRaw 不转义 HTML 字符，贴近 serde_json 的输出；
// 同时去掉 Encoder 追加的换行，保证 raw_json 与真实事件同形。
func marshalRaw(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// ---------- agent OCSF 事件体 ----------

type filePathJSON struct {
	Path string `json:"path"`
}

type processFileJSON struct {
	Path   *string `json:"path"`
	Sha256 *string `json:"sha256"`
}

type parentProcessJSON struct {
	PID     *uint32       `json:"pid"`
	UID     *string       `json:"uid"`
	Name    string        `json:"name,omitempty"`
	File    *filePathJSON `json:"file,omitempty"`
	CmdLine *string       `json:"cmd_line,omitempty"`
}

type processJSON struct {
	PID           uint32            `json:"pid"`
	UID           string            `json:"uid"`
	Name          string            `json:"name"`
	File          processFileJSON   `json:"file"`
	CmdLine       *string           `json:"cmd_line"`
	ExitCode      *uint32           `json:"exit_code"`
	ParentProcess parentProcessJSON `json:"parent_process"`
	CreatedTime   *int64            `json:"created_time,omitempty"`
}

type containerJSON struct {
	Runtime string `json:"runtime"`
	UID     string `json:"uid"`
	Name    string `json:"name,omitempty"`
}

type processRawJSON struct {
	ActivityID uint32         `json:"activity_id"`
	Process    processJSON    `json:"process"`
	Container  *containerJSON `json:"container,omitempty"`
	DurationMS *int64         `json:"duration_ms,omitempty"`
}

type procRefJSON struct {
	PID  uint32       `json:"pid"`
	UID  string       `json:"uid,omitempty"`
	Name string       `json:"name"`
	File filePathJSON `json:"file"`
}

type fileRawJSON struct {
	ActivityID uint32       `json:"activity_id"`
	File       filePathJSON `json:"file"`
	Process    *procRefJSON `json:"process,omitempty"`
}

type endpointJSON struct {
	IP       string `json:"ip,omitempty"`
	Port     uint32 `json:"port,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

type connectionInfoJSON struct {
	Direction    string `json:"direction"`
	ProtocolName string `json:"protocol_name"`
}

type networkRawJSON struct {
	ActivityID     uint32             `json:"activity_id"`
	ConnectionInfo connectionInfoJSON `json:"connection_info"`
	SrcEndpoint    endpointJSON       `json:"src_endpoint"`
	DstEndpoint    endpointJSON       `json:"dst_endpoint"`
	Process        *procRefJSON       `json:"process,omitempty"`
	Container      *containerJSON     `json:"container,omitempty"`
}

type dnsQueryJSON struct {
	Hostname string  `json:"hostname"`
	Type     string  `json:"type,omitempty"`
	RcodeID  *uint32 `json:"rcode_id,omitempty"`
}

type dnsAnswerJSON struct {
	Type  string `json:"type,omitempty"`
	Rdata string `json:"rdata,omitempty"`
	IP    string `json:"ip,omitempty"`
	TTL   *int64 `json:"ttl,omitempty"`
}

type dnsRawJSON struct {
	ActivityID  uint32          `json:"activity_id"`
	Query       dnsQueryJSON    `json:"query"`
	Answers     []dnsAnswerJSON `json:"answers,omitempty"`
	SrcEndpoint endpointJSON    `json:"src_endpoint"`
	DstEndpoint endpointJSON    `json:"dst_endpoint"`
	Process     *procRefJSON    `json:"process,omitempty"`
	Container   *containerJSON  `json:"container,omitempty"`
}

type userJSON struct {
	Name string `json:"name"`
}

type serviceJSON struct {
	Name string `json:"name"`
}

type authRawJSON struct {
	ActivityID  uint32       `json:"activity_id"`
	StatusID    uint32       `json:"status_id"`
	User        userJSON     `json:"user"`
	SrcEndpoint endpointJSON `json:"src_endpoint"`
	Service     serviceJSON  `json:"service"`
}

type moduleFileJSON struct {
	Path string `json:"path,omitempty"`
	Name string `json:"name"`
}

type moduleRawJSON struct {
	ActivityID uint32 `json:"activity_id"`
	Module     struct {
		File moduleFileJSON `json:"file"`
	} `json:"module"`
}

type listeningJSON struct {
	Proto   string       `json:"proto"`
	Addr    string       `json:"addr"`
	Port    uint32       `json:"port"`
	Process *procRefJSON `json:"process,omitempty"`
}

type cloudJSON struct {
	Provider   string `json:"provider"`
	InstanceID string `json:"instance_id"`
	Region     string `json:"region"`
	PublicIP   string `json:"public_ip"`
}

type inventoryRawJSON struct {
	ActivityID uint32 `json:"activity_id"`
	Device     struct {
		OS        string          `json:"os,omitempty"`
		Listening []listeningJSON `json:"listening"`
		Cloud     *cloudJSON      `json:"cloud,omitempty"`
	} `json:"device"`
}

// ---------- agent 合成 ----------

type binSpec struct {
	name string
	path string
	cmds []string
}

type liveProc struct {
	pid        uint32
	guid       string
	parentGUID string
	name       string
	path       string
	username   string
	cmdLine    string
	startedNS  int64
	container  *containerJSON
}

type agentGen struct {
	rng        *rand.Rand
	agentID    string
	start      time.Time
	pidPool    []uint32
	nextPID    int
	live       []*liveProc
	bins       []binSpec
	users      []string
	hostnames  []string
	containers []containerJSON
	sourceIPs  []string
	destIPs    []string
	dnsServers []string
	dnsNames   []string
	filePaths  []string
	modules    []string
	hashCache  map[string]string
	inventory  []listeningJSON
}

func newAgentGen(seed int64) *agentGen {
	r := rand.New(rand.NewPCG(uint64(seed), uint64(seed)^0x9e3779b97f4a7c15))
	g := &agentGen{
		rng:     r,
		agentID: randomUUID(r),
		// 固定基准时间，保证同一 seed 的 ts_unix_ns 也完全一致。
		start:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		hashCache: map[string]string{},
	}
	for i := 0; i < 512; i++ {
		g.pidPool = append(g.pidPool, 1000+uint32(i*97%60000))
	}
	g.bins = []binSpec{
		{name: "bash", path: "/usr/bin/bash", cmds: []string{"-c whoami", "-c curl -s http://10.0.0.5:8080/health", "-i"}},
		{name: "sshd", path: "/usr/sbin/sshd", cmds: []string{"-D", "-D -f /etc/ssh/sshd_config"}},
		{name: "curl", path: "/usr/bin/curl", cmds: []string{"-sS https://api.github.com/repos/yaklang/openxdr", "-O http://10.0.0.9/payload.bin"}},
		{name: "python3", path: "/usr/bin/python3", cmds: []string{"-m pip install requests", "/opt/app/worker.py --threads 4"}},
		{name: "systemd", path: "/usr/lib/systemd/systemd", cmds: []string{"--system --deserialize 23"}},
		{name: "nginx", path: "/usr/sbin/nginx", cmds: []string{"-g daemon off;"}},
		{name: "docker", path: "/usr/bin/docker", cmds: []string{"ps -a", "exec -it api-1 sh"}},
		{name: "psql", path: "/usr/bin/psql", cmds: []string{"-h 10.0.1.12 -U app -d openxdr"}},
		{name: "node", path: "/usr/bin/node", cmds: []string{"/opt/web/server.js"}},
		{name: "bash", path: "/bin/bash", cmds: []string{"-c id", "-c systemctl status docker"}},
	}
	g.users = []string{"root", "www-data", "ubuntu", "postgres", "nobody", "deploy"}
	g.hostnames = []string{
		"github.com", "api.github.com", "cdn.jsdelivr.net", "registry.npmjs.org",
		"update.microsoft.com", "www.google.com", "example.com", "mirror.aliyun.com",
		"telemetry.openxdr.io", "evil.example.net",
	}
	g.containers = []containerJSON{
		{Runtime: "docker", UID: "4f1c2a3b5d6e", Name: "api-1"},
		{Runtime: "docker", UID: "9ab3de12f045", Name: "web-2"},
		{Runtime: "containerd", UID: "1d7e8f90a2b3", Name: "redis-1"},
		{Runtime: "lxc", UID: "203", Name: "dns"},
	}
	g.sourceIPs = []string{
		"10.0.0.5", "10.0.0.8", "10.0.1.12", "10.0.1.20", "10.0.2.31",
		"10.0.3.7", "192.168.1.10", "192.168.1.24",
	}
	g.destIPs = []string{
		"20.205.243.166", "140.82.112.3", "104.16.85.20", "151.101.1.69",
		"13.107.42.14", "142.250.72.14", "47.98.1.2", "8.8.8.8",
		"1.1.1.1", "203.0.113.10", "198.51.100.7", "185.199.108.133",
		"93.184.216.34", "172.217.160.78", "31.13.94.36", "52.84.150.39",
	}
	g.dnsServers = []string{"10.0.0.53", "10.1.1.1", "8.8.8.8", "223.5.5.5"}
	g.dnsNames = []string{
		"github.com", "api.github.com", "registry.npmjs.org", "pypi.org",
		"update.microsoft.com", "www.google.com", "example.com", "mirror.aliyun.com",
		"telemetry.openxdr.io", "evil.example.net", "cdn.jsdelivr.net", "golang.org",
		"proxy.golang.org", "raw.githubusercontent.com", "docs.openxdr.io",
	}
	g.filePaths = []string{
		"/etc/cron.d/evil", "/root/.ssh/authorized_keys", "/etc/passwd",
		"/etc/shadow", "/tmp/xmrig", "/var/www/html/shell.php",
		"/etc/systemd/system/backdoor.service", "/var/spool/cron/root",
		"/usr/local/bin/cleanup.sh", "/etc/ld.so.preload",
	}
	g.modules = []string{
		"e1000e.ko.xz", "nf_conntrack.ko.xz", "overlay.ko.xz",
		"xfs.ko.xz", "veth.ko.xz", "binfmt_misc.ko.xz",
	}
	g.inventory = []listeningJSON{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Process: &procRefJSON{PID: 812, Name: "sshd", File: filePathJSON{Path: "/usr/sbin/sshd"}}},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 443, Process: &procRefJSON{PID: 933, Name: "nginx", File: filePathJSON{Path: "/usr/sbin/nginx"}}},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 5432, Process: &procRefJSON{PID: 1044, Name: "postgres", File: filePathJSON{Path: "/usr/lib/postgresql/16/bin/postgres"}}},
		{Proto: "udp", Addr: "0.0.0.0", Port: 53},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 8080, Process: &procRefJSON{PID: 1288, Name: "openxdr-server", File: filePathJSON{Path: "/usr/local/bin/openxdr-server"}}},
	}
	return g
}

func (g *agentGen) timestamp(i int) int64 {
	base := g.start.Add(time.Duration(i) * 250 * time.Millisecond)
	return base.Add(time.Duration(g.rng.IntN(50)) * time.Millisecond).UnixNano()
}

func synthesizeAgent(n int, seed int64) ([]*pb.AgentEvent, error) {
	if n <= 0 {
		return nil, fmt.Errorf("合成事件数必须大于 0")
	}
	g := newAgentGen(seed)
	events := make([]*pb.AgentEvent, 0, n)
	for i := 0; i < n; i++ {
		ts := g.timestamp(i)
		var (
			ev  *pb.AgentEvent
			err error
		)
		switch roll := g.rng.IntN(100); {
		case roll < 55:
			ev, err = g.processEvent(ts)
		case roll < 80:
			ev, err = g.networkEvent(ts)
		case roll < 92:
			ev, err = g.dnsEvent(ts)
		case roll < 96:
			ev, err = g.fileEvent(ts)
		case roll < 98:
			ev, err = g.authEvent(ts)
		case roll < 99:
			ev, err = g.moduleEvent(ts)
		default:
			ev, err = g.inventoryEvent(ts)
		}
		if err != nil {
			return nil, fmt.Errorf("生成第 %d 条事件: %w", i+1, err)
		}
		events = append(events, ev)
	}
	return events, nil
}

func (g *agentGen) rawEvent(class uint32, ts int64, guid, parentGUID, username, connTuple string, raw any) (*pb.AgentEvent, error) {
	b, err := marshalRaw(raw)
	if err != nil {
		return nil, fmt.Errorf("序列化 class_uid=%d 事件: %w", class, err)
	}
	return &pb.AgentEvent{
		AgentId:           g.agentID,
		TsUnixNs:          ts,
		ClassUid:          class,
		ProcessGuid:       guid,
		ParentProcessGuid: parentGUID,
		Username:          username,
		ConnTuple:         connTuple,
		RawJson:           string(b),
	}, nil
}

func (g *agentGen) processEvent(ts int64) (*pb.AgentEvent, error) {
	// 同时活着的进程有上限，保证 pid 池可复用且不无限增长。
	if len(g.live) >= 240 || (len(g.live) > 0 && g.rng.IntN(2) == 0) {
		return g.exitProcess(ts)
	}
	return g.launchProcess(ts)
}

func (g *agentGen) launchProcess(ts int64) (*pb.AgentEvent, error) {
	bin := pick(g.rng, g.bins)
	pid := g.freePID()
	guid := randomUUID(g.rng)
	username := pick(g.rng, g.users)
	cmdLine := pick(g.rng, bin.cmds)
	if g.rng.IntN(100) < 25 {
		cmdLine += " --trace-id " + randomHex(g.rng, 8)
	}

	var parent *liveProc
	if len(g.live) > 0 && g.rng.IntN(100) < 70 {
		parent = g.live[g.rng.IntN(len(g.live))]
	}
	p := &liveProc{
		pid:       pid,
		guid:      guid,
		name:      bin.name,
		path:      bin.path,
		username:  username,
		cmdLine:   cmdLine,
		startedNS: ts,
	}
	parentJSON := parentProcessJSON{}
	if parent != nil {
		p.parentGUID = parent.guid
		parentJSON = parentProcessJSON{
			PID:     &parent.pid,
			UID:     &parent.guid,
			Name:    parent.name,
			File:    &filePathJSON{Path: parent.path},
			CmdLine: &parent.cmdLine,
		}
	}
	if g.rng.IntN(100) < 12 {
		c := pick(g.rng, g.containers)
		p.container = &c
	}
	g.live = append(g.live, p)

	sha := g.hashFor(bin.path)
	raw := processRawJSON{
		ActivityID: 1,
		Process: processJSON{
			PID:           p.pid,
			UID:           p.guid,
			Name:          p.name,
			File:          processFileJSON{Path: &p.path, Sha256: &sha},
			CmdLine:       &p.cmdLine,
			ExitCode:      nil,
			ParentProcess: parentJSON,
		},
		Container: p.container,
	}
	return g.rawEvent(1007, ts, p.guid, p.parentGUID, p.username, "", raw)
}

func (g *agentGen) exitProcess(ts int64) (*pb.AgentEvent, error) {
	idx := g.rng.IntN(len(g.live))
	p := g.live[idx]
	g.live = append(g.live[:idx], g.live[idx+1:]...)

	exitCode := pick(g.rng, []uint32{0, 0, 0, 1, 2, 137, 143})
	durationMS := (ts - p.startedNS) / int64(time.Millisecond)
	if durationMS < 0 {
		durationMS = 0
	}
	createdTime := p.startedNS / int64(time.Millisecond)
	parentJSON := parentProcessJSON{}
	if p.parentGUID != "" {
		parentJSON.UID = &p.parentGUID
	}
	raw := processRawJSON{
		ActivityID: 2,
		Process: processJSON{
			PID:           p.pid,
			UID:           p.guid,
			Name:          p.name,
			File:          processFileJSON{Path: &p.path, Sha256: ptr(g.hashFor(p.path))},
			CmdLine:       &p.cmdLine,
			ExitCode:      &exitCode,
			ParentProcess: parentJSON,
			CreatedTime:   &createdTime,
		},
		Container:  p.container,
		DurationMS: &durationMS,
	}
	return g.rawEvent(1007, ts, p.guid, p.parentGUID, p.username, "", raw)
}

func (g *agentGen) networkEvent(ts int64) (*pb.AgentEvent, error) {
	var p *liveProc
	if len(g.live) > 0 && g.rng.IntN(100) < 80 {
		p = g.live[g.rng.IntN(len(g.live))]
	}
	srcIP := fmt.Sprintf("10.1.%d.%d", 1+g.rng.IntN(8), 1+g.rng.IntN(254))
	dstIP := pick(g.rng, g.destIPs)
	srcPort := uint32(32768 + g.rng.IntN(32768))
	dstPort := pick(g.rng, []uint32{443, 443, 443, 80, 8080, 22, 3306, 5432, 8443})
	protocol := "tcp"
	if g.rng.IntN(100) < 15 {
		protocol = "udp"
		dstPort = pick(g.rng, []uint32{123, 514, 41641})
	}
	direction := "outbound"
	if g.rng.IntN(100) < 20 {
		direction = "inbound"
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, uint32(32768+g.rng.IntN(32768))
		dstPort = pick(g.rng, []uint32{22, 443, 8080})
	}
	dst := endpointJSON{IP: dstIP, Port: dstPort}
	if g.rng.IntN(100) < 15 {
		dst.Hostname = pick(g.rng, g.hostnames)
	}
	raw := networkRawJSON{
		ActivityID:     1,
		ConnectionInfo: connectionInfoJSON{Direction: direction, ProtocolName: protocol},
		SrcEndpoint:    endpointJSON{IP: srcIP, Port: srcPort},
		DstEndpoint:    dst,
	}
	guid, username := "", ""
	if p != nil {
		raw.Process = g.procRef(p)
		guid, username = p.guid, p.username
		if p.container != nil && g.rng.IntN(100) < 15 {
			c := *p.container
			raw.Container = &c
		}
	}
	connTuple := fmt.Sprintf("%s:%s:%d>%s:%d", protocol, srcIP, srcPort, dstIP, dstPort)
	return g.rawEvent(4001, ts, guid, "", username, connTuple, raw)
}

func (g *agentGen) dnsEvent(ts int64) (*pb.AgentEvent, error) {
	var p *liveProc
	if len(g.live) > 0 && g.rng.IntN(100) < 70 {
		p = g.live[g.rng.IntN(len(g.live))]
	}
	hostname := pick(g.rng, g.dnsNames)
	if g.rng.IntN(100) < 20 {
		hostname = randomHex(g.rng, 4) + "." + hostname
	}
	qtype := "A"
	if g.rng.IntN(100) < 20 {
		qtype = "AAAA"
	}
	srcIP := fmt.Sprintf("10.1.%d.%d", 1+g.rng.IntN(8), 1+g.rng.IntN(254))
	srcPort := uint32(32768 + g.rng.IntN(32768))
	dstIP := pick(g.rng, g.dnsServers)
	raw := dnsRawJSON{
		ActivityID:  6,
		Query:       dnsQueryJSON{Hostname: hostname, Type: qtype},
		SrcEndpoint: endpointJSON{IP: srcIP, Port: srcPort},
		DstEndpoint: endpointJSON{IP: dstIP, Port: 53},
	}
	if g.rng.IntN(100) < 90 {
		rcode := uint32(0)
		raw.Query.RcodeID = &rcode
		ttl := int64(pick(g.rng, []int64{30, 60, 120, 300, 600}))
		if g.rng.IntN(100) < 30 {
			raw.Answers = append(raw.Answers, dnsAnswerJSON{Type: "CNAME", Rdata: "edge." + hostname, TTL: &ttl})
		}
		for i := 0; i < 1+g.rng.IntN(3); i++ {
			if qtype == "AAAA" {
				raw.Answers = append(raw.Answers, dnsAnswerJSON{
					Type: "AAAA",
					IP:   fmt.Sprintf("2606:4700:10::%x", 0x6812+g.rng.IntN(2000)),
					TTL:  &ttl,
				})
				continue
			}
			raw.Answers = append(raw.Answers, dnsAnswerJSON{Type: "A", IP: pick(g.rng, g.destIPs), TTL: &ttl})
		}
	} else {
		// 5 秒没等到应答：只有查询（activity_id=1），不编造 rcode 与 answers。
		raw.ActivityID = 1
	}
	guid, username := "", ""
	if p != nil {
		raw.Process = g.procRef(p)
		guid, username = p.guid, p.username
		if p.container != nil && g.rng.IntN(100) < 20 {
			c := *p.container
			raw.Container = &c
		}
	}
	connTuple := fmt.Sprintf("udp:%s:%d>%s:53", srcIP, srcPort, dstIP)
	return g.rawEvent(4003, ts, guid, "", username, connTuple, raw)
}

func (g *agentGen) fileEvent(ts int64) (*pb.AgentEvent, error) {
	activity := pick(g.rng, []uint32{1, 1, 3, 3, 4})
	raw := fileRawJSON{ActivityID: activity, File: filePathJSON{Path: pick(g.rng, g.filePaths)}}
	guid, username := "", ""
	if len(g.live) > 0 && g.rng.IntN(100) < 30 {
		p := g.live[g.rng.IntN(len(g.live))]
		raw.Process = g.procRef(p)
		guid, username = p.guid, p.username
	}
	return g.rawEvent(1001, ts, guid, "", username, "", raw)
}

func (g *agentGen) authEvent(ts int64) (*pb.AgentEvent, error) {
	user := pick(g.rng, []string{"root", "ubuntu", "admin", "postgres", "deploy"})
	status := uint32(1)
	if g.rng.IntN(100) < 65 {
		status = 2
	}
	service := "sshd"
	if g.rng.IntN(100) < 15 {
		service = "pts/0"
	}
	raw := authRawJSON{
		ActivityID:  1,
		StatusID:    status,
		User:        userJSON{Name: user},
		SrcEndpoint: endpointJSON{IP: pick(g.rng, g.sourceIPs)},
		Service:     serviceJSON{Name: service},
	}
	return g.rawEvent(3002, ts, "", "", user, "", raw)
}

func (g *agentGen) moduleEvent(ts int64) (*pb.AgentEvent, error) {
	activity := uint32(1)
	if g.rng.IntN(100) < 20 {
		activity = 4
	}
	name := pick(g.rng, g.modules)
	raw := moduleRawJSON{ActivityID: activity}
	raw.Module.File = moduleFileJSON{
		Path: "/lib/modules/6.8.0-45-generic/kernel/" + name,
		Name: name,
	}
	return g.rawEvent(1005, ts, "", "", "", "", raw)
}

func (g *agentGen) inventoryEvent(ts int64) (*pb.AgentEvent, error) {
	raw := inventoryRawJSON{ActivityID: 2}
	raw.Device.OS = "Ubuntu 24.04.1 LTS"
	raw.Device.Listening = g.inventory
	if g.rng.IntN(100) < 50 {
		raw.Device.Cloud = &cloudJSON{
			Provider:   "aliyun",
			InstanceID: "i-" + randomHex(g.rng, 8),
			Region:     "cn-hangzhou",
			PublicIP:   pick(g.rng, g.destIPs),
		}
	}
	return g.rawEvent(5001, ts, "", "", "", "", raw)
}

func (g *agentGen) procRef(p *liveProc) *procRefJSON {
	return &procRefJSON{
		PID:  p.pid,
		UID:  p.guid,
		Name: p.name,
		File: filePathJSON{Path: p.path},
	}
}

func (g *agentGen) hashFor(path string) string {
	if h, ok := g.hashCache[path]; ok {
		return h
	}
	sum := sha256.Sum256([]byte(path))
	h := hex.EncodeToString(sum[:])
	g.hashCache[path] = h
	return h
}

func (g *agentGen) freePID() uint32 {
	for i := 0; i < len(g.pidPool); i++ {
		idx := (g.nextPID + i) % len(g.pidPool)
		pid := g.pidPool[idx]
		if !g.pidLive(pid) {
			g.nextPID = (idx + 1) % len(g.pidPool)
			return pid
		}
	}
	// 调用方保证 live < len(pidPool)，这里只可能是逻辑错误。
	panic("compressbench: pid 池耗尽")
}

func (g *agentGen) pidLive(pid uint32) bool {
	for _, p := range g.live {
		if p.pid == pid {
			return true
		}
	}
	return false
}

func ptr[T any](v T) *T {
	return &v
}

// ---------- sensor 合成 ----------

type sensorGen struct {
	rng        *rand.Rand
	start      time.Time
	publicIPs  []string
	snis       []string
	ja3s       []string
	ja3ss      []string
	httpHosts  []string
	httpURIs   []string
	userAgents []string
	dnsNames   []string
	dnsAnswers []string
	issuers    []string
}

func newSensorGen(seed int64) *sensorGen {
	r := rand.New(rand.NewPCG(uint64(seed), uint64(seed)^0x9e3779b97f4a7c15))
	g := &sensorGen{
		rng:   r,
		start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	g.publicIPs = []string{
		"20.205.243.166", "140.82.112.3", "104.16.85.20", "151.101.1.69",
		"13.107.42.14", "142.250.72.14", "47.98.1.2", "8.8.8.8",
		"1.1.1.1", "203.0.113.10", "198.51.100.7", "185.199.108.133",
		"93.184.216.34", "172.217.160.78", "31.13.94.36", "52.84.150.39",
	}
	g.snis = []string{
		"github.com", "api.github.com", "cdn.jsdelivr.net", "registry.npmjs.org",
		"update.microsoft.com", "www.google.com", "example.com", "mirror.aliyun.com",
		"telemetry.openxdr.io", "evil.example.net", "docs.openxdr.io", "golang.org",
	}
	g.ja3s = make([]string, 8)
	for i := range g.ja3s {
		g.ja3s[i] = randomHex(r, 16)
	}
	g.ja3ss = make([]string, 6)
	for i := range g.ja3ss {
		g.ja3ss[i] = randomHex(r, 16)
	}
	g.httpHosts = []string{
		"github.com", "raw.githubusercontent.com", "registry.npmjs.org",
		"pypi.org", "docs.openxdr.io", "evil.example.net", "update.microsoft.com",
	}
	g.httpURIs = []string{
		"/api/v1/events", "/healthz", "/.git/config", "/login", "/static/app.js",
		"/download/agent", "/v1/users", "/wp-login.php", "/cgi-bin/luci",
		"/api/v1/reports", "/metrics", "/index.html",
	}
	g.userAgents = []string{
		"curl/8.5.0", "Wget/1.21.4", "python-requests/2.32.3", "Go-http-client/2.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36",
		"sqlmap/1.8.7#stable", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
	}
	g.dnsNames = []string{
		"github.com", "api.github.com", "registry.npmjs.org", "pypi.org",
		"update.microsoft.com", "www.google.com", "example.com", "mirror.aliyun.com",
		"telemetry.openxdr.io", "evil.example.net", "cdn.jsdelivr.net", "golang.org",
		"ntp.aliyun.com", "time.windows.com",
	}
	g.dnsAnswers = []string{
		"20.205.243.166", "140.82.112.3", "104.16.85.20", "151.101.1.69",
		"13.107.42.14", "142.250.72.14", "47.98.1.2", "93.184.216.34",
		"172.217.160.78", "31.13.94.36", "52.84.150.39", "185.199.108.133",
	}
	g.issuers = []string{"DigiCert CA", "Let's Encrypt R3", "GlobalSign", "Sectigo RSA DV"}
	return g
}

func synthesizeSensor(n int, seed int64) ([]*pb.FlowRecord, error) {
	if n <= 0 {
		return nil, fmt.Errorf("合成事件数必须大于 0")
	}
	g := newSensorGen(seed)
	flows := make([]*pb.FlowRecord, 0, n)
	for i := 0; i < n; i++ {
		flows = append(flows, g.flow(i))
	}
	return flows, nil
}

func (g *sensorGen) flow(i int) *pb.FlowRecord {
	start := g.start.Add(time.Duration(i)*200*time.Millisecond + time.Duration(g.rng.IntN(100))*time.Millisecond)
	kind := g.rng.IntN(100)
	durationMS := 1 + g.rng.IntN(120000)
	if kind < 12 {
		durationMS = 1 + g.rng.IntN(300)
	}

	srcIP := fmt.Sprintf("10.0.%d.%d", 1+g.rng.IntN(16), 1+g.rng.IntN(254))
	dstIP := pick(g.rng, g.publicIPs)
	srcPort := uint32(32768 + g.rng.IntN(32768))
	dstPort := pick(g.rng, []uint32{443, 443, 80, 8080, 22, 3306, 5432, 8443})
	protocol := uint32(6)
	tcpFlags := uint32(0x18)

	f := &pb.FlowRecord{
		StartUnixNs: start.UnixNano(),
		EndUnixNs:   start.Add(time.Duration(durationMS) * time.Millisecond).UnixNano(),
		SrcIp:       srcIP,
		DstIp:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Protocol:    protocol,
		TcpFlags:    tcpFlags,
	}

	switch {
	case kind < 12: // DNS 会话
		protocol = 17
		tcpFlags = 0
		dstIP = pick(g.rng, []string{"10.0.0.53", "10.1.1.1", "8.8.8.8", "223.5.5.5"})
		dstPort = 53
		f.DnsQuery = pick(g.rng, g.dnsNames)
		if g.rng.IntN(100) < 12 {
			f.DnsQuery = randomHex(g.rng, 4) + "." + f.DnsQuery
		}
		if g.rng.IntN(100) < 88 {
			f.DnsRcode = 0
			for j := 0; j < 1+g.rng.IntN(4); j++ {
				f.DnsAnswers = append(f.DnsAnswers, pick(g.rng, g.dnsAnswers))
			}
		} else {
			f.DnsRcode = 3
		}
	case kind < 40: // TLS
		dstPort = 443
		f.TlsSni = pick(g.rng, g.snis)
		f.Ja3 = pick(g.rng, g.ja3s)
		f.Ja3S = pick(g.rng, g.ja3ss)
		f.TlsHandshakeOnly = g.rng.IntN(100) < 8
		if g.rng.IntN(100) < 20 {
			f.TlsCertSubject = f.TlsSni
			f.TlsCertIssuer = pick(g.rng, g.issuers)
			f.TlsCertSelfSigned = g.rng.IntN(100) < 5
			f.TlsCertNotBefore = g.start.Add(-90 * 24 * time.Hour).Unix()
			f.TlsCertNotAfter = g.start.Add(365 * 24 * time.Hour).Unix()
		}
		if g.rng.IntN(100) < 45 {
			f.HttpHost = f.TlsSni
			f.HttpUri = pick(g.rng, g.httpURIs)
			f.HttpUserAgent = pick(g.rng, g.userAgents)
		}
	case kind < 55: // 明文 HTTP
		dstPort = pick(g.rng, []uint32{80, 8080})
		f.HttpHost = pick(g.rng, g.httpHosts)
		f.HttpUri = pick(g.rng, g.httpURIs)
		f.HttpUserAgent = pick(g.rng, g.userAgents)
		if g.rng.IntN(100) < 20 {
			f.TlsSni = f.HttpHost
			f.Ja3 = pick(g.rng, g.ja3s)
		}
	case kind < 80: // 普通 TCP
		if g.rng.IntN(100) < 25 {
			dstPort = 22
		}
	default: // 普通 UDP
		protocol = 17
		tcpFlags = 0
		dstPort = pick(g.rng, []uint32{123, 514, 41641, 5353})
	}

	if g.rng.IntN(100) < 15 {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, uint32(32768+g.rng.IntN(32768))
	}

	packets := 2 + g.rng.IntN(120)
	if kind < 12 {
		packets = 1 + g.rng.IntN(2)
	}
	f.SrcIp, f.DstIp = srcIP, dstIP
	f.SrcPort, f.DstPort = srcPort, dstPort
	f.Protocol = protocol
	f.TcpFlags = tcpFlags
	f.SrcPackets = uint64(packets)
	f.DstPackets = uint64(1 + g.rng.IntN(packets+1))
	f.SrcBytes = f.SrcPackets*uint64(40+g.rng.IntN(1200)) + uint64(g.rng.IntN(500))
	f.DstBytes = f.DstPackets*uint64(40+g.rng.IntN(1200)) + uint64(g.rng.IntN(500))
	if kind < 12 {
		f.SrcBytes = uint64(40 + g.rng.IntN(120))
		f.DstBytes = uint64(60 + g.rng.IntN(400))
	}
	return f
}

// ---------- --input 解析 ----------

type agentInputProbe struct {
	AgentID           string `json:"agent_id"`
	TsUnixNS          int64  `json:"ts_unix_ns"`
	ClassUID          uint32 `json:"class_uid"`
	ProcessGUID       string `json:"process_guid"`
	ParentProcessGUID string `json:"parent_process_guid"`
	Username          string `json:"username"`
	ConnTuple         string `json:"conn_tuple"`
	Process           *struct {
		UID           string `json:"uid"`
		ParentProcess *struct {
			UID string `json:"uid"`
		} `json:"parent_process"`
	} `json:"process"`
	User *struct {
		Name string `json:"name"`
	} `json:"user"`
	SrcEndpoint    *endpointJSON `json:"src_endpoint"`
	DstEndpoint    *endpointJSON `json:"dst_endpoint"`
	ConnectionInfo *struct {
		ProtocolName string `json:"protocol_name"`
	} `json:"connection_info"`
	Query *struct {
		Hostname string `json:"hostname"`
	} `json:"query"`
}

// parseAgentLine 把一行 events.raw 转成 AgentEvent。raw 本身不含 events 表的信封列，
// 因此只回填能由事件体证明的字段（进程 GUID、认证用户、可由端点推出的 conn_tuple）；
// 其余信封字段留空，不臆测。
func parseAgentLine(line []byte) (*pb.AgentEvent, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(line, &obj); err != nil {
		return nil, fmt.Errorf("不是 JSON 对象: %w", err)
	}
	if obj == nil {
		return nil, fmt.Errorf("不是 JSON 对象")
	}
	var p agentInputProbe
	if err := json.Unmarshal(line, &p); err != nil {
		return nil, fmt.Errorf("解析事件字段: %w", err)
	}
	ev := &pb.AgentEvent{
		AgentId:           p.AgentID,
		TsUnixNs:          p.TsUnixNS,
		ClassUid:          p.ClassUID,
		ProcessGuid:       p.ProcessGUID,
		ParentProcessGuid: p.ParentProcessGUID,
		Username:          p.Username,
		ConnTuple:         p.ConnTuple,
		RawJson:           string(line),
	}
	if p.Process != nil {
		if ev.ProcessGuid == "" {
			ev.ProcessGuid = p.Process.UID
		}
		if ev.ParentProcessGuid == "" && p.Process.ParentProcess != nil {
			ev.ParentProcessGuid = p.Process.ParentProcess.UID
		}
	}
	if ev.Username == "" && p.User != nil {
		ev.Username = p.User.Name
	}
	if ev.ConnTuple == "" {
		ev.ConnTuple = connTupleFromProbe(p)
	}
	return ev, nil
}

func connTupleFromProbe(p agentInputProbe) string {
	if p.SrcEndpoint == nil || p.DstEndpoint == nil || p.SrcEndpoint.IP == "" || p.DstEndpoint.IP == "" {
		return ""
	}
	protocol := "tcp"
	if p.ConnectionInfo != nil && p.ConnectionInfo.ProtocolName != "" {
		protocol = p.ConnectionInfo.ProtocolName
	}
	if p.Query != nil {
		protocol = "udp"
	}
	return fmt.Sprintf("%s:%s:%d>%s:%d", protocol, p.SrcEndpoint.IP, p.SrcEndpoint.Port, p.DstEndpoint.IP, p.DstEndpoint.Port)
}

type sensorInputRaw struct {
	DurationMS     int64 `json:"duration_ms"`
	ConnectionInfo struct {
		ProtocolNum uint32 `json:"protocol_num"`
		TcpFlags    uint32 `json:"tcp_flags"`
	} `json:"connection_info"`
	SrcEndpoint endpointJSON `json:"src_endpoint"`
	DstEndpoint endpointJSON `json:"dst_endpoint"`
	Traffic     struct {
		Packets    uint64 `json:"packets"`
		Bytes      uint64 `json:"bytes"`
		PacketsIn  uint64 `json:"packets_in"`
		BytesIn    uint64 `json:"bytes_in"`
		PacketsOut uint64 `json:"packets_out"`
		BytesOut   uint64 `json:"bytes_out"`
	} `json:"traffic"`
	TLS *struct {
		SNI           string `json:"sni"`
		Ja3Hash       string `json:"ja3_hash"`
		Ja3sHash      string `json:"ja3s_hash"`
		HandshakeOnly bool   `json:"handshake_only"`
		Cert          *struct {
			Subject    string `json:"subject"`
			Issuer     string `json:"issuer"`
			SelfSigned bool   `json:"self_signed"`
			NotBefore  int64  `json:"not_before"`
			NotAfter   int64  `json:"not_after"`
		} `json:"cert"`
	} `json:"tls"`
	HTTPRequest *struct {
		Hostname string `json:"hostname"`
		URL      struct {
			Path string `json:"path"`
		} `json:"url"`
		UserAgent string `json:"user_agent"`
	} `json:"http_request"`
	Query *struct {
		Hostname string `json:"hostname"`
		RcodeID  uint32 `json:"rcode_id"`
	} `json:"query"`
	Answers []struct {
		IP string `json:"ip"`
	} `json:"answers"`
}

// parseSensorLine 是 grpcsvc.flowRaw 的逆映射：events.raw 里的 sensor 事件体
// 由 FlowRecord 确定性生成，字段可以逐项还原。raw 不含会话起止时间，
// 输入模式下 start_unix_ns=0、end_unix_ns=duration_ms，字节数略低于线上原始记录。
func parseSensorLine(line []byte) (*pb.FlowRecord, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(line, &obj); err != nil {
		return nil, fmt.Errorf("不是 JSON 对象: %w", err)
	}
	if obj == nil {
		return nil, fmt.Errorf("不是 JSON 对象")
	}
	var raw sensorInputRaw
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("解析事件字段: %w", err)
	}
	if raw.ConnectionInfo.ProtocolNum == 0 {
		return nil, fmt.Errorf("缺少 connection_info.protocol_num，不像是 sensor 会话事件")
	}
	if raw.DurationMS < 0 {
		return nil, fmt.Errorf("duration_ms 不能为负数")
	}
	if raw.SrcEndpoint.IP == "" && raw.DstEndpoint.IP == "" &&
		(raw.Query == nil || raw.Query.Hostname == "") &&
		(raw.TLS == nil || raw.TLS.SNI == "") &&
		(raw.HTTPRequest == nil || raw.HTTPRequest.Hostname == "") {
		return nil, fmt.Errorf("没有 src/dst/query/tls/http 字段，不像是 sensor 会话事件")
	}

	f := &pb.FlowRecord{
		EndUnixNs:  raw.DurationMS * int64(time.Millisecond),
		SrcIp:      raw.SrcEndpoint.IP,
		DstIp:      raw.DstEndpoint.IP,
		SrcPort:    raw.SrcEndpoint.Port,
		DstPort:    raw.DstEndpoint.Port,
		Protocol:   raw.ConnectionInfo.ProtocolNum,
		TcpFlags:   raw.ConnectionInfo.TcpFlags,
		SrcPackets: raw.Traffic.PacketsOut,
		SrcBytes:   raw.Traffic.BytesOut,
		DstPackets: raw.Traffic.PacketsIn,
		DstBytes:   raw.Traffic.BytesIn,
	}
	if raw.TLS != nil {
		f.TlsSni = raw.TLS.SNI
		f.Ja3 = raw.TLS.Ja3Hash
		f.Ja3S = raw.TLS.Ja3sHash
		f.TlsHandshakeOnly = raw.TLS.HandshakeOnly
		if raw.TLS.Cert != nil {
			f.TlsCertSubject = raw.TLS.Cert.Subject
			f.TlsCertIssuer = raw.TLS.Cert.Issuer
			f.TlsCertSelfSigned = raw.TLS.Cert.SelfSigned
			f.TlsCertNotBefore = raw.TLS.Cert.NotBefore
			f.TlsCertNotAfter = raw.TLS.Cert.NotAfter
		}
	}
	if raw.HTTPRequest != nil {
		f.HttpHost = raw.HTTPRequest.Hostname
		f.HttpUri = raw.HTTPRequest.URL.Path
		f.HttpUserAgent = raw.HTTPRequest.UserAgent
	}
	if raw.Query != nil && raw.Query.Hostname != "" {
		f.DnsQuery = raw.Query.Hostname
		f.DnsRcode = raw.Query.RcodeID
		for _, a := range raw.Answers {
			if a.IP != "" {
				f.DnsAnswers = append(f.DnsAnswers, a.IP)
			}
		}
	}
	return f, nil
}

func readNDJSON(path string, fn func(line []byte, lineNo int) error) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("打开 %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			return fmt.Errorf("%s 第 %d 行是空行", path, lineNo)
		}
		if err := fn(line, lineNo); err != nil {
			return fmt.Errorf("%s 第 %d 行: %w", path, lineNo, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("读取 %s: %w", path, err)
	}
	return nil
}

func loadAgentInput(path string) ([]*pb.AgentEvent, error) {
	var events []*pb.AgentEvent
	if err := readNDJSON(path, func(line []byte, _ int) error {
		ev, err := parseAgentLine(line)
		if err != nil {
			return err
		}
		events = append(events, ev)
		return nil
	}); err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("%s 里没有事件", path)
	}
	return events, nil
}

func loadSensorInput(path string) ([]*pb.FlowRecord, error) {
	var flows []*pb.FlowRecord
	if err := readNDJSON(path, func(line []byte, _ int) error {
		f, err := parseSensorLine(line)
		if err != nil {
			return err
		}
		flows = append(flows, f)
		return nil
	}); err != nil {
		return nil, err
	}
	if len(flows) == 0 {
		return nil, fmt.Errorf("%s 里没有事件", path)
	}
	return flows, nil
}
