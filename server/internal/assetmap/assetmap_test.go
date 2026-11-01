package assetmap

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/zone"
)

func TestInventoryValidatesAgentData(t *testing.T) {
	raw := json.RawMessage(`{"activity_id":2,"device":{
"listening":[
 {"proto":"tcp","addr":"0.0.0.0","port":22,"process":{"pid":812,"name":"sshd","file":{"path":"/usr/sbin/sshd"}}},
 {"proto":"tcp","addr":"0.0.0.0","port":22},
 {"proto":"udp","addr":"::","port":53},
 {"proto":"icmp","addr":"0.0.0.0","port":1},
 {"proto":"tcp","addr":"not-ip","port":80},
 {"proto":"tcp","addr":"127.0.0.1","port":70000}
],
"cloud":{"provider":"aliyun","instance_id":"i-bp1","region":"cn-hangzhou","public_ip":"47.1.2.3"}}}`)
	l, c, os := inventory(raw)
	if len(l) != 2 || l[0].Proto != "tcp" || l[0].Process != "sshd" || l[0].Path != "/usr/sbin/sshd" || l[1].Proto != "udp" {
		t.Fatalf("坏条目应丢弃、重复只留第一条: %+v", l)
	}
	if c == nil || c.Provider != "aliyun" || c.PublicIP != "47.1.2.3" {
		t.Fatalf("云信息解析错误: %+v", c)
	}
	if os != "" {
		t.Fatalf("不带 os 键应返回空串: %q", os)
	}
	if _, c, _ := inventory(json.RawMessage(`{"device":{"cloud":{"provider":"evilcloud","instance_id":"x"}}}`)); c != nil {
		t.Fatal("未知云厂商不能当作在云上")
	}
	if _, c, _ := inventory(json.RawMessage(`{"device":{"cloud":{"provider":"aws","instance_id":""}}}`)); c != nil {
		t.Fatal("缺实例 ID 不能当作在云上")
	}
	// 系统显示名随 5001 上报：原样清洗保留，供物化覆盖导入时的声明值
	if _, _, os := inventory(json.RawMessage(`{"device":{"os":"Kylin Linux Advanced Server V10 (Sword)"}}`)); os != "Kylin Linux Advanced Server V10 (Sword)" {
		t.Fatalf("系统显示名应原样保留: %q", os)
	}
	if _, _, os := inventory(json.RawMessage(`{"device":{"os":"  UnionTech OS Server 20E \n"}}`)); os != "UnionTech OS Server 20E" {
		t.Fatalf("系统显示名应清洗首尾空白: %q", os)
	}
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, v := range s {
		out[i] = netip.MustParseAddr(v)
	}
	return out
}

func TestClassifyPriority(t *testing.T) {
	dmz := &ent.Zone{ID: uuid.New(), Name: "DMZ", Kind: zone.KindDmz, Cidrs: []string{"10.1.0.0/16"}}
	office := &ent.Zone{ID: uuid.New(), Name: "办公网", Kind: zone.KindInternal, Cidrs: []string{"10.1.1.0/24"}}
	zones := []*ent.Zone{dmz, office}

	if z := Classify(addrs("10.1.1.5"), nil, nil, zones); z.Name != "办公网" || z.Source != "cidr" {
		t.Fatalf("网段取最长前缀: %+v", z)
	}
	if z := Classify(addrs("10.1.1.5"), nil, dmz, zones); z.Name != "DMZ" || z.Source != "manual" {
		t.Fatalf("手工指派优先: %+v", z)
	}
	if z := Classify(addrs("172.16.0.9"), &Cloud{Provider: "aws", InstanceID: "i-1"}, nil, zones); z.Kind != "cloud" || z.Name != "aws" {
		t.Fatalf("云元数据其次: %+v", z)
	}
	if z := Classify(addrs("100.121.204.45", "10.9.9.9", "fd7a:115c:a1e0::1"), nil, nil, nil); z.Kind != "internal" {
		t.Fatalf("CGNAT 与 ULA 不算公网: %+v", z)
	}
	if z := Classify(addrs("10.9.9.9", "8.8.8.8"), nil, nil, nil); z.Kind != "external" {
		t.Fatalf("带公网地址划入公网: %+v", z)
	}
}

func TestExposure(t *testing.T) {
	internal := Zone{Kind: "internal"}
	if Exposure(internal, addrs("10.0.0.1"), nil) != ExposureInternal {
		t.Fatal("纯内网")
	}
	if Exposure(internal, addrs("10.0.0.1"), &Cloud{Provider: "aws", InstanceID: "i-1", PublicIP: "3.3.3.3"}) != ExposureInternet {
		t.Fatal("云上有公网 IP 即公网可达")
	}
	if Exposure(Zone{Kind: "dmz"}, addrs("10.0.0.1"), nil) != ExposureDMZ {
		t.Fatal("DMZ")
	}
}

func TestDependencyFiltersNoise(t *testing.T) {
	own := addrs("10.1.1.2")
	cases := []struct {
		src, dst string
		want     bool
	}{
		{"10.1.1.2", "10.1.1.32", true},     // 宿主机连内网主机
		{"10.1.1.2", "8.8.8.8", true},       // 连公网
		{"172.18.0.3", "172.18.0.4", false}, // 同一网桥上的容器互连
		{"172.19.0.2", "10.1.1.4", true},    // 容器连出到内网其他主机
		{"10.1.1.2", "127.0.0.1", false},
		{"10.1.1.2", "224.0.0.251", false},
		{"10.1.1.2", "169.254.169.254", false},
		{"10.1.1.2", "100.100.100.200", false}, // 阿里云实例元数据
		{"10.1.1.2", "100.100.100.201", true},  // 同在 CGNAT 段的其他地址照常算
	}
	for _, c := range cases {
		got := dependency(conn{src: netip.MustParseAddr(c.src), dst: netip.MustParseAddr(c.dst), port: 80, proto: "tcp"}, own)
		if got != c.want {
			t.Errorf("%s → %s: got %v", c.src, c.dst, got)
		}
	}
	if !dependency(conn{src: netip.MustParseAddr("172.18.0.3"), dst: netip.MustParseAddr("172.18.0.4")}, nil) {
		t.Error("sensor 事件没有本机地址，不做容器判断")
	}
}

// 未指定的源地址换成资产自己的同族地址，私网优先；没有可用地址就不进图谱
func TestSourceOf(t *testing.T) {
	own := parseIPs([]string{"127.0.0.1", "100.121.204.45", "10.1.1.2", "fe80::1", "fd7a:115c:a1e0::a37:cc2e"})
	v4, v6 := netip.MustParseAddr("110.42.47.158"), netip.MustParseAddr("2001:db8::9")
	cases := []struct {
		src  netip.Addr
		dst  netip.Addr
		own  []netip.Addr
		want string
	}{
		{netip.MustParseAddr("192.0.2.1"), v4, own, "192.0.2.1"}, // 正常源地址原样
		{netip.IPv4Unspecified(), v4, own, "10.1.1.2"},
		{netip.Addr{}, v4, own, "10.1.1.2"},
		{netip.IPv6Unspecified(), v6, own, "fd7a:115c:a1e0::a37:cc2e"},
		{netip.Addr{}, v4, parseIPs([]string{"100.121.204.45"}), "100.121.204.45"}, // 没有私网地址取第一个可用的
		{netip.Addr{}, v6, parseIPs([]string{"10.1.1.2", "fe80::1"}), ""},          // 没有同族可用地址
		{netip.Addr{}, v4, nil, ""},                                                // sensor 事件没有资产
	}
	for _, c := range cases {
		got, ok := sourceOf(c.src, c.dst, c.own)
		if ok != (c.want != "") || (ok && got.String() != c.want) {
			t.Errorf("%v → %v: got %v %v, want %q", c.src, c.dst, got, ok, c.want)
		}
	}
	if dependency(conn{src: netip.IPv4Unspecified(), dst: v4}, nil) || dependency(conn{dst: v4}, nil) {
		t.Error("未指定或缺失的源地址不能成为依赖边的一端")
	}
}

func TestConnOf(t *testing.T) {
	c, ok := connOf(json.RawMessage(`{"src_endpoint":{"ip":"10.0.0.1","port":5000},"dst_endpoint":{"ip":"::ffff:10.0.0.2","port":5432},"process":{"pid":7,"name":"psql"}}`), "udp:10.0.0.1:5000>10.0.0.2:5432")
	if !ok || c.proto != "udp" || c.dst != netip.MustParseAddr("10.0.0.2") || c.port != 5432 || c.process != "psql" {
		t.Fatalf("%+v %v", c, ok)
	}
	if _, ok := connOf(json.RawMessage(`{"dst_endpoint":{"ip":"10.0.0.2","port":0}}`), ""); ok {
		t.Fatal("端口非法应丢弃")
	}
	if c, ok := connOf(json.RawMessage(`{"src_endpoint":{"port":41641},"dst_endpoint":{"ip":"10.0.0.2","port":41641}}`), ""); !ok || c.src.IsValid() {
		t.Fatalf("缺源地址的照收、源留空由调用方补：%+v %v", c, ok)
	}
	if _, ok := connOf(json.RawMessage(`{"src_endpoint":{"ip":"bogus"},"dst_endpoint":{"ip":"10.0.0.2","port":80}}`), ""); ok {
		t.Fatal("源地址写了但解析不了应丢弃")
	}
	// 容器里的进程记成「容器/进程」，没有名字用运行时与 ID；入站标出来
	for raw, want := range map[string]string{
		`"container":{"runtime":"docker","uid":"4f1c2a3b5d6e","name":"termix"}`: "termix/node",
		`"container":{"runtime":"lxc","uid":"203"}`:                             "lxc 203/node",
		`"connection_info":{"direction":"inbound"}`:                             "node",
	} {
		c, ok := connOf(json.RawMessage(`{"src_endpoint":{"ip":"10.0.0.1"},"dst_endpoint":{"ip":"10.0.0.2","port":80},"process":{"name":"node"},`+raw+`}`), "")
		if !ok || c.process != want || c.inbound != strings.Contains(raw, "inbound") {
			t.Fatalf("%s: %+v", raw, c)
		}
	}
}

func TestParseAnnotation(t *testing.T) {
	ann, err := parseAnnotation("好的：\n{\"role\":\"PostgreSQL 数据库\",\"summary\":\"业务库\",\"criticality\":5,\"reason\":\"被多台依赖\",\"relations\":[{\"peer\":\"web-01\",\"note\":\"读写业务库\"},{\"peer\":\"编造的\",\"note\":\"x\"}],\"services\":[{\"port\":\"udp/5405\",\"name\":\"Corosync\"},{\"port\":\"tcp/9999\",\"name\":\"编造\"}],\"egress\":[{\"ip\":\"1.2.3.4\",\"purpose\":\"Debian 软件源\"},{\"ip\":\"9.9.9.9\",\"purpose\":\"编造\"}]}", []string{"web-01"}, []string{"udp/5405"}, []string{"1.2.3.4"})
	// 公网用途只收 public 里给过的地址，和关系说明记在一起
	if err != nil || ann.Criticality != 5 || ann.Relations["web-01"] != "读写业务库" || ann.Relations["1.2.3.4"] != "Debian 软件源" || len(ann.Relations) != 2 || len(ann.Services) != 1 || ann.Services["udp/5405"].Source != "ai" {
		t.Fatalf("%+v %v", ann, err)
	}
	for _, bad := range []string{"没有 JSON", `{"role":"x","criticality":9}`, `{"role":"","criticality":3}`} {
		if _, err := parseAnnotation(bad, nil, nil, nil); err == nil {
			t.Errorf("应拒绝: %s", bad)
		}
	}
}

func TestFingerprintIgnoresVolatileFacts(t *testing.T) {
	f := Facts{Hostname: "db-01", Listening: []string{"tcp/5432 postgres"}, Programs: []string{"/usr/bin/a"}, PublicDestinations: 3}
	g := f
	g.Programs = append(g.Programs, "/usr/bin/b")
	g.PublicDestinations = 9
	g.Public = []PublicDest{{IP: "1.2.3.4", Ports: []string{"tcp/443"}}}
	if f.fingerprint() != g.fingerprint() {
		t.Fatal("程序清单与公网目的地变化不应触发重新标注")
	}
	g.Listening = append(g.Listening, "tcp/22 sshd")
	if f.fingerprint() == g.fingerprint() {
		t.Fatal("监听端口变化应触发重新标注")
	}
}

func testGroup(t *testing.T) *Group {
	t.Helper()
	gid := uuid.New()
	now := time.Now()
	crit := 5
	web := &ent.Asset{ID: uuid.New(), Hostname: "web-01", GroupID: &gid, IPAddrs: []string{"10.0.0.1", "203.0.113.10"}, LastSeen: now, InventoryAt: &now,
		Listening:     json.RawMessage(`[{"proto":"tcp","addr":"0.0.0.0","port":443,"process":"nginx"},{"proto":"tcp","addr":"::","port":443,"process":"nginx"},{"proto":"tcp","addr":"127.0.0.1","port":6379}]`),
		RelationNotes: map[string]string{"db-01": "读写业务库"}}
	db := &ent.Asset{ID: uuid.New(), Hostname: "db-01", GroupID: &gid, IPAddrs: []string{"10.0.0.2"}, LastSeen: now, InventoryAt: &now, Criticality: &crit,
		Listening:    json.RawMessage(`[{"proto":"tcp","addr":"0.0.0.0","port":5432,"process":"postgres"},{"proto":"udp","addr":"10.0.0.2","port":5405,"process":"corosync"}]`),
		ServiceNotes: json.RawMessage(`{"udp/5405":{"name":"Corosync 集群通信","risk":"low","source":"investigation"}}`)}
	old := &ent.Asset{ID: uuid.New(), Hostname: "old-01", GroupID: &gid, IPAddrs: []string{"10.0.0.3"}, LastSeen: now}
	other := uuid.New()
	elsewhere := &ent.Asset{ID: uuid.New(), Hostname: "secret", GroupID: &other, IPAddrs: []string{"10.0.9.9"}, LastSeen: now}
	all := []*ent.Asset{web, db, old, elsewhere}
	w := &World{Assets: all, ByIP: map[netip.Addr]*ent.Asset{}, ByID: map[uuid.UUID]*ent.Asset{}}
	for _, a := range all {
		w.ByID[a.ID] = a
		for _, ip := range parseIPs(a.IPAddrs) {
			w.ByIP[ip] = a
		}
	}
	link := func(src string, srcAsset *uuid.UUID, dst string, port int, process string, n int64) *ent.AssetLink {
		return &ent.AssetLink{SrcIP: src, SrcAssetID: srcAsset, DstIP: dst, DstPort: port, Proto: "tcp", Process: process, Count: n, LastSeen: now}
	}
	return &Group{World: w, Assets: []*ent.Asset{web, db, old}, Links: []*ent.AssetLink{
		link("10.0.0.1", &web.ID, "10.0.0.2", 5432, "nginx", 10),
		link("10.0.0.1", &web.ID, "1.1.1.1", 443, "curl", 3),
		link("198.51.100.7", nil, "203.0.113.10", 443, "", 50), // sensor 看到的公网访问
		link("10.0.0.2", &db.ID, "10.0.0.50", 22, "ssh", 4),    // 未纳管
		link("10.0.0.2", &db.ID, "10.0.9.9", 9100, "", 1),      // 别组资产
		link("10.0.0.77", nil, "10.0.0.2", 9187, "", 2),        // 未纳管地址主动访问本组服务
	}}
}

func TestGraph(t *testing.T) {
	g := testGroup(t).Graph(time.Now())
	kinds := map[string]string{}
	for _, n := range g.Nodes {
		kinds[n.Label] = n.Kind
		if n.Label == "secret" {
			t.Fatal("别组资产不能露主机名")
		}
	}
	if kinds["web-01"] != "asset" || kinds["10.0.0.50"] != "discovered" || kinds["10.0.9.9"] != "managed" || kinds["internet"] != "internet" {
		t.Fatalf("节点类型: %v", kinds)
	}
	var note string
	for _, e := range g.Edges {
		if e.Ports[0] == "tcp/5432" {
			note = e.Note
		}
	}
	if note != "读写业务库" {
		t.Fatalf("边上应带 AI 关系说明: %q", note)
	}
}

func TestSurface(t *testing.T) {
	s := testGroup(t).Surface()
	if len(s.Exposures) != 3 {
		t.Fatalf("回环监听不算暴露面，双栈合成一条: %+v", s.Exposures)
	}
	if got := s.Exposures[0].Addrs; len(got) != 2 {
		t.Fatalf("双栈地址并列: %v", got)
	}
	top := s.Exposures[0]
	if top.Hostname != "web-01" || top.Level != ExposureInternet || !top.FromPublic || top.Peers[0] != "198.51.100.7" {
		t.Fatalf("带公网 IP 的主机按公网暴露，且记下公网来源: %+v", top)
	}
	pg := s.Exposures[1]
	if pg.Level != ExposureInternal || pg.Service.Name != "PostgreSQL" || pg.Peers[0] != "web-01" || pg.Score != Score(ExposureInternal, "high", pg.Criticality) {
		t.Fatalf("%+v", pg)
	}
	if len(s.Blind) != 2 || s.Blind[0].IP != "10.0.0.50" || s.Blind[1].Accessed[0] != "db-01:9187" {
		t.Fatalf("主动访问本组的未纳管地址也是盲区: %+v", s.Blind)
	}
	if s.Blind[0].IP != "10.0.0.50" || s.Blind[0].SeenBy[0] != "db-01" || s.Blind[0].Ports[0] != "tcp/22" {
		t.Fatalf("盲区只算未纳管地址: %+v", s.Blind)
	}
	if len(s.Summary.NoInventory) != 1 || s.Summary.NoInventory[0] != "old-01" {
		t.Fatalf("没上报清单的资产要点名: %+v", s.Summary.NoInventory)
	}
}

func TestSurfaceNotesAndPaths(t *testing.T) {
	g := testGroup(t)
	s := g.Surface()
	var corosync *ExposedService
	for i, e := range s.Exposures {
		if e.Port == 5405 {
			corosync = &s.Exposures[i]
		}
	}
	if corosync == nil || corosync.Service.Name != "Corosync 集群通信" || corosync.Service.Risk != "low" || corosync.Note.Source != "investigation" {
		t.Fatalf("服务说明应覆盖端口推测: %+v", corosync)
	}
	web, db := g.Assets[0], g.Assets[1]
	want := map[string]bool{"internet>" + web.ID.String() + ">tcp/443": false, web.ID.String() + ">" + db.ID.String() + ">tcp/5432": false}
	for _, p := range s.Paths {
		k := p.From + ">" + p.AssetID.String() + ">" + p.Service
		if _, ok := want[k]; ok {
			want[k] = true
		}
	}
	for k, ok := range want {
		if !ok {
			t.Errorf("缺少访问路径 %s: %+v", k, s.Paths)
		}
	}
	kinds := map[string]string{}
	for _, p := range s.Peers {
		kinds[p.ID] = p.Kind
	}
	if kinds["internet"] != "internet" || kinds[web.ID.String()] != "asset" {
		t.Fatalf("访问方: %+v", s.Peers)
	}
}

func TestServicePort(t *testing.T) {
	for in, want := range map[string]string{"udp/5405": "udp/5405", "udp/5405 corosync /usr/sbin/corosync": "udp/5405", "9100/tcp": "tcp/9100", " tcp/22 ": "tcp/22"} {
		if got := servicePort(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

// 已携带名字的新版事件、入站事件和无效连接不应访问历史事件表。
func TestProcessNamesAvoidsUnneededDatabaseLookup(t *testing.T) {
	guid := uuid.New()
	events := []*ent.Event{
		{ClassUID: classNetwork, ProcessGUID: &guid, Raw: json.RawMessage(`{"dst_endpoint":{"ip":"8.8.8.8","port":443},"process":{"name":"curl"}}`)},
		{ClassUID: classNetwork, ProcessGUID: &guid, Raw: json.RawMessage(`{"dst_endpoint":{"ip":"10.0.0.1","port":443},"connection_info":{"direction":"inbound"}}`)},
		{ClassUID: classNetwork, ProcessGUID: &guid, Raw: json.RawMessage(`{"dst_endpoint":{"ip":"invalid","port":443}}`)},
	}
	e := &Engine{}
	names, err := e.processNames(context.Background(), events)
	if err != nil || len(names) != 0 {
		t.Fatalf("无需回查却返回结果: %v %v", names, err)
	}
}
