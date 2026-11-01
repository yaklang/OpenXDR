package assetmap

import (
	"cmp"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/uuid"
	"openxdr/server/ent"
)

// conn 一条网络事件的两端：src 是发起方
type conn struct {
	src, dst netip.Addr
	port     int
	proto    string
	process  string
	// inbound agent 在服务端看到的入站：进程是本机的服务进程，不是发起方
	inbound bool
}

// connOf 从网络事件取出两端。agent 与 sensor 的事件体同一约定：src_endpoint / dst_endpoint。
// 源地址可以缺省（agent 的 UDP 出站查不到出口地址时不写），此时 src 为零值，由调用方按资产补上。
// 协议取 conn_tuple 的前缀，缺省按 tcp。进程在容器里时记成「容器/进程」，图上分得清是哪个容器发起的
func connOf(raw json.RawMessage, tuple string) (conn, bool) {
	var body struct {
		Src struct {
			IP string `json:"ip"`
		} `json:"src_endpoint"`
		Dst struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"dst_endpoint"`
		Process struct {
			Name string `json:"name"`
		} `json:"process"`
		Container struct {
			UID     string `json:"uid"`
			Name    string `json:"name"`
			Runtime string `json:"runtime"`
		} `json:"container"`
		Info struct {
			Direction string `json:"direction"`
		} `json:"connection_info"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return conn{}, false
	}
	var src netip.Addr
	var err1 error
	if body.Src.IP != "" {
		src, err1 = netip.ParseAddr(body.Src.IP)
	}
	dst, err2 := netip.ParseAddr(body.Dst.IP)
	if err1 != nil || err2 != nil || body.Dst.Port < 1 || body.Dst.Port > 65535 {
		return conn{}, false
	}
	proto := "tcp"
	if p, _, ok := strings.Cut(tuple, ":"); ok && (p == "tcp" || p == "udp") {
		proto = p
	}
	process := clean(body.Process.Name, 64)
	if label := clean(cmp.Or(body.Container.Name, strings.TrimSpace(body.Container.Runtime+" "+body.Container.UID)), 64); label != "" && process != "" {
		process = label + "/" + process
	}
	return conn{src.Unmap(), dst.Unmap(), body.Dst.Port, proto, process, body.Info.Direction == "inbound"}, true
}

// sourceOf 发起方地址。未 connect 的 UDP 套接字在 agent 上看到的源地址是未指定地址
// （旧版 agent 照报 0.0.0.0 / ::，新版查不到出口地址时省略），它不是一台主机——发起方就是
// 上报的资产本身，记成它登记的与目的同族的地址，私网地址优先（出公网的包多半从私网地址经 NAT 出去）。
// 资产没有可用地址时返回 false：说不清是谁发起的连接不进图谱，不编一个节点出来。
func sourceOf(src, dst netip.Addr, own []netip.Addr) (netip.Addr, bool) {
	if src.IsValid() && !src.IsUnspecified() {
		return src, true
	}
	var pick netip.Addr
	for _, a := range own {
		if a.Is4() != dst.Is4() || a.IsUnspecified() || a.IsLoopback() || a.IsLinkLocalUnicast() {
			continue
		}
		if a.IsPrivate() {
			return a, true
		}
		if !pick.IsValid() {
			pick = a
		}
	}
	return pick, pick.IsValid()
}

// instanceMetadata 不在链路本地段里的实例元数据地址：阿里云 IMDS 在 CGNAT 段、AWS 的 IPv6 IMDS 在 ULA 段。
// 各家都是每台实例本机的服务，agent 启动识别云环境、cloud-init 都会连，不是资产间的依赖；
// 169.254.169.254（AWS/Azure/GCP）与 169.254.0.23（腾讯云）已按链路本地剔掉
var instanceMetadata = []netip.Addr{netip.MustParseAddr("100.100.100.200"), netip.MustParseAddr("fd00:ec2::254")}

// dependency 这条连接算不算资产间的依赖。own 是上报 agent 所在资产的地址，sensor 事件为空。
//
// 未指定的源地址不是节点（发起方先经 sourceOf 换成资产自己的地址）。
// 回环、组播、链路本地、云厂商实例元数据服务、自己连自己都不算。另有一类要剔掉：源地址不是本机登记的地址、
// 目的又和源同在一个私网段——这是宿主机里容器之间的通信（docker 网桥），
// 不该在图上长出一台「未纳管主机」。
func dependency(c conn, own []netip.Addr) bool {
	d := c.dst
	if !c.src.IsValid() || c.src.IsUnspecified() || !d.IsValid() || d.IsLoopback() || d.IsUnspecified() || d.IsMulticast() ||
		d.IsLinkLocalUnicast() || d.IsLinkLocalMulticast() || slices.Contains(instanceMetadata, d) || c.src == d {
		return false
	}
	if len(own) == 0 || slices.Contains(own, c.src) || !d.IsPrivate() {
		return true
	}
	bits := 16
	if d.Is6() {
		bits = 64
	}
	srcNet, _ := c.src.Prefix(bits)
	return !srcNet.Contains(d)
}

// eventLink 统一日常消费和历史核对使用的连接身份与过滤规则。
func eventLink(ev *ent.Event, own map[uuid.UUID][]netip.Addr, names map[uuid.UUID]string, managed map[netip.Addr]bool) (linkKey, *uuid.UUID, bool) {
	tuple := ""
	if ev.ConnTuple != nil {
		tuple = *ev.ConnTuple
	}
	c, ok := connOf(ev.Raw, tuple)
	if !ok {
		return linkKey{}, nil, false
	}
	srcAsset, process := ev.AssetID, c.process
	var ownIPs []netip.Addr
	if ev.AssetID != nil {
		ownIPs = own[*ev.AssetID]
	}
	// sensor 会话源地址不是纳管资产时归到目的端（公网打进网关的），发起方不是这台资产，按入站记
	if ev.Source == "sensor" && ev.AssetID != nil && !slices.Contains(ownIPs, c.src) {
		c.inbound = true
	}
	if c.inbound {
		// 入站只补发起方未纳管的那部分：发起方纳管时它自己的出站已经记过这条依赖。
		// 只认连到宿主机自己地址上的：宿主机上容器的服务（docker 网桥、LXC）不是这台资产的服务。
		// 发起方由地址解析，进程是本机服务端，不是发起方，不记
		if managed[c.src] || !slices.Contains(ownIPs, c.dst) || !dependency(c, nil) {
			return linkKey{}, nil, false
		}
		srcAsset, process = nil, ""
	} else {
		if c.src, ok = sourceOf(c.src, c.dst, ownIPs); !ok || !dependency(c, ownIPs) {
			return linkKey{}, nil, false
		}
		// 新版 agent 随连接带进程名；旧版只有 GUID，回查同一进程的启动事件
		if process == "" && ev.ProcessGUID != nil {
			process = names[*ev.ProcessGUID]
		}
	}
	return linkKey{c.src.String(), c.dst.String(), c.port, c.proto, process}, srcAsset, true
}
