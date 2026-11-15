package questions

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/setting"
	"openxdr/server/internal/facts"
)

type certCacheEntry struct {
	path  string
	mtime time.Time
	ips   []string
	hosts []string
}

var certCache struct {
	mu sync.Mutex
	e  certCacheEntry
}

type platformIndex struct {
	ips      map[string][]string
	domains  map[string][]string
	assetRef map[string]uuid.UUID
}

func newPlatformIndex() *platformIndex {
	return &platformIndex{
		ips:      map[string][]string{},
		domains:  map[string][]string{},
		assetRef: map[string]uuid.UUID{},
	}
}

func (p *platformIndex) addAddr(raw, role string, assetID *uuid.UUID) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		if !prefix.IsSingleIP() {
			return
		}
		raw = prefix.Addr().Unmap().String()
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		addr = addr.Unmap()
		if !isUsablePlatformIP(addr) {
			return
		}
		key := addr.String()
		if !slices.Contains(p.ips[key], role) {
			p.ips[key] = append(p.ips[key], role)
		}
		if assetID != nil && *assetID != uuid.Nil {
			if _, exists := p.assetRef[key]; !exists {
				p.assetRef[key] = *assetID
			}
		}
		return
	}
	host := strings.TrimSuffix(strings.ToLower(raw), ".")
	if !isUsablePlatformHost(host) {
		return
	}
	if !slices.Contains(p.domains[host], role) {
		p.domains[host] = append(p.domains[host], role)
	}
	if assetID != nil && *assetID != uuid.Nil {
		if _, exists := p.assetRef[host]; !exists {
			p.assetRef[host] = *assetID
		}
	}
}

func (p *platformIndex) addEndpoint(raw, role string) {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "://") {
			u, err := url.Parse(part)
			if err != nil || u.Hostname() == "" {
				continue
			}
			p.addAddr(u.Hostname(), role, nil)
			continue
		}
		// 兼容 host:port 或裸 IP / 域名 / 单机 CIDR
		if h, _, err := net.SplitHostPort(part); err == nil {
			p.addAddr(h, role, nil)
			continue
		}
		p.addAddr(part, role, nil)
	}
}

func isUsablePlatformIP(addr netip.Addr) bool {
	return addr.IsValid() &&
		!addr.IsLoopback() &&
		!addr.IsUnspecified() &&
		!addr.IsMulticast() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast()
}

func isUsablePlatformHost(host string) bool {
	if host == "" || host == "localhost" || host == "host.docker.internal" || strings.HasPrefix(host, "*.") {
		return false
	}
	return domainRE.MatchString(host)
}

func tlsCertSANs(path string) (ips, hosts []string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, nil
	}
	certCache.mu.Lock()
	defer certCache.mu.Unlock()
	if certCache.e.path == path && certCache.e.mtime.Equal(st.ModTime()) {
		return certCache.e.ips, certCache.e.hosts
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil
	}
	for _, ip := range cert.IPAddresses {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			ips = append(ips, addr.Unmap().String())
		}
	}
	for _, d := range cert.DNSNames {
		hosts = append(hosts, d)
	}
	certCache.e = certCacheEntry{path: path, mtime: st.ModTime(), ips: ips, hosts: hosts}
	return ips, hosts
}

// assetComponentRoles 从资产自身的监听进程与运行容器中确定性识别 OpenXDR 平台自身组件角色
func assetComponentRoles(a *ent.Asset) (roles []string, containerAddrs []string) {
	addRole := func(r string) {
		if !slices.Contains(roles, r) {
			roles = append(roles, r)
		}
	}
	if len(a.Listening) > 0 {
		var ports []struct {
			Process string `json:"process"`
		}
		if json.Unmarshal(a.Listening, &ports) == nil {
			for _, p := range ports {
				switch strings.TrimSpace(p.Process) {
				case "openxdr-server":
					addRole("OpenXDR Server 节点")
				case "sandboxd":
					addRole("OpenXDR Pi 沙箱节点（sandboxd）")
				}
			}
		}
	}
	if len(a.Containers) > 0 {
		var cs []struct {
			Name  string   `json:"name"`
			Addrs []string `json:"addrs"`
		}
		if json.Unmarshal(a.Containers, &cs) == nil {
			for _, c := range cs {
				name := strings.TrimSpace(c.Name)
				matched := false
				switch {
				case name == "openxdr-witness" || strings.HasPrefix(name, "openxdr-witness-"):
					addRole("OpenXDR NATS/etcd 见证节点")
					matched = true
				case name == "openxdr-pi-sandbox" || strings.HasPrefix(name, "openxdr-pi-sandbox-"):
					addRole("OpenXDR Pi 沙箱容器")
					matched = true
				case name == "openxdr-server" || strings.HasPrefix(name, "openxdr-server-") || strings.HasPrefix(name, "openxdr-ha-"):
					addRole("OpenXDR 平台服务容器")
					matched = true
				}
				if matched {
					containerAddrs = append(containerAddrs, c.Addrs...)
				}
			}
		}
	}
	return roles, containerAddrs
}

func buildPlatformIndex(ctx context.Context, db *ent.Client) (*platformIndex, error) {
	idx := newPlatformIndex()
	for _, spec := range []struct {
		env  string
		role string
	}{
		{"ENROLL_GRPC_URL", "采集接入端点 / VIP"},
		{"ENROLL_PUBLIC_URL", "控制台入口"},
		{"WEBHOOK_LINK_BASE", "控制台入口"},
		{"ISOLATION_ALLOW", "服务端接入端点 / VIP"},
		{"SANDBOX_URL", "Pi 沙箱（sandboxd）"},
		{"NATS_URL", "NATS 事件队列 / 见证节点"},
		{"DATABASE_URL", "数据库节点"},
		{"SELFWATCH_PATRONI_URL", "Patroni 高可用管控端点"},
	} {
		if v := strings.TrimSpace(os.Getenv(spec.env)); v != "" {
			idx.addEndpoint(v, spec.role)
		}
	}
	ips, hosts := tlsCertSANs(os.Getenv("TLS_CERT_FILE"))
	for _, ip := range ips {
		idx.addAddr(ip, "服务端证书端点 / VIP", nil)
	}
	for _, h := range hosts {
		idx.addAddr(h, "服务端证书端点 / VIP", nil)
	}

	if row, err := db.Setting.Get(ctx, "notify"); err == nil && len(row.Value) > 0 {
		var cfg struct {
			LinkBase string `json:"linkBase"`
		}
		if json.Unmarshal(row.Value, &cfg) == nil && cfg.LinkBase != "" {
			idx.addEndpoint(cfg.LinkBase, "控制台入口")
		}
	} else if err != nil && !ent.IsNotFound(err) && !strings.Contains(err.Error(), setting.Table) {
		return nil, err
	}

	assets, err := db.Asset.Query().
		Where(asset.RetiredAtIsNil()).
		Select(asset.FieldID, asset.FieldHostname, asset.FieldIPAddrs, asset.FieldListening, asset.FieldContainers).
		All(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range assets {
		roles, cAddrs := assetComponentRoles(a)
		if len(roles) == 0 {
			continue
		}
		id := a.ID
		for _, r := range roles {
			// Server 节点的 ip_addrs 同时包含节点地址与 Keepalived 漂移到本机的 VIP
			for _, ip := range a.IPAddrs {
				idx.addAddr(ip, r, &id)
			}
			for _, ip := range cAddrs {
				idx.addAddr(ip, r, &id)
			}
			idx.addAddr(a.Hostname, r, &id)
		}
	}
	return idx, nil
}

// lookupPlatform 平台自我认知：从服务端配置、TLS 证书与在线资产清单中确定性识别平台自身组件。
// 归属类问题直接作为权威记录返回（Answered=true）；授权/权限/策略类只挂进 Context 作参考，绝不把平台自身组件自动当作外部操作授权。
func lookupPlatform(ctx context.Context, db *ent.Client, req Request, res *Result) error {
	switch req.SubjectKind {
	case "ip", "domain", "asset", "change":
	default:
		return nil
	}
	idx, err := buildPlatformIndex(ctx, db)
	if err != nil {
		return err
	}

	var roles []string
	ref := "SYS-openxdr"

	switch req.SubjectKind {
	case "ip":
		p, err := facts.Prefix(req.Subject)
		if err != nil || !p.IsSingleIP() {
			return nil
		}
		ip := p.Addr().Unmap().String()
		roles = idx.ips[ip]
		if aid, ok := idx.assetRef[ip]; ok {
			ref = facts.Ref("A", aid)
		}
	case "domain":
		d := strings.TrimSuffix(strings.ToLower(req.Subject), ".")
		roles = idx.domains[d]
		if aid, ok := idx.assetRef[d]; ok {
			ref = facts.Ref("A", aid)
		}
	case "asset", "change":
		aid, ok := SubjectAsset(req.SubjectKind, req.Subject)
		if !ok {
			return nil
		}
		host, err := db.Asset.Get(ctx, aid)
		if ent.IsNotFound(err) || (err == nil && host.RetiredAt != nil) {
			return nil
		}
		if err != nil {
			return err
		}
		rList, _ := assetComponentRoles(host)
		for _, r := range rList {
			if !slices.Contains(roles, r) {
				roles = append(roles, r)
			}
		}
		for _, ip := range host.IPAddrs {
			if addr, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
				for _, r := range idx.ips[addr.Unmap().String()] {
					if !slices.Contains(roles, r) {
						roles = append(roles, r)
					}
				}
			}
		}
		hKey := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host.Hostname)), ".")
		for _, r := range idx.domains[hKey] {
			if !slices.Contains(roles, r) {
				roles = append(roles, r)
			}
		}
		if len(roles) > 0 {
			ref = facts.Ref("A", host.ID)
		}
	}

	if len(roles) == 0 {
		return nil
	}
	rec := Record{
		Ref:    ref,
		Kind:   "platform_component",
		Detail: "这是 OpenXDR 平台自身组件（" + strings.Join(roles, "、") + "）",
	}
	if req.Kind == "owner" {
		res.Records = append(res.Records, rec)
	} else {
		res.Context = append(res.Context, rec)
	}
	return nil
}
