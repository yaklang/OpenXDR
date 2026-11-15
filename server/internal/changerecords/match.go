// Package changerecords 从外部代码与配置仓库增量拉取变更记录，确定性关联纳管资产，
// 并作为非权威的时间线佐证注入 AI 研判、Pi 调查与独立结案审计。
package changerecords

import (
	"cmp"
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/fact"
)

// MatchInput 待抽取资产线索的一条提交记录（不含文件内容与 diff）。
type MatchInput struct {
	Title string
	Body  string
	Files []string
}

// AssetMatch 命中某台纳管资产的确定性关联结果。
type AssetMatch struct {
	AssetID uuid.UUID
	Clues   []string
}

type vmidOwner struct {
	assetID uuid.UUID
	pveHost string // 小写 PVE 宿主机名；未知时为空
}

// Snapshot 纳管资产的确定性线索索引快照。
// 同名裸主机名或共享桥接地址（如多台 Docker 主机共用的 172.17.0.1）出现歧义时不盲目关联，宁漏勿串。
type Snapshot struct {
	hostByID  map[uuid.UUID]string
	fqdnToIDs map[string][]uuid.UUID
	hostToIDs map[string][]uuid.UUID
	lxcToIDs  map[string][]uuid.UUID
	hostIPs   map[netip.Addr][]uuid.UUID
	guestIPs  map[netip.Addr][]uuid.UUID
	vmids     map[string][]vmidOwner
}

var (
	ipv4TokenRe = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	ipv6TokenRe = regexp.MustCompile(`(?i)[0-9a-f]{0,4}:[0-9a-f:]{2,38}`)
	// 显式带宿主机前缀的 VM/CT 引用，如「pve1 VM 116」「pve2 CT 100」；前缀须真为纳管主机名才按宿主机限定。
	qualifiedVMIDRe = regexp.MustCompile(`(?i)([a-z0-9][a-z0-9-]{1,62})\s+(?:vm|ct|lxc)\s*#?(\d{2,9})`)
	// PVE 节点配置文件路径，如 nodes/pve1/lxc/100.conf、/etc/pve/qemu-server/145.conf。
	nodePVEConfRe = regexp.MustCompile(`(?i)(?:^|/)nodes/([a-z0-9][a-z0-9-]{0,62})/(?:lxc|qemu-server)/(\d{2,9})\.conf`)
	barePVEConfRe = regexp.MustCompile(`(?i)(?:^|/)(?:lxc|qemu-server)/(\d{2,9})\.conf`)
	// 独立 VM/CT 编号，如「VM 145」「vm-145」「CT 100」「VMID: 103」「LXC100」。
	bareVMIDRe     = regexp.MustCompile(`(?i)(?:vmid|vm|ct|lxc)(?:[\s#:=]+|-)?(\d{2,9})`)
	hostSelfVMIDRe = regexp.MustCompile(`(?i)^(?:vm|ct|lxc)-?(\d{2,9})$`)
)

var ignoredHostnames = map[string]bool{
	"localhost":             true,
	"localhost.localdomain": true,
	"broadcasthost":         true,
}

// configExts 配置文件或文档常见后缀：`hosts/gateway.yml` 中的 `gateway` 视作候选主机标识。
var configExts = map[string]bool{
	"yml": true, "yaml": true, "conf": true, "cfg": true, "ini": true,
	"json": true, "toml": true, "md": true, "txt": true, "sh": true,
	"rules": true, "service": true, " caddyfile": true, "dpapi": true,
}

// codeExts 应用源码文件后缀：源码路径（如 server/internal/cache/store.go）不抽取纯字母单词作裸主机名，避免代码目录撞名。
var codeExts = map[string]bool{
	".go": true, ".rs": true, ".ts": true, ".tsx": true, ".js": true, ".jsx": true,
	".css": true, ".scss": true, ".html": true, ".proto": true, ".sql": true,
	".sum": true, ".mod": true, ".lock": true, ".c": true, ".h": true, ".py": true,
}

var internalDomainMarkers = []string{"internal", "node", "yuzhian", "local", "lan", "corp", "intra"}

// LoadSnapshot 从数据库加载纳管资产及有效 asset_role 事实，构建确定性匹配快照。
func LoadSnapshot(ctx context.Context, db *ent.Client, now time.Time) (*Snapshot, error) {
	assets, err := db.Asset.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	roleFacts, err := db.Fact.Query().Where(
		fact.KindEQ("asset_role"),
		fact.AssetIDNotNil(),
		fact.RetiredAtIsNil(),
		fact.Or(fact.ExpiresAtIsNil(), fact.ExpiresAtGT(now)),
	).All(ctx)
	if err != nil {
		return nil, err
	}
	return BuildSnapshot(assets, roleFacts), nil
}

// BuildSnapshot 纯内存构建匹配快照，便于单元测试直接喂入资产与角色事实。
func BuildSnapshot(assets []*ent.Asset, roleFacts []*ent.Fact) *Snapshot {
	s := &Snapshot{
		hostByID:  make(map[uuid.UUID]string, len(assets)),
		fqdnToIDs: map[string][]uuid.UUID{},
		hostToIDs: map[string][]uuid.UUID{},
		lxcToIDs:  map[string][]uuid.UUID{},
		hostIPs:   map[netip.Addr][]uuid.UUID{},
		guestIPs:  map[netip.Addr][]uuid.UUID{},
		vmids:     map[string][]vmidOwner{},
	}
	addUnique := func(m map[string][]uuid.UUID, key string, id uuid.UUID) {
		if key == "" || ignoredHostnames[key] {
			return
		}
		if !slices.Contains(m[key], id) {
			m[key] = append(m[key], id)
		}
	}
	addIP := func(m map[netip.Addr][]uuid.UUID, raw string, id uuid.UUID) {
		addr, ok := parseMatchableIP(raw)
		if !ok {
			return
		}
		if !slices.Contains(m[addr], id) {
			m[addr] = append(m[addr], id)
		}
	}
	addVMID := func(vmid, pveHost string, id uuid.UUID) {
		vmid = strings.TrimLeft(vmid, "0")
		if vmid == "" {
			return
		}
		pveHost = strings.ToLower(strings.TrimSpace(pveHost))
		cur := s.vmids[vmid]
		for i := range cur {
			if cur[i].assetID == id {
				if cur[i].pveHost == "" && pveHost != "" {
					cur[i].pveHost = pveHost
				}
				return
			}
		}
		s.vmids[vmid] = append(cur, vmidOwner{assetID: id, pveHost: pveHost})
	}

	// 第一遍登记各资产自身的主机名与 IP，供第二遍将宿主机上的 LXC 容器反查到独立纳管的客体资产。
	for _, a := range assets {
		s.hostByID[a.ID] = a.Hostname
		h := normalizeHostname(a.Hostname)
		if h != "" && !ignoredHostnames[h] {
			if strings.Contains(h, ".") {
				addUnique(s.fqdnToIDs, h, a.ID)
				short, _, _ := strings.Cut(h, ".")
				if len(short) >= 3 {
					addUnique(s.hostToIDs, short, a.ID)
				}
			} else if len(h) >= 3 {
				addUnique(s.hostToIDs, h, a.ID)
			}
			if m := hostSelfVMIDRe.FindStringSubmatch(h); len(m) == 2 {
				addVMID(m[1], "", a.ID)
			}
		}
		for _, ip := range a.IPAddrs {
			addIP(s.hostIPs, ip, a.ID)
		}
	}

	// 第二遍登记宿主机上报的 LXC / QEMU 容器清单：既关联宿主机，也在客体已独立纳管时同步关联客体资产。
	type hostedEntry struct {
		Runtime string   `json:"runtime"`
		UID     string   `json:"uid"`
		Name    string   `json:"name"`
		Addrs   []string `json:"addrs"`
	}
	for _, a := range assets {
		if len(a.Containers) == 0 {
			continue
		}
		var hosted []hostedEntry
		if json.Unmarshal(a.Containers, &hosted) != nil {
			continue
		}
		pveHost := shortHostname(a.Hostname)
		for _, c := range hosted {
			rt := strings.ToLower(strings.TrimSpace(c.Runtime))
			if rt != "lxc" && rt != "qemu" {
				continue
			}
			cname := normalizeHostname(c.Name)
			if rt == "lxc" && len(cname) >= 3 {
				addUnique(s.lxcToIDs, cname, a.ID)
			}
			for _, ip := range c.Addrs {
				addIP(s.guestIPs, ip, a.ID)
			}
			uid := strings.TrimSpace(c.UID)
			if isDigits(uid) && len(uid) >= 2 && len(uid) <= 9 {
				addVMID(uid, pveHost, a.ID)
				if cname != "" && len(s.hostToIDs[cname]) == 1 {
					addVMID(uid, pveHost, s.hostToIDs[cname][0])
				}
				for _, ip := range c.Addrs {
					if addr, ok := parseMatchableIP(ip); ok && len(s.hostIPs[addr]) == 1 {
						addVMID(uid, pveHost, s.hostIPs[addr][0])
					}
				}
			}
		}
	}

	// 第三遍从管理员录入的权威 asset_role 事实中提取显式声明的 VMID（如「pve2 VM 103」），弥补 QEMU 虚拟机不入宿主机容器清单。
	for _, f := range roleFacts {
		if f.AssetID == nil || s.hostByID[*f.AssetID] == "" {
			continue
		}
		for _, ref := range s.extractVMIDRefs(f.Content) {
			addVMID(ref.vmid, ref.host, *f.AssetID)
		}
	}
	return s
}

// Hostname 返回快照里记录的资产主机名。
func (s *Snapshot) Hostname(id uuid.UUID) string {
	if s == nil {
		return ""
	}
	return s.hostByID[id]
}

// Match 从提交说明与改动文件路径确定性抽取线索并匹配纳管资产。
func (s *Snapshot) Match(in MatchInput) []AssetMatch {
	if s == nil || len(s.hostByID) == 0 {
		return nil
	}
	cluesByAsset := map[uuid.UUID][]string{}
	record := func(id uuid.UUID, clue string) {
		if s.hostByID[id] == "" {
			return
		}
		if !slices.Contains(cluesByAsset[id], clue) {
			cluesByAsset[id] = append(cluesByAsset[id], clue)
		}
	}

	msgText := in.Title
	if in.Body != "" {
		msgText += "\n" + in.Body
	}
	allTexts := make([]string, 0, 1+len(in.Files))
	if msgText != "" {
		allTexts = append(allTexts, msgText)
	}
	allTexts = append(allTexts, in.Files...)

	// 1. 抽取并匹配 IPv4 / IPv6（仅当该地址唯一归属单台主机或单台容器宿主机时关联，跳过多机共用的网桥地址）。
	for _, text := range allTexts {
		for _, ip := range extractIPs(text) {
			clue := "ip:" + ip.String()
			if owners := s.hostIPs[ip]; len(owners) == 1 {
				record(owners[0], clue)
			}
			if guests := s.guestIPs[ip]; len(guests) == 1 {
				record(guests[0], clue)
			}
		}
	}

	// 2. 抽取并匹配 PVE VMID（支持「pve1 VM 116」、nodes/pve1/lxc/100.conf、lxc/100.conf、「VM 145」、「CT 100」）。
	matchVMID := func(rawID, hostHint string) {
		vmid := strings.TrimLeft(rawID, "0")
		if vmid == "" {
			return
		}
		hostHint = strings.ToLower(strings.TrimSpace(hostHint))
		if hostHint != "" {
			if hosts := s.hostToIDs[hostHint]; len(hosts) == 1 {
				record(hosts[0], "host:"+hostHint)
			}
		}
		owners := s.vmids[vmid]
		if len(owners) == 0 {
			return
		}
		clue := "vmid:" + vmid
		if hostHint != "" {
			var scoped []uuid.UUID
			for _, o := range owners {
				if o.pveHost == hostHint || o.pveHost == "" {
					scoped = append(scoped, o.assetID)
				}
			}
			for _, id := range scoped {
				record(id, clue)
			}
			return
		}
		// 未带宿主机限定时，若同一 VMID 分布在多台不同 PVE 宿主机上则视为歧义跳过；单台 PVE（宿主机+客体）正常关联。
		distinctPVE := map[string]bool{}
		for _, o := range owners {
			if o.pveHost != "" {
				distinctPVE[o.pveHost] = true
			}
		}
		if len(distinctPVE) > 1 {
			return
		}
		for _, o := range owners {
			record(o.assetID, clue)
		}
	}

	for _, text := range allTexts {
		for _, ref := range s.extractVMIDRefs(text) {
			matchVMID(ref.vmid, ref.host)
		}
	}

	// 3. 抽取并匹配主机名、rs-<host> SSH 别名、内网 FQDN 与 LXC 容器名。
	if msgText != "" {
		s.matchTextTokens(msgText, false, record)
	}
	for _, f := range in.Files {
		s.matchTextTokens(f, isCodePath(f), record)
	}

	if len(cluesByAsset) == 0 {
		return nil
	}
	out := make([]AssetMatch, 0, len(cluesByAsset))
	for id, clues := range cluesByAsset {
		slices.Sort(clues)
		out = append(out, AssetMatch{AssetID: id, Clues: clues})
	}
	slices.SortFunc(out, func(a, b AssetMatch) int {
		return cmp.Compare(a.AssetID.String(), b.AssetID.String())
	})
	return out
}

func (s *Snapshot) matchTextTokens(text string, codeFile bool, record func(uuid.UUID, string)) {
	lower := strings.ToLower(text)
	// 先按含点链路（FQDN 或文件名如 gateway.yml）识别，再扫描独立标识符 token。
	for _, chain := range extractDotChains(lower) {
		if ids := s.fqdnToIDs[chain]; len(ids) == 1 {
			record(ids[0], "fqdn:"+chain)
		}
		parts := strings.Split(chain, ".")
		if len(parts) >= 2 && len(parts[0]) >= 3 {
			first := parts[0]
			if slices.ContainsFunc(parts[1:], func(lbl string) bool { return slices.Contains(internalDomainMarkers, lbl) }) {
				if ids := s.hostToIDs[first]; len(ids) == 1 {
					record(ids[0], "fqdn:"+first)
				}
				if ids := s.lxcToIDs[first]; len(ids) == 1 {
					record(ids[0], "lxc:"+first)
				}
			} else if len(parts) == 2 && configExts[parts[1]] && (!codeFile || !isPureAlpha(first)) {
				s.matchBareToken(first, record)
			}
		}
	}

	for _, tok := range extractStandaloneTokens(lower) {
		if host, ok := strings.CutPrefix(tok, "rs-"); ok && len(host) >= 3 {
			if ids := s.hostToIDs[host]; len(ids) == 1 {
				record(ids[0], "alias:rs-"+host)
			}
			if ids := s.lxcToIDs[host]; len(ids) == 1 {
				record(ids[0], "lxc:"+host)
			}
		}
		if codeFile && isPureAlpha(tok) {
			continue
		}
		s.matchBareToken(tok, record)
	}
}

func (s *Snapshot) matchBareToken(tok string, record func(uuid.UUID, string)) {
	if len(tok) < 3 || ignoredHostnames[tok] {
		return
	}
	if ids := s.hostToIDs[tok]; len(ids) == 1 {
		record(ids[0], "host:"+tok)
	}
	if ids := s.lxcToIDs[tok]; len(ids) == 1 {
		record(ids[0], "lxc:"+tok)
	}
}

func isIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '_'
}

// extractStandaloneTokens 提取前后均不紧邻标识符字符或内部点号的独立 token（句末句号允许，如 "updated gateway."）。
func extractStandaloneTokens(lower string) []string {
	var out []string
	n := len(lower)
	for i := 0; i < n; {
		if !isIdentByte(lower[i]) {
			i++
			continue
		}
		start := i
		for i < n && isIdentByte(lower[i]) {
			i++
		}
		// 若紧跟在点号后（如 foo.cache 或 api.gateway.io 的后段），交给 extractDotChains 处理，不当独立裸词。
		if start > 0 && lower[start-1] == '.' {
			continue
		}
		// 若后面是点号且点号后仍是标识符字符（如 api.gateway.io 的首段），同样交给 extractDotChains。
		if i < n && lower[i] == '.' && i+1 < n && isIdentByte(lower[i+1]) {
			continue
		}
		tok := strings.Trim(lower[start:i], "-_")
		if len(tok) >= 3 {
			out = append(out, tok)
		}
	}
	return out
}

// extractDotChains 提取形如 a.b 或 a.b.c 的连续点分标识符串。
func extractDotChains(lower string) []string {
	var out []string
	n := len(lower)
	for i := 0; i < n; {
		if !isIdentByte(lower[i]) {
			i++
			continue
		}
		start := i
		dots := 0
		for {
			for i < n && isIdentByte(lower[i]) {
				i++
			}
			if i < n && lower[i] == '.' && i+1 < n && isIdentByte(lower[i+1]) {
				dots++
				i++
				continue
			}
			break
		}
		if dots > 0 {
			out = append(out, lower[start:i])
		}
	}
	return out
}

type vmidRef struct {
	vmid string
	host string
}

func hasTokenBoundary(s string, start, end int) bool {
	if start > 0 && isIdentByte(lowerByte(s[start-1])) {
		return false
	}
	if end < len(s) && isIdentByte(lowerByte(s[end])) {
		return false
	}
	return true
}

func lowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func (s *Snapshot) extractVMIDRefs(text string) []vmidRef {
	var out []vmidRef
	qualified := map[string]bool{}
	add := func(vmid, host string) {
		vmid = strings.TrimLeft(vmid, "0")
		if vmid == "" {
			return
		}
		ref := vmidRef{vmid: vmid, host: host}
		if !slices.Contains(out, ref) {
			out = append(out, ref)
		}
	}
	for _, idx := range qualifiedVMIDRe.FindAllStringSubmatchIndex(text, -1) {
		if !hasTokenBoundary(text, idx[0], idx[1]) {
			continue
		}
		prefix := strings.ToLower(text[idx[2]:idx[3]])
		if len(s.hostToIDs[prefix]) == 1 {
			vmid := text[idx[4]:idx[5]]
			qualified[strings.TrimLeft(vmid, "0")] = true
			add(vmid, prefix)
		}
	}
	for _, idx := range nodePVEConfRe.FindAllStringSubmatchIndex(text, -1) {
		if idx[1] < len(text) && isIdentByte(lowerByte(text[idx[1]])) {
			continue
		}
		prefix := strings.ToLower(text[idx[2]:idx[3]])
		vmid := text[idx[4]:idx[5]]
		qualified[strings.TrimLeft(vmid, "0")] = true
		add(vmid, prefix)
	}
	for _, idx := range barePVEConfRe.FindAllStringSubmatchIndex(text, -1) {
		if idx[1] < len(text) && isIdentByte(lowerByte(text[idx[1]])) {
			continue
		}
		vmid := text[idx[2]:idx[3]]
		if !qualified[strings.TrimLeft(vmid, "0")] {
			add(vmid, "")
		}
	}
	for _, idx := range bareVMIDRe.FindAllStringSubmatchIndex(text, -1) {
		if !hasTokenBoundary(text, idx[0], idx[1]) {
			continue
		}
		vmid := text[idx[2]:idx[3]]
		if !qualified[strings.TrimLeft(vmid, "0")] {
			add(vmid, "")
		}
	}
	return out
}

func extractIPs(text string) []netip.Addr {
	var out []netip.Addr
	add := func(raw string) {
		if addr, ok := parseMatchableIP(raw); ok && !slices.Contains(out, addr) {
			out = append(out, addr)
		}
	}
	isIPv4Adj := func(b byte) bool {
		return (b >= '0' && b <= '9') || b == '.'
	}
	for _, idx := range ipv4TokenRe.FindAllStringIndex(text, -1) {
		if (idx[0] > 0 && isIPv4Adj(text[idx[0]-1])) || (idx[1] < len(text) && isIPv4Adj(text[idx[1]])) {
			continue
		}
		add(text[idx[0]:idx[1]])
	}
	isIPv6Adj := func(b byte) bool {
		b = lowerByte(b)
		return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || b == ':'
	}
	for _, idx := range ipv6TokenRe.FindAllStringIndex(text, -1) {
		if (idx[0] > 0 && isIPv6Adj(text[idx[0]-1])) || (idx[1] < len(text) && isIPv6Adj(text[idx[1]])) {
			continue
		}
		add(text[idx[0]:idx[1]])
	}
	return out
}

func parseMatchableIP(raw string) (netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	if host, _, ok := strings.Cut(raw, "/"); ok {
		raw = host
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return netip.Addr{}, false
	}
	if addr == netip.MustParseAddr("255.255.255.255") {
		return netip.Addr{}, false
	}
	return addr, true
}

func normalizeHostname(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func shortHostname(h string) string {
	h = normalizeHostname(h)
	short, _, _ := strings.Cut(h, ".")
	return short
}

func isCodePath(p string) bool {
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(p)))
	return codeExts[ext]
}

func isPureAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return len(s) > 0
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}
