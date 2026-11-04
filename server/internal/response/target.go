package response

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strings"
)

// 网段下限与 agent 一致：比这更宽的封锁更像误操作
const (
	minPrefixV4 = 16
	minPrefixV6 = 48
)

var (
	hostLabel   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	accountName = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$`)
	// docker 系容器 ID（agent 上报前 12 位，也接受完整的 64 位）或 LXC / QEMU 的 VMID
	containerID = regexp.MustCompile(`^([0-9a-f]{12,64}|[0-9]{1,9})$`)
	builtin     = map[string]bool{"root": true, "administrator": true, "system": true, "localsystem": true, "defaultaccount": true}
)

// TargetKinds 需要目标的动作
var TargetKinds = map[string]bool{
	"block_network": true, "unblock_network": true,
	"quarantine_file": true, "restore_file": true,
	"disable_account": true, "enable_account": true,
	"isolate_container": true, "unisolate_container": true,
}

// NormalizeTarget 校验并规范化动作目标。protected 是 server 自己的地址：封锁不能覆盖它们，
// 否则 agent 再也收不到解除指令。agent 侧还会再查一遍，两边任何一边放过都不会出事
func NormalizeTarget(kind, target string, protected []netip.Addr) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", errors.New("未指定目标")
	}
	switch kind {
	case "block_network", "unblock_network":
		target = strings.ToLower(strings.TrimSuffix(target, "."))
		prefix, err := network(target)
		if err != nil {
			return "", err
		}
		if kind == "unblock_network" || !prefix.IsValid() {
			return target, nil // 域名在 agent 上解析，解析出的地址由 agent 自保检查
		}
		if min := map[bool]int{true: minPrefixV4, false: minPrefixV6}[prefix.Addr().Is4()]; prefix.Bits() < min {
			return "", fmt.Errorf("%s 范围过宽（IPv4 至少 /%d、IPv6 至少 /%d）", target, minPrefixV4, minPrefixV6)
		}
		if a := prefix.Addr(); a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
			return "", fmt.Errorf("%s 不能封锁", target)
		}
		for _, p := range protected {
			if prefix.Contains(p) {
				return "", fmt.Errorf("%s 包含 server 地址 %s，封锁后将收不到解除指令", target, p)
			}
		}
		return target, nil
	case "quarantine_file", "restore_file":
		windows := len(target) > 2 && target[1] == ':' && (target[2] == '\\' || target[2] == '/')
		if !windows && (!strings.HasPrefix(target, "/") || path.Clean(target) != target) {
			return "", errors.New("文件路径必须是规范的绝对路径")
		}
		if len(target) > 4096 || strings.ContainsAny(target, "\x00\n\r") {
			return "", errors.New("文件路径无效")
		}
		return target, nil
	case "disable_account", "enable_account":
		if !accountName.MatchString(target) {
			return "", errors.New("账号名只能包含字母、数字与 . _ -，最长 32 个字符")
		}
		if builtin[strings.ToLower(target)] {
			return "", fmt.Errorf("%s 是系统内置账号，锁定会让主机无法管理", target)
		}
		return target, nil
	case "isolate_container", "unisolate_container":
		if !containerID.MatchString(strings.ToLower(target)) {
			return "", errors.New("容器 ID 必须是 12–64 位十六进制或数字 VMID")
		}
		return strings.ToLower(target), nil
	}
	return "", fmt.Errorf("%s 不需要目标", kind)
}

// network 解析封锁目标：IP、网段返回对应网段；域名返回零值网段
func network(target string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(target); err == nil {
		return p.Masked(), nil
	}
	if a, err := netip.ParseAddr(target); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	labels := strings.Split(target, ".")
	if len(target) > 253 || len(labels) < 2 {
		return netip.Prefix{}, errors.New("目标必须是 IP、网段或域名")
	}
	for _, l := range labels {
		if !hostLabel.MatchString(l) {
			return netip.Prefix{}, errors.New("目标必须是 IP、网段或域名")
		}
	}
	return netip.Prefix{}, nil
}

// ProtectedAddrs 从隔离放行地址（host:port）里取出 server 自己的地址
func ProtectedAddrs(endpoints []string) []netip.Addr {
	var out []netip.Addr
	for _, ep := range endpoints {
		if ap, err := netip.ParseAddrPort(ep); err == nil {
			out = append(out, ap.Addr())
		} else if a, err := netip.ParseAddr(ep); err == nil {
			out = append(out, a)
		}
	}
	return out
}
