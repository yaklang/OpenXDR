// Package authfields 只从已知认证字段或严格 SSH 日志格式提取来源，不使用传输对端冒充攻击源。
package authfields

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// CanonicalIP 统一 IPv4 映射地址；拒绝主机名、带端口、作用域和不可作为来源的地址。
func CanonicalIP(value string) string {
	ip, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || ip.Zone() != "" {
		return ""
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip.String() == "255.255.255.255" {
		return ""
	}
	return ip.String()
}

var sshFailure = regexp.MustCompile(`^(?:Failed (?:password|publickey|keyboard-interactive(?:/pam)?) for (?:invalid user )?\S+|Invalid user \S+) from (\S+) port ([0-9]+)(?: ssh2)?(?: \[preauth\])?$`)

// SSHSourceIP 不接受任意包含 from 的文本，避免把用户名里的伪造地址当成来源。
func SSHSourceIP(message string) string {
	parts := sshFailure.FindStringSubmatch(message)
	if len(parts) != 3 {
		return ""
	}
	port, err := strconv.Atoi(parts[2])
	if err != nil || port < 1 || port > 65535 {
		return ""
	}
	return CanonicalIP(parts[1])
}

// SourceIP 优先采用归一化字段。旧 SSH 原文只在明确缺少该字段时回退解析。
// 无法解析时返回空串，由关联层记录 no_source_ip，绝不归并到“未知来源”。
func SourceIP(raw []byte) string {
	var doc struct {
		Source   json.RawMessage `json:"src_endpoint"`
		Message  string          `json:"message"`
		Metadata struct {
			Product struct {
				Name string `json:"name"`
			} `json:"product"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	if doc.Source != nil {
		var source struct {
			IP string `json:"ip"`
		}
		if json.Unmarshal(doc.Source, &source) != nil {
			return ""
		}
		return CanonicalIP(source.IP)
	}
	if doc.Metadata.Product.Name == "sshd" {
		return SSHSourceIP(doc.Message)
	}
	return ""
}

// PeerIP 受害方视角的对端地址：登录事件（3002）与 sshd 日志（100001）的来源、agent 入站连接（4001 inbound）的对端。
// 出站连接与探针会话的 src 是本机自己，不算；取不到返回空串
func PeerIP(classUID int, raw []byte) string {
	switch classUID {
	case 3002, 100001:
		return SourceIP(raw)
	case 4001:
		var doc struct {
			Conn struct {
				Direction string `json:"direction"`
			} `json:"connection_info"`
			Src struct {
				IP string `json:"ip"`
			} `json:"src_endpoint"`
		}
		if json.Unmarshal(raw, &doc) != nil || doc.Conn.Direction != "inbound" {
			return ""
		}
		return CanonicalIP(doc.Src.IP)
	}
	return ""
}
