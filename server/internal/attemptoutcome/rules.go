// Package attemptoutcome 对认证失败族事件执行「真实攻击、但未得手」的确定性核验、自动结案、新证据重开与入口加固建议归并。
//
// 安全边界：
//   - 仅覆盖认证失败族规则（Linux / Authentik 交互式登录失败、SSH 认证失败、Windows 登录失败及对应短时爆破计数规则）；
//     凭据窃取、清痕、削弱防御、破坏、持久化、情报命中、爆破得手、横向喷洒等一律不自动放行。
//   - 核验纯靠数据库确定性查询（不调模型），查询强制限定资产与时间范围走 events 分区裁剪与 (asset_id, ts) 索引，并设超时。
//   - 被挡住的外部攻击尝试按 closed 结案（resolution_source="attempt_verified"），绝不标 false_positive，防止喂给误报统计生成永久抑制。
//   - 拿不准（缺来源 IP、采集中断、分区已退役、查询超时、存在其他告警）一律不自动结案，保留给研判与人工复核。
package attemptoutcome

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"openxdr/server/ent"
	"openxdr/server/internal/authfields"
)

const (
	// ResolutionSource 未得手确定性核验自动结案的来源标记
	ResolutionSource = "attempt_verified"
	// Actor 审计日志与联动事件记录的系统身份
	Actor = "system:attempt-outcome"

	// DefaultQuietHours 默认静默观察窗口（小时）：末次失败后至少安静这么久才允许自动结案
	DefaultQuietHours = 6

	// 审计动作名
	AuditActionVerified = "incident_attempt_verified"
	AuditActionReopened = "incident_attempt_reopened"
)

// 认证失败族规则白名单（严禁放入提权、爆破成功、横向喷洒、数据库无成功对照规则或高危后渗透规则）。
const (
	RuleLinuxLoginFailure             = "9c4e6b2d-8f13-47a5-9e07-3d5a8c1f6b42" // Failed Interactive Login (Linux 3002 / Authentik 3002)
	RuleSSHAuthFailure                = "b1e7a4f0-2c93-4d58-9a16-5f0d3e8c7b24" // SSH Authentication Failure (syslog 100001 sshd)
	RuleWinLoginFailure               = "d2b870a5-1c34-4738-9f35-0b49bac2cb76" // Failed Windows Logon (Windows Security 4625)
	RuleTemporalLinuxAuthBurst        = "temporal:linux-auth-burst"            // 同主机短时登录失败集中出现
	RuleTemporalLinuxAccountAuthBurst = "temporal:linux-account-auth-burst"    // 同账号短时跨主机登录失败集中出现
	RuleTemporalSSHDFailBurst         = "temporal:wazuh-gap-sshd-fail-burst"   // SSH 同主机同源 IP 两分钟十次认证失败
	RuleTemporalWindowsFailBurst      = "temporal:wazuh-gap-windows-fail-burst"
)

var authFailureRuleSet = map[string]bool{
	RuleLinuxLoginFailure:             true,
	RuleSSHAuthFailure:                true,
	RuleWinLoginFailure:               true,
	RuleTemporalLinuxAuthBurst:        true,
	RuleTemporalLinuxAccountAuthBurst: true,
	RuleTemporalSSHDFailBurst:         true,
	RuleTemporalWindowsFailBurst:      true,
}

// IsAuthFailureRule 判断规则是否属于本机制覆盖的认证失败族。
func IsAuthFailureRule(ruleID string) bool {
	return authFailureRuleSet[ruleID]
}

// IncidentAllAuthFailures 事件非空且全部告警均属于认证失败族时才返回 true。
func IncidentAllAuthFailures(alerts []*ent.Alert) bool {
	if len(alerts) == 0 {
		return false
	}
	for _, a := range alerts {
		if a == nil || !IsAuthFailureRule(a.RuleID) {
			return false
		}
	}
	return true
}

// IncidentHasAuthFailures 事件至少包含一条认证失败族告警时返回 true（供研判上下文补充核验结果）。
func IncidentHasAuthFailures(alerts []*ent.Alert) bool {
	for _, a := range alerts {
		if a != nil && IsAuthFailureRule(a.RuleID) {
			return true
		}
	}
	return false
}

// ManuallyHeld 与 closurereview 保持同一人工接管/锁定口径：人工明确接管或锁定的事件绝不自动结案。
// 系统自动升级（Owner="human" 且 Stage="escalated"、无 ManualLock/ManualOwner）不视为人工锁定。
func ManuallyHeld(inc *ent.Incident) bool {
	if inc == nil || inc.Work == nil {
		return false
	}
	return inc.Work.ManualLock || inc.Work.ManualOwner != "" || (inc.Work.Owner == "human" && inc.Work.Stage != "escalated")
}

// AuthEvent 归一化提取后的单条认证事件（成功或失败）。
type AuthEvent struct {
	Success      bool
	Failure      bool
	SrcIP        string
	Account      string
	ServiceSlug  string
	ServiceLabel string
	SourceKind   string // agent / authentik / syslog
}

// ParseAuthEvent 从 events 行（3002 或 100001）提取认证结果、来源 IP、账号与目标服务。
// 非认证登录事件（如 Windows 账户管理 4720、审计日志清空 1102、普通 syslog）返回 ok=false。
func ParseAuthEvent(classUID int, source, assetOS, colUser string, raw []byte) (AuthEvent, bool) {
	switch classUID {
	case 3002:
		return parse3002(source, assetOS, colUser, raw)
	case 100001:
		return parseSyslogSSHD(colUser, raw)
	default:
		return AuthEvent{}, false
	}
}

func parse3002(source, assetOS, colUser string, raw []byte) (AuthEvent, bool) {
	var doc struct {
		ActivityID int    `json:"activity_id"`
		EventID    int    `json:"event_id"`
		StatusID   int    `json:"status_id"`
		Status     string `json:"status"`
		LogName    string `json:"log_name"`
		User       struct {
			Name string `json:"name"`
		} `json:"user"`
		Service struct {
			Name string `json:"name"`
		} `json:"service"`
		LoginSession struct {
			SrcIP string `json:"src_ip"`
		} `json:"login_session"`
		Metadata struct {
			Product struct {
				Name string `json:"name"`
			} `json:"product"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return AuthEvent{}, false
	}
	// 仅认登录认证（activity_id=1 或缺省 0）及 Windows 显式凭据登录（4648），排除账户增删/清日志等管理事件
	if doc.ActivityID != 0 && doc.ActivityID != 1 && doc.EventID != 4648 {
		return AuthEvent{}, false
	}
	succ := doc.StatusID == 1 || strings.EqualFold(strings.TrimSpace(doc.Status), "Success")
	fail := doc.StatusID == 2 || strings.EqualFold(strings.TrimSpace(doc.Status), "Failure")
	if !succ && !fail {
		return AuthEvent{}, false
	}

	ip := authfields.SourceIP(raw)
	if ip == "" && doc.LoginSession.SrcIP != "" {
		ip = authfields.CanonicalIP(doc.LoginSession.SrcIP)
	}
	acct := cleanLabel(doc.User.Name, 128)
	if acct == "" {
		acct = cleanLabel(colUser, 128)
	}
	slug, label := classify3002Service(source, assetOS, doc.LogName, doc.Service.Name, doc.Metadata.Product.Name)
	kind := "agent"
	if strings.EqualFold(source, "authentik") || slug == "authentik" {
		kind = "authentik"
	} else if strings.EqualFold(source, "syslog") {
		kind = "syslog"
	}
	return AuthEvent{
		Success:      succ,
		Failure:      fail,
		SrcIP:        ip,
		Account:      acct,
		ServiceSlug:  slug,
		ServiceLabel: label,
		SourceKind:   kind,
	}, true
}

func classify3002Service(source, assetOS, logName, svcName, productName string) (string, string) {
	svcLower := strings.ToLower(strings.TrimSpace(svcName))
	prodLower := strings.ToLower(strings.TrimSpace(productName))
	if strings.EqualFold(source, "authentik") || svcLower == "authentik" || prodLower == "authentik" {
		return "authentik", "Authentik"
	}
	if strings.EqualFold(logName, "Security") || strings.EqualFold(assetOS, "windows") {
		if svcLower == "logon-type-10" || strings.Contains(svcLower, "rdp") {
			return "windows-rdp", "Windows RDP"
		}
		return "windows-logon", "Windows 登录"
	}
	if strings.Contains(svcLower, "ssh") {
		return "ssh", "SSH"
	}
	if slug := sanitizeSlug(svcLower); slug != "" {
		return slug, cleanLabel(svcName, 48)
	}
	return "linux-login", "Linux 登录"
}

var pamRhostRe = regexp.MustCompile(`(?:^|\s)rhost=([^\s;]+)`)
var pamUserRe = regexp.MustCompile(`(?:^|\s)user=([^\s;]+)`)

func parseSyslogSSHD(colUser string, raw []byte) (AuthEvent, bool) {
	var doc struct {
		Message  string `json:"message"`
		Metadata struct {
			Product struct {
				Name string `json:"name"`
			} `json:"product"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return AuthEvent{}, false
	}
	if !strings.EqualFold(strings.TrimSpace(doc.Metadata.Product.Name), "sshd") {
		return AuthEvent{}, false
	}
	msg := strings.TrimSpace(doc.Message)
	if msg == "" {
		return AuthEvent{}, false
	}

	// 1. Accepted <method> for <user> from <ip> port <port>...（从右向左切 " from " 防止伪造用户名污染来源 IP）
	if strings.HasPrefix(msg, "Accepted ") {
		ip, acct, ok := parseSSHDFromPort(msg, "Accepted ")
		if !ok {
			return AuthEvent{}, false
		}
		if acct == "" {
			acct = cleanLabel(colUser, 128)
		}
		return AuthEvent{
			Success:      true,
			SrcIP:        ip,
			Account:      acct,
			ServiceSlug:  "ssh",
			ServiceLabel: "SSH",
			SourceKind:   "syslog",
		}, true
	}

	// 2. Failed <method> for [invalid user ]<user> from <ip> port <port> / Invalid user <user> from <ip> port <port>
	if strings.HasPrefix(msg, "Failed ") || strings.HasPrefix(msg, "Invalid user ") {
		ip := authfields.SourceIP(raw)
		_, acct, _ := parseSSHDFromPort(msg, "")
		if acct == "" {
			acct = cleanLabel(colUser, 128)
		}
		return AuthEvent{
			Failure:      true,
			SrcIP:        ip,
			Account:      acct,
			ServiceSlug:  "ssh",
			ServiceLabel: "SSH",
			SourceKind:   "syslog",
		}, true
	}

	// 3. PAM authentication failure（rules/lnx_ssh_auth_failure.yml 第三分支）
	if strings.Contains(msg, "authentication failure") {
		ip := authfields.SourceIP(raw)
		if ip == "" {
			if m := pamRhostRe.FindStringSubmatch(msg); len(m) == 2 {
				ip = authfields.CanonicalIP(m[1])
			}
		}
		acct := ""
		if m := pamUserRe.FindStringSubmatch(msg); len(m) == 2 {
			acct = cleanLabel(m[1], 128)
		}
		if acct == "" {
			acct = cleanLabel(colUser, 128)
		}
		return AuthEvent{
			Failure:      true,
			SrcIP:        ip,
			Account:      acct,
			ServiceSlug:  "ssh",
			ServiceLabel: "SSH",
			SourceKind:   "syslog",
		}, true
	}

	return AuthEvent{}, false
}

// parseSSHDFromPort 从右向左按 " from <ip> port <port>" 切分 OpenSSH 认证日志，防止攻击者在用户名里塞入伪造的 "from 1.2.3.4"。
func parseSSHDFromPort(msg, prefix string) (ip, user string, ok bool) {
	idx := strings.LastIndex(msg, " from ")
	if idx <= 0 {
		return "", "", false
	}
	head := strings.TrimSpace(msg[:idx])
	tail := strings.Fields(msg[idx+len(" from "):])
	if len(tail) < 3 || tail[1] != "port" {
		return "", "", false
	}
	port, err := strconv.Atoi(tail[2])
	if err != nil || port < 1 || port > 65535 {
		return "", "", false
	}
	canon := authfields.CanonicalIP(tail[0])
	if canon == "" {
		return "", "", false
	}
	if prefix != "" {
		rest := strings.TrimPrefix(head, prefix)
		if _, afterFor, found := strings.Cut(rest, " for "); found {
			afterFor = strings.TrimPrefix(afterFor, "invalid user ")
			user = cleanLabel(afterFor, 128)
		}
	} else if strings.HasPrefix(head, "Invalid user ") {
		user = cleanLabel(strings.TrimPrefix(head, "Invalid user "), 128)
	} else if _, afterFor, found := strings.Cut(head, " for "); found {
		afterFor = strings.TrimPrefix(afterFor, "invalid user ")
		user = cleanLabel(afterFor, 128)
	}
	return canon, user, true
}

// ExtractEventIPs 提取任意告警原始事件中涉及的规范化 IP（用于核对同一攻击源是否触发了其他规则命中）。
func ExtractEventIPs(classUID int, raw []byte) []string {
	var out []string
	add := func(s string) {
		if ip := authfields.CanonicalIP(s); ip != "" && !slices.Contains(out, ip) {
			out = append(out, ip)
		}
	}
	if p := authfields.PeerIP(classUID, raw); p != "" {
		add(p)
	}
	if ev, ok := ParseAuthEvent(classUID, "", "", "", raw); ok && ev.SrcIP != "" {
		add(ev.SrcIP)
	}
	var doc struct {
		Src struct {
			IP string `json:"ip"`
		} `json:"src_endpoint"`
		Dst struct {
			IP string `json:"ip"`
		} `json:"dst_endpoint"`
		LoginSession struct {
			SrcIP string `json:"src_ip"`
		} `json:"login_session"`
	}
	if len(raw) > 0 && json.Unmarshal(raw, &doc) == nil {
		add(doc.Src.IP)
		add(doc.Dst.IP)
		add(doc.LoginSession.SrcIP)
	}
	return out
}

// ExtractAlertIPs 提取告警自身（含 intel:ip:<ip>、时序告警 detail 及关联事件）涉及的 IP。
func ExtractAlertIPs(ruleID string, detail *string, classUID int, raw []byte) []string {
	ips := ExtractEventIPs(classUID, raw)
	add := func(s string) {
		if ip := authfields.CanonicalIP(s); ip != "" && !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	if after, ok := strings.CutPrefix(ruleID, "intel:ip:"); ok {
		add(after)
	}
	if detail != nil {
		if after, ok := strings.CutPrefix(strings.TrimSpace(*detail), "首个来源 IP "); ok {
			add(after)
		} else {
			for _, tok := range strings.Fields(*detail) {
				tok = strings.Trim(tok, ",;()[]\"'")
				if addr, err := netip.ParseAddr(tok); err == nil {
					add(addr.Unmap().String())
				}
			}
		}
	}
	return ips
}

func sanitizeSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		case r == ' ' || r == '/' || r == ':':
			b.WriteByte('-')
		}
		if b.Len() >= 40 {
			break
		}
	}
	res := strings.Trim(b.String(), "._-")
	if res == "" || (res[0] < 'a' || res[0] > 'z') && (res[0] < '0' || res[0] > '9') {
		return ""
	}
	return res
}

func cleanLabel(s string, maxRunes int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxRunes {
			break
		}
		if unicode.IsControl(r) {
			b.WriteByte(' ')
		} else {
			b.WriteRune(r)
		}
		n++
	}
	return strings.TrimSpace(b.String())
}
