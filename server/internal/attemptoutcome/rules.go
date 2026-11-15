// Package attemptoutcome 对认证失败族事件执行「真实攻击、但未得手」的确定性核验、自动结案、新证据重开与入口加固建议归并。
//
// 安全边界：
//   - 仅覆盖认证失败族规则（Linux / Authentik 交互式登录失败、SSH 认证失败、Windows 登录失败及对应短时爆破计数规则）；
//     凭据窃取、清痕、削弱防御、破坏、持久化、情报命中、爆破得手、横向喷洒等一律不自动放行。
//   - 核验纯靠数据库确定性查询（不调模型），认证事件统一查询 ingest 物化小表 auth_events（带 (src_ip, ts) 与 (asset_id, ts) 索引），
//     events 分区表只允许按主键 (id, ts) 取锚点事件正文，并强制设 statement_timeout。
//   - 被挡住的外部攻击尝试按 closed 结案（resolution_source="attempt_verified"），绝不标 false_positive，防止喂给误报统计生成永久抑制。
//   - 拿不准（上线前存量事件、缺来源 IP、采集中断、分区已退役、查询超时、存在其他告警）一律不自动结案，保留给研判与人工复核。
package attemptoutcome

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"

	"openxdr/server/ent"
	"openxdr/server/internal/authevents"
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
type AuthEvent = authevents.Parsed

// ParseAuthEvent 从 events 行（3002 或 100001）提取认证结果、来源 IP、账号与目标服务。
func ParseAuthEvent(classUID int, source, assetOS, colUser string, raw []byte) (AuthEvent, bool) {
	return authevents.Parse(classUID, source, assetOS, colUser, raw)
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
	return authevents.SanitizeSlug(s)
}
