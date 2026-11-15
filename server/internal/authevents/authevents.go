// Package authevents 将认证失败族涉及的登录认证事件（OCSF 3002 与 syslog 100001 sshd）在接入事务内实时物化为精简行，
// 供「真实攻击、但未得手」确定性核验、静默成功登录批量重开巡检与入口加固统计按索引点查，避免扫描海量原始 events 分区表。
package authevents

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"openxdr/server/internal/authfields"
)

const (
	// RecordedSinceKey settings 表中记录 auth_events 开始物化的时间；早于或等于该时刻的存量事件不自动结案。
	RecordedSinceKey = "auth_events.recorded_since"

	pruneBatchSize     = 10000
	closureRetainFloor = 8 * 24 * time.Hour
)

// Execer 兼容 *sql.DB 与 *sql.Tx，用于在 ingest 现有事务内执行单次 INSERT。
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Parsed 归一化提取后的单条登录认证事件。
type Parsed struct {
	Success      bool
	Failure      bool
	SrcIP        string
	Account      string
	ServiceSlug  string
	ServiceLabel string
	SourceKind   string // agent / authentik / syslog
}

// EnsureSchema 创建认证事件物化表、已结案来源索引表及其索引。
// 指向事件的 event_id 不建外键（分区表主键含 ts），保留期由 janitor 按 ts 统一清理。
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS auth_events (
  event_id    uuid PRIMARY KEY,
  asset_id    uuid NOT NULL,
  ts          timestamptz NOT NULL,
  src_ip      text NOT NULL,
  service     text NOT NULL,
  source_kind text NOT NULL,
  account     text NOT NULL,
  success     boolean NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_events_src_ip_ts ON auth_events (src_ip, ts);
CREATE INDEX IF NOT EXISTS auth_events_asset_id_ts ON auth_events (asset_id, ts);
CREATE INDEX IF NOT EXISTS auth_events_ts ON auth_events (ts);

CREATE TABLE IF NOT EXISTS auth_attempt_closures (
  incident_id   uuid NOT NULL,
  src_ip        text NOT NULL,
  asset_id      uuid NOT NULL,
  group_id      uuid,
  first_failure timestamptz NOT NULL,
  resolved_at   timestamptz NOT NULL,
  PRIMARY KEY (incident_id, src_ip, asset_id)
);
CREATE INDEX IF NOT EXISTS auth_attempt_closures_src_ip_resolved ON auth_attempt_closures (src_ip, resolved_at);
CREATE INDEX IF NOT EXISTS auth_attempt_closures_resolved_at ON auth_attempt_closures (resolved_at);`)
	return err
}

// EnsureRecordedSince 在 settings 表记录 auth_events 首次启用的时间（已存在则保持原值不变）。
func EnsureRecordedSince(ctx context.Context, q Execer, at time.Time) error {
	if q == nil {
		return nil
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	b, err := json.Marshal(at.UTC())
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `
INSERT INTO settings (id, value, updated_at)
VALUES ($1, $2::jsonb, now())
ON CONFLICT (id) DO NOTHING`, RecordedSinceKey, string(b))
	return err
}

// Record 在 ingest 现有事务内把属于认证族的 3002 / 100001 sshd 事件物化进 auth_events。
// 非认证事件（如 Windows 账户管理 4720、审计清日志 1102、非 sshd 的 syslog）在内存过滤后直接返回，零额外查询、单次 INSERT。
func Record(
	ctx context.Context,
	q Execer,
	eventID, assetID uuid.UUID,
	ts time.Time,
	classUID int,
	source, assetOS, colUser string,
	raw []byte,
) error {
	if q == nil || eventID == uuid.Nil || assetID == uuid.Nil {
		return nil
	}
	parsed, ok := Parse(classUID, source, assetOS, colUser, raw)
	if !ok {
		return nil
	}
	_, err := q.ExecContext(ctx, `
INSERT INTO auth_events (event_id, asset_id, ts, src_ip, service, source_kind, account, success)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (event_id) DO NOTHING`,
		eventID,
		assetID,
		ts,
		parsed.SrcIP,
		parsed.ServiceSlug,
		parsed.SourceKind,
		parsed.Account,
		parsed.Success,
	)
	return err
}

// Prune 按与 events 一致的保留期分批清理过期的 auth_events 与过期结案索引。
func Prune(ctx context.Context, db *sql.DB, cutoff time.Time) (int64, error) {
	if db == nil {
		return 0, nil
	}
	var total int64
	for {
		res, err := db.ExecContext(ctx, `
DELETE FROM auth_events
WHERE event_id IN (
  SELECT event_id FROM auth_events WHERE ts < $1 ORDER BY ts ASC LIMIT $2
)`, cutoff, pruneBatchSize)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n < pruneBatchSize {
			break
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}

	closureCutoff := cutoff
	if eightDaysAgo := time.Now().Add(-closureRetainFloor); eightDaysAgo.Before(closureCutoff) {
		closureCutoff = eightDaysAgo
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM auth_attempt_closures WHERE resolved_at < $1`, closureCutoff)
	return total, nil
}

// ServiceLabel 将持久化的目标服务标识还原为展示名称。
func ServiceLabel(slug string) string {
	switch slug {
	case "authentik":
		return "Authentik"
	case "ssh":
		return "SSH"
	case "windows-rdp":
		return "Windows RDP"
	case "windows-logon":
		return "Windows 登录"
	case "linux-login":
		return "Linux 登录"
	case "":
		return "认证服务"
	default:
		return slug
	}
}

// Parse 从 3002 或 100001 事件提取认证结果、来源 IP、账号与目标服务。
// 非登录认证事件返回 ok=false。
func Parse(classUID int, source, assetOS, colUser string, raw []byte) (Parsed, bool) {
	switch classUID {
	case 3002:
		return parse3002(source, assetOS, colUser, raw)
	case 100001:
		return parseSyslogSSHD(colUser, raw)
	default:
		return Parsed{}, false
	}
}

func parse3002(source, assetOS, colUser string, raw []byte) (Parsed, bool) {
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
		return Parsed{}, false
	}
	// 仅认登录认证（activity_id=1 或缺省 0）及 Windows 显式凭据登录（4648），排除账户增删/清日志等管理事件
	if doc.ActivityID != 0 && doc.ActivityID != 1 && doc.EventID != 4648 {
		return Parsed{}, false
	}
	succ := doc.StatusID == 1 || strings.EqualFold(strings.TrimSpace(doc.Status), "Success")
	fail := doc.StatusID == 2 || strings.EqualFold(strings.TrimSpace(doc.Status), "Failure")
	if !succ && !fail {
		return Parsed{}, false
	}

	ip := authfields.SourceIP(raw)
	if ip == "" && doc.LoginSession.SrcIP != "" {
		ip = authfields.CanonicalIP(doc.LoginSession.SrcIP)
	}
	acct := CleanLabel(doc.User.Name, 128)
	if acct == "" {
		acct = CleanLabel(colUser, 128)
	}
	slug, label := classify3002Service(source, assetOS, doc.LogName, doc.Service.Name, doc.Metadata.Product.Name)
	kind := "agent"
	if strings.EqualFold(source, "authentik") || slug == "authentik" {
		kind = "authentik"
	} else if strings.EqualFold(source, "syslog") {
		kind = "syslog"
	}
	return Parsed{
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
	if slug := SanitizeSlug(svcLower); slug != "" {
		return slug, CleanLabel(svcName, 48)
	}
	return "linux-login", "Linux 登录"
}

var pamRhostRe = regexp.MustCompile(`(?:^|\s)rhost=([^\s;]+)`)
var pamUserRe = regexp.MustCompile(`(?:^|\s)user=([^\s;]+)`)

func parseSyslogSSHD(colUser string, raw []byte) (Parsed, bool) {
	var doc struct {
		Message  string `json:"message"`
		Metadata struct {
			Product struct {
				Name string `json:"name"`
			} `json:"product"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return Parsed{}, false
	}
	if !strings.EqualFold(strings.TrimSpace(doc.Metadata.Product.Name), "sshd") {
		return Parsed{}, false
	}
	msg := strings.TrimSpace(doc.Message)
	if msg == "" {
		return Parsed{}, false
	}

	// 1. Accepted <method> for <user> from <ip> port <port>...（从右向左切 " from " 防止伪造用户名污染来源 IP）
	if strings.HasPrefix(msg, "Accepted ") {
		ip, acct, ok := parseSSHDFromPort(msg, "Accepted ")
		if !ok {
			return Parsed{}, false
		}
		if acct == "" {
			acct = CleanLabel(colUser, 128)
		}
		return Parsed{
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
			acct = CleanLabel(colUser, 128)
		}
		return Parsed{
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
			acct = CleanLabel(m[1], 128)
		}
		if acct == "" {
			acct = CleanLabel(colUser, 128)
		}
		return Parsed{
			Failure:      true,
			SrcIP:        ip,
			Account:      acct,
			ServiceSlug:  "ssh",
			ServiceLabel: "SSH",
			SourceKind:   "syslog",
		}, true
	}

	return Parsed{}, false
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
	ip = authfields.CanonicalIP(tail[0])
	if ip == "" {
		return "", "", false
	}

	if prefix != "" {
		head = strings.TrimPrefix(head, prefix)
	}
	switch {
	case strings.HasPrefix(msg, "Invalid user "):
		user = strings.TrimSpace(strings.TrimPrefix(head, "Invalid user "))
	default:
		if forIdx := strings.Index(head, " for "); forIdx >= 0 {
			rest := strings.TrimSpace(head[forIdx+len(" for "):])
			if strings.HasPrefix(rest, "invalid user ") {
				rest = strings.TrimSpace(strings.TrimPrefix(rest, "invalid user "))
			}
			user = rest
		}
	}
	return ip, CleanLabel(user, 128), true
}

// SanitizeSlug 归一化目标服务标识符。
func SanitizeSlug(s string) string {
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

// CleanLabel 清理单行标签字符串，剔除控制字符并限制字符数。
func CleanLabel(s string, maxRunes int) string {
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
