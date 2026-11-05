package selfwatch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const maxEvidenceChanges = 16

// configEvidence 保存观察到的配置变化，不推断发起人或维护授权。任意配置原文不进入告警。
type configEvidence struct {
	Version      int            `json:"version"`
	Source       string         `json:"source"`
	ObservedAt   time.Time      `json:"observed_at"`
	Actor        string         `json:"actor"`
	Coverage     string         `json:"coverage"`
	BeforeSHA256 string         `json:"before_sha256"`
	AfterSHA256  string         `json:"after_sha256"`
	Changes      []configChange `json:"changes"`
	Dropped      int            `json:"dropped_changes,omitempty"`
}

type configChange struct {
	Path      string       `json:"path"`
	Dangerous bool         `json:"dangerous"`
	Before    valueSummary `json:"before"`
	After     valueSummary `json:"after"`
}

type valueSummary struct {
	Present       bool         `json:"present"`
	Kind          string       `json:"kind"`
	SHA256        string       `json:"sha256"`
	Value         any          `json:"value,omitempty"`
	HBA           []hbaSummary `json:"hba,omitempty"`
	Count         int          `json:"count,omitempty"`
	Redacted      bool         `json:"redacted"`
	TrustRules    int          `json:"trust_rules,omitempty"`
	WorldRules    int          `json:"world_rules,omitempty"`
	UnparsedRules int          `json:"unparsed_rules,omitempty"`
	OmittedHBA    int          `json:"omitted_hba,omitempty"`
}

type hbaSummary struct {
	Type    string `json:"type"`
	Address string `json:"address,omitempty"`
	Method  string `json:"method,omitempty"`
}

func fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func changeEvidence(before, after json.RawMessage, now time.Time) configEvidence {
	var a, b any
	_ = json.Unmarshal(before, &a)
	_ = json.Unmarshal(after, &b)
	e := configEvidence{
		Version: 1, Source: "platform_selfwatch", ObservedAt: now.UTC(), Actor: "unknown",
		Coverage:     "Patroni /config 两次轮询之间的配置差异；不代表精确修改时间、发起人或操作已获授权。字符串、命令、密码和未识别配置值均不保留原文。HBA 摘要省略数据库、用户与认证选项，不能替代完整规则审计。",
		BeforeSHA256: fingerprint(before), AfterSHA256: fingerprint(after),
	}
	collectChanges("", a, b, true, true, &e)
	return e
}

func collectChanges(path string, a, b any, hasA, hasB bool, e *configEvidence) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok || bok {
		keys := make(map[string]bool, len(am)+len(bm))
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			p := k
			if path != "" {
				p = path + "." + k
			}
			av, ap := am[k]
			bv, bp := bm[k]
			collectChanges(p, av, bv, ap, bp, e)
		}
		if len(names) > 0 {
			return
		}
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if hasA == hasB && string(ja) == string(jb) {
		return
	}
	if len(e.Changes) == maxEvidenceChanges {
		e.Dropped++
		if dangerous(path) {
			for i := len(e.Changes) - 1; i >= 0; i-- {
				if !e.Changes[i].Dangerous {
					e.Changes[i] = configChange{Path: safePath(path), Dangerous: true, Before: summarize(path, a, hasA), After: summarize(path, b, hasB)}
					break
				}
			}
		}
		return
	}
	e.Changes = append(e.Changes, configChange{Path: safePath(path), Dangerous: dangerous(path), Before: summarize(path, a, hasA), After: summarize(path, b, hasB)})
}

func safePath(path string) string {
	// 配置键也来自外部输入；只保留已知字段名，未知键不能借路径把秘密带进告警。
	switch path {
	case "ttl", "loop_wait", "retry_timeout", "maximum_lag_on_failover", "maximum_lag_on_syncnode", "pause", "synchronous_mode", "synchronous_mode_strict", "synchronous_node_count", "failsafe_mode", "postgresql", "postgresql.pg_hba", "postgresql.pg_ident", "postgresql.parameters", "postgresql.parameters.ssl", "postgresql.parameters.password_encryption", "postgresql.parameters.listen_addresses", "postgresql.parameters.shared_preload_libraries", "postgresql.parameters.local_preload_libraries", "postgresql.parameters.session_preload_libraries", "postgresql.parameters.archive_command", "postgresql.parameters.restore_command", "postgresql.parameters.archive_cleanup_command", "postgresql.parameters.recovery_end_command":
		return path
	default:
		return "redacted-path:" + fingerprint([]byte(path))
	}
}

func summarize(path string, v any, present bool) valueSummary {
	raw, _ := json.Marshal(v)
	s := valueSummary{Present: present, SHA256: fingerprint(raw), Redacted: true}
	switch x := v.(type) {
	case nil:
		s.Kind = "null"
	case bool:
		s.Kind = "boolean"
	case float64:
		s.Kind = "number"
	case string:
		s.Kind = "string"
	case map[string]any:
		s.Kind = "object"
		s.Count = len(x)
	case []any:
		s.Kind = "array"
		s.Count = len(x)
		if path == "postgresql.pg_hba" {
			for _, item := range x {
				h := hbaSummary{Type: "unparsed"}
				if line, ok := item.(string); ok {
					h = summarizeHBA(line)
				}
				if h.Method == "trust" {
					s.TrustRules++
				}
				if h.Address == "0.0.0.0/0" || h.Address == "::/0" || h.Address == "all" {
					s.WorldRules++
				}
				if h.Type == "unparsed" {
					s.UnparsedRules++
				}
				if len(s.HBA) < 8 {
					s.HBA = append(s.HBA, h)
				} else {
					s.OmittedHBA++
				}
			}
		}
	}
	// 只展示固定运维字段的数值或 ssl 的枚举，未知字段即使是数字也可能是凭据。
	if path == "ttl" || path == "loop_wait" || path == "retry_timeout" {
		if n, ok := v.(float64); ok && n >= 0 && n <= 86400 {
			s.Value = n
			s.Redacted = false
		}
	}
	if path == "postgresql.parameters.ssl" {
		switch x := v.(type) {
		case bool:
			s.Value = x
			s.Redacted = false
		case string:
			if x == "on" || x == "off" {
				s.Value = x
				s.Redacted = false
			}
		}
	}
	return s
}

func summarizeHBA(line string) hbaSummary {
	unknown := hbaSummary{Type: "unparsed"}
	if strings.ContainsAny(line, "\"'\\\n\r") {
		return unknown
	}
	fields := strings.Fields(line)
	if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
		return hbaSummary{Type: "comment_or_empty"}
	}
	method := 3
	s := hbaSummary{Type: fields[0]}
	switch s.Type {
	case "local":
	case "host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc":
		method = 4
		if len(fields) < 5 {
			return unknown
		}
		if _, err := netip.ParsePrefix(fields[3]); err == nil {
			s.Address = fields[3]
		}
		if ip, err := netip.ParseAddr(fields[3]); err == nil {
			s.Address = ip.String()
			if len(fields) > 5 {
				if _, err := netip.ParseAddr(fields[4]); err == nil {
					method = 5
				}
			}
		}
		if fields[3] == "all" || fields[3] == "samehost" || fields[3] == "samenet" {
			s.Address = fields[3]
		}
	default:
		return unknown
	}
	if len(fields) <= method {
		return unknown
	}
	switch fields[method] {
	case "trust", "reject", "md5", "scram-sha-256", "password", "peer", "ident", "cert", "ldap", "radius", "pam", "bsd", "gss", "sspi", "oauth":
		s.Method = fields[method]
	default:
		return unknown
	}
	return s
}
