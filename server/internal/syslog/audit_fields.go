package syslog

import (
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

var auditHeader = regexp.MustCompile(`^(?:node=\S+\s+)?type=(SYSCALL|CONFIG_CHANGE) msg=audit\(([0-9]+\.[0-9]+):([0-9]+)\):\s*(.*)$`)
var auditKV = regexp.MustCompile(`([A-Za-z_][A-Za-z_0-9]*)=("[^"\r\n]*"|'[^'\r\n]*'|[^\s"']+)`)

// withAuditFields 仅解析 auditd 的独立 SYSCALL/CONFIG_CHANGE 记录，不伪造多记录归因。
// 保留原 message；只有可信配置的 syslog 转发源才应送入此接口。
func withAuditFields(raw []byte, msg Message) []byte {
	if msg.AppName != "auditd" && msg.AppName != "audit" && msg.AppName != "audispd" && msg.AppName != "audisp-syslog" {
		return raw
	}
	if len(msg.Content) > 16384 {
		return raw
	}
	h := auditHeader.FindStringSubmatch(msg.Content)
	if h == nil {
		return raw
	}
	fields := map[string]any{"type": h[1], "timestamp": h[2], "serial": h[3], "record_scope": "single_record"}
	allowed := map[string]bool{}
	for _, key := range strings.Fields("arch syscall success pid ppid auid uid euid gid egid ses tty comm exe op key res") {
		allowed[key] = true
	}
	seen := map[string]bool{}
	end := 0
	for _, m := range auditKV.FindAllStringSubmatchIndex(h[4], -1) {
		if strings.TrimSpace(h[4][end:m[0]]) != "" {
			return raw
		}
		end = m[1]
		key := h[4][m[2]:m[3]]
		value := h[4][m[4]:m[5]]
		if seen[key] {
			return raw
		}
		seen[key] = true
		if !allowed[key] {
			continue
		}
		quoted := strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'")
		if quoted {
			value = value[1 : len(value)-1]
		}
		if !quoted && (key == "exe" || key == "comm") {
			if decoded, err := hex.DecodeString(value); err == nil && utf8.Valid(decoded) && len(decoded) > 0 {
				value = string(decoded)
			}
		}
		fields[key] = value
	}
	if strings.TrimSpace(h[4][end:]) != "" || len(seen) == 0 {
		return raw
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil || doc == nil {
		return raw
	}
	doc["audit"] = fields
	result, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return result
}
