package syslog

import (
	"encoding/json"
	"openxdr/server/internal/authfields"
)

// 接收报文的来源可能是日志中转服务器，不可用它代替 SSH 攻击源。
func withAuthSource(raw []byte, msg Message) []byte {
	if msg.AppName != "sshd" {
		return raw
	}
	ip := authfields.SSHSourceIP(msg.Content)
	if ip == "" {
		return raw
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return raw
	}
	doc["src_endpoint"] = map[string]any{"ip": ip}
	normalized, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return normalized
}
