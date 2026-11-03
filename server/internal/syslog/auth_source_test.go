package syslog

import (
	"openxdr/server/internal/authfields"
	"testing"
	"time"
)

func TestSSHLogSourceNormalization(t *testing.T) {
	msg := Parse(`<34>Oct 11 22:14:15 host sshd[7]: Failed password for root from 192.0.2.8 port 2345 ssh2`, time.Now())
	raw := withAuthSource([]byte(`{"device":{"hostname":"host"}}`), msg)
	if authfields.SourceIP(raw) != "192.0.2.8" {
		t.Fatalf("未保留日志来源: %s", raw)
	}
	msg.AppName = "nginx"
	if string(withAuthSource([]byte(`{}`), msg)) != "{}" {
		t.Fatal("非 SSH 日志不应解析认证来源")
	}
}
