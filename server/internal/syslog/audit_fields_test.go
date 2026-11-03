package syslog

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAuditNormalization(t *testing.T) {
	input := `<86>1 2026-11-02T00:00:00Z host auditd - - - type=CONFIG_CHANGE msg=audit(1793577600.123:42): auid=1000 ses=2 op=remove_rule key="auth" list=4 res=1`
	m := Parse(input, time.Now())
	raw := withAuditFields([]byte(`{"message":"preserved"}`), m)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	a := doc["audit"].(map[string]any)
	if a["auid"] != "1000" || a["serial"] != "42" || doc["message"] != "preserved" {
		t.Fatalf("归因错误: %s", raw)
	}
	for _, line := range []string{
		`type=CONFIG_CHANGE msg=audit(1.1:2): op=remove_rule op=add_rule res=1`,
		`type=CONFIG_CHANGE msg=audit(1.1:2): op="unterminated res=1`,
		`type=CONFIG_CHANGE msg=audit(1.1:2): op=remove_rule garbage res=1`,
		`type=CONFIG_CHANGE msg=audit(1.1:2): op=remove_rule res=1` + strings.Repeat("x", 16384),
	} {
		if got := string(withAuditFields([]byte(`{}`), Message{AppName: "auditd", Content: line})); got != "{}" {
			t.Fatalf("不应接受歧义/截断: %s", got)
		}
	}
	m.AppName = "nginx"
	if string(withAuditFields([]byte(`{}`), m)) != "{}" {
		t.Fatal("其他应用冒充 audit")
	}
	syscall := Message{AppName: "auditd", Content: `type=SYSCALL msg=audit(1.2:3): arch=c000003e syscall=59 success=yes auid=1000 uid=0 euid=0 exe=2F7573722F62696E2F6964`}
	if got := string(withAuditFields([]byte(`{}`), syscall)); !strings.Contains(got, `"exe":"/usr/bin/id"`) {
		t.Fatal(got)
	}
}
