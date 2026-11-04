package correlate

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/sigma"
)

func recurAlert(rule string, class int, raw string) *ent.Alert {
	return &ent.Alert{RuleID: rule, Edges: ent.AlertEdges{Event: &ent.Event{ClassUID: class, Raw: json.RawMessage(raw)}}}
}

func recurKey(al *ent.Alert) string {
	k, _ := recurKeys(al)
	return k
}

func coarseOf(al *ent.Alert) string {
	_, c := recurKeys(al)
	return c
}

func procAlert(rule, user, image, parent, cmd string) *ent.Alert {
	raw := `{"process":{"cmd_line":"` + cmd + `","file":{"path":"` + image + `"},"parent_process":{"file":{"path":"` + parent + `"}}}}`
	al := recurAlert(rule, 1007, raw)
	al.Edges.Event.Username = &user
	return al
}

// 实体键：同一件事键相同，不同实体、不同容器键不同，取不到实体为空（不参与复发归并）。
func TestRecurKey(t *testing.T) {
	inbound := `{"connection_info":{"direction":"inbound"},"src_endpoint":{"ip":"1.2.3.4"},"dst_endpoint":{"ip":"10.0.0.1"}}`
	outbound := `{"connection_info":{"direction":"outbound"},"src_endpoint":{"ip":"10.0.0.1"},"dst_endpoint":{"ip":"1.2.3.4"}}`
	same := [][2]*ent.Alert{
		{recurAlert("r", 4001, inbound), recurAlert("r", 4001, outbound)},
		{recurAlert("r", 4003, `{"query":{"hostname":"Evil.top"}}`), recurAlert("r", 4003, `{"query":{"hostname":"evil.top"}}`)},
		{recurAlert("intel:ip:1.2.3.4", 4001, `{"src_endpoint":{"ip":"1.2.3.4","port":1}}`), recurAlert("intel:ip:1.2.3.4", 4001, `{"src_endpoint":{"ip":"1.2.3.4","port":2}}`)},
		{procAlert("r", "root", "/bin/bash", "/sbin/sshd", "bash -c id"), procAlert("r", "root", "/usr/bin/bash", "/usr/sbin/sshd", "bash -c id")},
	}
	for i, p := range same {
		if a, b := recurKey(p[0]), recurKey(p[1]); a == "" || a != b {
			t.Errorf("same[%d] 应同键：%q vs %q", i, a, b)
		}
	}
	differ := [][2]*ent.Alert{
		{recurAlert("r", 4003, `{"query":{"hostname":"a.top"}}`), recurAlert("r", 4003, `{"query":{"hostname":"b.top"}}`)},
		{recurAlert("r", 4003, `{"query":{"hostname":"a.top"},"container":{"uid":"203","name":"dns-primary"}}`),
			recurAlert("r", 4003, `{"query":{"hostname":"a.top"},"container":{"uid":"204","name":"dns-secondary"}}`)},
		{recurAlert("r", 1007, `{"process":{"cmd_line":"id","file":{"path":"/usr/bin/id"}}}`),
			recurAlert("r", 1007, `{"process":{"cmd_line":"id -a","file":{"path":"/usr/bin/id"}}}`)},
		{procAlert("r", "root", "/usr/bin/id", "", "id"), procAlert("r", "www-data", "/usr/bin/id", "", "id")},
		{procAlert("r", "root", "/usr/bin/id", "/usr/sbin/cron", "id"), procAlert("r", "root", "/usr/bin/id", "/usr/sbin/sshd", "id")},
	}
	for i, p := range differ {
		if a, b := recurKey(p[0]), recurKey(p[1]); a == b {
			t.Errorf("differ[%d] 不应同键：%q", i, a)
		}
	}
	for i, al := range []*ent.Alert{
		{RuleID: "xdr:beacon"},
		recurAlert("r", 1007, `{}`),
		recurAlert("r", 3002, `{"user":{"name":"root"}}`),
		recurAlert("r", 4003, `garbage`),
	} {
		if k := recurKey(al); k != "" {
			t.Errorf("none[%d] 取不到实体应为空，得到 %q", i, k)
		}
	}
}

// 粗键：同映像同用户同父进程、命令行不同同键；解释器与命令包装器没有粗键；
// 用户、父进程、容器不同不同键；首次出现规则去掉映像。
func TestCoarseKey(t *testing.T) {
	same := [][2]*ent.Alert{
		{procAlert("r", "root", "/sbin/lvcreate", "/usr/bin/pvesm", "lvcreate -V 4096k --name vm-145"),
			procAlert("r", "root", "/usr/sbin/lvcreate", "/usr/bin/pvesm", "lvcreate -V 8192k --name vm-146")},
		{procAlert("r", `NT AUTHORITY\SYSTEM`, `C:\\Windows\\System32\\sc.exe`, "", "sc create a"),
			procAlert("r", `NT AUTHORITY\SYSTEM`, `c:\\windows\\system32\\SC.EXE`, "", "sc create b")},
		{procAlert(sigma.RuleNewProcess, "root", "/usr/bin/fstrim", "", "fstrim"),
			procAlert(sigma.RuleNewProcess, "root", "/usr/bin/kpartx", "", "kpartx -av")},
	}
	for i, p := range same {
		if a, b := coarseOf(p[0]), coarseOf(p[1]); a == "" || a != b {
			t.Errorf("same[%d] 应同粗键：%q vs %q", i, a, b)
		}
	}
	differ := [][2]*ent.Alert{
		{procAlert("r", "root", "/usr/bin/pgrep", "", "pgrep a"), procAlert("r", "www-data", "/usr/bin/pgrep", "", "pgrep a")},
		{procAlert("r", "root", "/usr/bin/pgrep", "/usr/sbin/cron", "pgrep a"), procAlert("r", "root", "/usr/bin/pgrep", "/usr/sbin/sshd", "pgrep a")},
		{procAlert("r", "root", "/usr/bin/pgrep", "", "pgrep a"), procAlert("r", "root", "/usr/bin/pkill", "", "pgrep a")},
		{procAlert(sigma.RuleNewProcess, "root", "/usr/bin/fstrim", "", "fstrim"), procAlert(sigma.RuleNewProcess, "100000", "/usr/bin/fstrim", "", "fstrim")},
	}
	for i, p := range differ {
		if a, b := coarseOf(p[0]), coarseOf(p[1]); a == b {
			t.Errorf("differ[%d] 不应同粗键：%q", i, a)
		}
	}
	inLXC := recurAlert("r", 1007, `{"process":{"cmd_line":"pgrep a","file":{"path":"/usr/bin/pgrep"}},"container":{"uid":"203","name":"dns"}}`)
	if a, b := coarseOf(inLXC), coarseOf(recurAlert("r", 1007, `{"process":{"cmd_line":"pgrep a","file":{"path":"/usr/bin/pgrep"}}}`)); a == "" || a == b {
		t.Errorf("不同容器不应同粗键：%q vs %q", a, b)
	}
	for _, image := range []string{"/bin/bash", "/usr/bin/sh", "/usr/local/bin/python3.12", "/usr/bin/perl5.36", "/usr/bin/timeout",
		`C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`, `C:\\Windows\\System32\\cmd.exe`} {
		if c := coarseOf(procAlert("r", "root", image, "", "x")); c != "" {
			t.Errorf("解释器 %s 不应有粗键，得到 %q", image, c)
		}
	}
	if c := coarseOf(recurAlert("r", 4003, `{"query":{"hostname":"a.top"}}`)); c != "" {
		t.Errorf("非进程类不应有粗键：%q", c)
	}
}

func TestSelfWatchCorrelationBucket(t *testing.T) {
	host := uuid.New()
	proc := &ent.Alert{RuleID: "30bcce26", AssetID: &host}
	cp1 := &ent.Alert{RuleID: sigma.RuleControlPlaneChange, AssetID: &host}
	cp2 := &ent.Alert{RuleID: sigma.RuleControlPlaneChange, AssetID: &host}
	silent := &ent.Alert{RuleID: sigma.RuleCoreAgentSilent, AssetID: &host}
	tamper := &ent.Alert{RuleID: sigma.RuleAuditTamper}

	if correlationBucket(cp1) != correlationBucket(cp2) {
		t.Fatalf("同节点控制面变更告警应进同一桶：%q vs %q", correlationBucket(cp1), correlationBucket(cp2))
	}
	if correlationBucket(cp1) == correlationBucket(proc) {
		t.Fatalf("控制面变更不应与宿主机普通进程告警同桶：%q", correlationBucket(cp1))
	}
	if correlationBucket(cp1) == correlationBucket(silent) {
		t.Fatalf("不同类的平台自监控不应同桶：%q", correlationBucket(cp1))
	}
	if correlationBucket(tamper) == correlationBucket(&ent.Alert{RuleID: "other"}) {
		t.Fatalf("审计链篡改不应进普通无资产桶：%q", correlationBucket(tamper))
	}
}
