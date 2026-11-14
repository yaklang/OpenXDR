package attemptoutcome

import (
	"net/netip"
	"strings"
	"testing"

	"openxdr/server/ent"
	"openxdr/server/ent/schema"
)

func TestIsAuthFailureRuleAndIncidentClassification(t *testing.T) {
	allowed := []string{
		RuleLinuxLoginFailure,
		RuleSSHAuthFailure,
		RuleWinLoginFailure,
		RuleTemporalLinuxAuthBurst,
		RuleTemporalLinuxAccountAuthBurst,
		RuleTemporalSSHDFailBurst,
		RuleTemporalWindowsFailBurst,
	}
	for _, r := range allowed {
		if !IsAuthFailureRule(r) {
			t.Fatalf("认证失败族规则 %s 应被识别", r)
		}
	}

	// 高危、爆破成功、横向喷洒、情报命中、无成功对照的数据库规则等绝不能归入本白名单
	rejected := []string{
		"",
		"temporal:ssh-brute-then-success",
		"temporal:ssh-lateral-spray",
		"temporal:postgresql-auth-burst",
		"intel:ip:198.51.100.10",
		"intel:domain:evil.example",
		"eba9127a-8d70-4c92-a316-5a9f3e21b7d4", // Mimikatz / 凭据窃取类普通 UUID
	}
	for _, r := range rejected {
		if IsAuthFailureRule(r) {
			t.Fatalf("非认证失败族规则 %q 绝不应放入自动放行白名单", r)
		}
	}

	if IncidentAllAuthFailures(nil) {
		t.Fatal("空告警列表不应判为全认证失败")
	}
	onlyAuth := []*ent.Alert{
		{RuleID: RuleLinuxLoginFailure},
		{RuleID: RuleTemporalLinuxAuthBurst},
	}
	if !IncidentAllAuthFailures(onlyAuth) || !IncidentHasAuthFailures(onlyAuth) {
		t.Fatal("纯认证失败告警列表判定错误")
	}
	mixed := []*ent.Alert{
		{RuleID: RuleLinuxLoginFailure},
		{RuleID: "intel:ip:198.51.100.10"},
	}
	if IncidentAllAuthFailures(mixed) {
		t.Fatal("混入情报或高危告警时绝不能判为全认证失败")
	}
	if !IncidentHasAuthFailures(mixed) {
		t.Fatal("混入其他告警时仍应识别含认证失败以便研判上下文附注")
	}
}

func TestParseAuthEvent3002Variants(t *testing.T) {
	// 1. Authentik 登录失败
	akFail := []byte(`{"activity_id":1,"status_id":2,"status":"Failure","user":{"name":"akadmin"},"service":{"name":"authentik"},"src_endpoint":{"ip":"203.0.113.45"},"metadata":{"product":{"name":"Authentik"}}}`)
	ev, ok := ParseAuthEvent(3002, "authentik", "linux", "", akFail)
	if !ok || !ev.Failure || ev.Success || ev.SrcIP != "203.0.113.45" || ev.Account != "akadmin" || ev.ServiceSlug != "authentik" || ev.SourceKind != "authentik" {
		t.Fatalf("Authentik 失败解析不符: ok=%v ev=%+v", ok, ev)
	}

	// 2. Linux SSH 登录成功（带 ::ffff: 映射地址，应规范化为 IPv4）
	sshSucc := []byte(`{"activity_id":1,"status_id":1,"user":{"name":"ubuntu"},"service":{"name":"sshd"},"login_session":{"src_ip":"::ffff:203.0.113.45"}}`)
	ev, ok = ParseAuthEvent(3002, "agent", "linux", "", sshSucc)
	if !ok || !ev.Success || ev.Failure || ev.SrcIP != "203.0.113.45" || ev.Account != "ubuntu" || ev.ServiceSlug != "ssh" || ev.SourceKind != "agent" {
		t.Fatalf("Linux SSH 成功解析不符: ok=%v ev=%+v", ok, ev)
	}

	// 3. Windows Security 4625 RDP 登录失败
	winFail := []byte(`{"activity_id":1,"event_id":4625,"status_id":2,"log_name":"Security","user":{"name":"Administrator"},"service":{"name":"logon-type-10"},"src_endpoint":{"ip":"198.51.100.77"}}`)
	ev, ok = ParseAuthEvent(3002, "agent", "windows", "", winFail)
	if !ok || !ev.Failure || ev.SrcIP != "198.51.100.77" || ev.ServiceSlug != "windows-rdp" {
		t.Fatalf("Windows 4625 解析不符: ok=%v ev=%+v", ok, ev)
	}

	// 4. Windows 4648 显式凭据登录成功（activity_id != 1 但 event_id == 4648，应视为成功认证）
	win4648 := []byte(`{"activity_id":2,"event_id":4648,"status_id":1,"log_name":"Security","user":{"name":"Administrator"},"src_endpoint":{"ip":"198.51.100.77"}}`)
	ev, ok = ParseAuthEvent(3002, "agent", "windows", "", win4648)
	if !ok || !ev.Success || ev.SrcIP != "198.51.100.77" {
		t.Fatalf("Windows 4648 应识别为成功认证: ok=%v ev=%+v", ok, ev)
	}

	// 5. Windows 4720 创建用户 / 1102 清空审计日志（同为 3002 status_id=1，但非登录认证，必须排除）
	win4720 := []byte(`{"activity_id":3,"event_id":4720,"status_id":1,"log_name":"Security","user":{"name":"backdoor"}}`)
	if _, ok := ParseAuthEvent(3002, "agent", "windows", "", win4720); ok {
		t.Fatal("账户创建事件 4720 不应被误判为登录认证")
	}
	win1102 := []byte(`{"activity_id":6,"event_id":1102,"status_id":1,"log_name":"Security","user":{"name":"SYSTEM"}}`)
	if _, ok := ParseAuthEvent(3002, "agent", "windows", "", win1102); ok {
		t.Fatal("审计日志清空 1102 不应被误判为登录认证")
	}
}

func TestParseSyslogSSHDAndUsernameSpoofingDefense(t *testing.T) {
	// 正常 Accepted
	acc := []byte(`{"metadata":{"product":{"name":"sshd"}},"message":"Accepted publickey for root from 203.0.113.10 port 51234 ssh2: RSA SHA256:abc"}`)
	ev, ok := ParseAuthEvent(100001, "syslog", "linux", "", acc)
	if !ok || !ev.Success || ev.SrcIP != "203.0.113.10" || ev.Account != "root" || ev.ServiceSlug != "ssh" {
		t.Fatalf("sshd Accepted 解析不符: ok=%v ev=%+v", ok, ev)
	}

	// 正常 Failed invalid user
	fail := []byte(`{"metadata":{"product":{"name":"sshd"}},"message":"Failed password for invalid user oracle from 198.51.100.22 port 44112 ssh2"}`)
	ev, ok = ParseAuthEvent(100001, "syslog", "linux", "", fail)
	if !ok || !ev.Failure || ev.SrcIP != "198.51.100.22" || ev.Account != "oracle" {
		t.Fatalf("sshd Failed 解析不符: ok=%v ev=%+v", ok, ev)
	}

	// Invalid user
	inv := []byte(`{"metadata":{"product":{"name":"sshd"}},"message":"Invalid user postgres from 198.51.100.23 port 39001"}`)
	ev, ok = ParseAuthEvent(100001, "syslog", "linux", "", inv)
	if !ok || !ev.Failure || ev.SrcIP != "198.51.100.23" || ev.Account != "postgres" {
		t.Fatalf("sshd Invalid user 解析不符: ok=%v ev=%+v", ok, ev)
	}

	// PAM authentication failure
	pam := []byte(`{"metadata":{"product":{"name":"sshd"}},"message":"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.24  user=root"}`)
	ev, ok = ParseAuthEvent(100001, "syslog", "linux", "", pam)
	if !ok || !ev.Failure || ev.SrcIP != "198.51.100.24" || ev.Account != "root" {
		t.Fatalf("sshd PAM authentication failure 解析不符: ok=%v ev=%+v", ok, ev)
	}

	// 攻击者在用户名中注入伪造的 "from 10.0.0.1 port 22"：
	// 失败日志由 authfields 拒绝歧义用户名并返回空 SrcIP（触发 missing_source_ip 不自动结案，绝不采信 10.0.0.1）；
	// 成功日志从右向左取真实对端 IP（203.0.113.99），防止通过伪造用户名逃避同源成功认证检测。
	spoofFail := []byte(`{"metadata":{"product":{"name":"sshd"}},"message":"Failed password for invalid user admin from 10.0.0.1 port 22 from 203.0.113.88 port 54321 ssh2"}`)
	ev, ok = ParseAuthEvent(100001, "syslog", "linux", "", spoofFail)
	if !ok || !ev.Failure || ev.SrcIP != "" {
		t.Fatalf("伪造用户名失败日志应拒绝解析来源 IP（交不完整分支兜底），不应污染为伪造地址: ok=%v ev=%+v", ok, ev)
	}

	spoofAcc := []byte(`{"metadata":{"product":{"name":"sshd"}},"message":"Accepted password for fake from 127.0.0.1 port 22 from 203.0.113.99 port 54322 ssh2"}`)
	ev, ok = ParseAuthEvent(100001, "syslog", "linux", "", spoofAcc)
	if !ok || !ev.Success || ev.SrcIP != "203.0.113.99" {
		t.Fatalf("Accepted 伪造用户名注入不应掩盖真实来源 IP: ok=%v ev=%+v", ok, ev)
	}
}

func TestManuallyHeldAndHelpers(t *testing.T) {
	if ManuallyHeld(nil) || ManuallyHeld(&ent.Incident{}) {
		t.Fatal("空事件不应判为人工锁定")
	}
	// 系统自动升级（Owner=human, Stage=escalated，无人工锁）不阻止确定性机制结案
	if ManuallyHeld(&ent.Incident{Work: &schema.IncidentWork{Owner: "human", Stage: "escalated"}}) {
		t.Fatal("系统自动升级不应被误判为人工手动接管")
	}
	if !ManuallyHeld(&ent.Incident{Work: &schema.IncidentWork{ManualLock: true}}) {
		t.Fatal("ManualLock 必须阻止自动结案")
	}
	if !ManuallyHeld(&ent.Incident{Work: &schema.IncidentWork{ManualOwner: "zachary"}}) {
		t.Fatal("ManualOwner 必须阻止自动结案")
	}
	if !ManuallyHeld(&ent.Incident{Work: &schema.IncidentWork{Owner: "human", Stage: "investigating"}}) {
		t.Fatal("人工接管阶段必须阻止自动结案")
	}

	k := HardeningKey("Authentik SSO / Portal" + strings.Repeat("-extra", 20))
	if len(k) > 64 || !strings.HasPrefix(k, "auth-hardening-authentik") {
		t.Fatalf("HardeningKey 规范化越界或不符: %q", k)
	}

	if !isPublicAddr(netip.MustParseAddr("203.0.113.10")) {
		t.Fatal("203.0.113.10 应判为外部公网地址")
	}
	for _, nonPub := range []string{"10.1.1.36", "192.168.1.1", "172.16.5.4", "100.100.103.88", "127.0.0.1", "fd7a:115c:a1e0::1"} {
		if isPublicAddr(netip.MustParseAddr(nonPub)) {
			t.Fatalf("%s 不应判为外部公网地址", nonPub)
		}
	}
}
