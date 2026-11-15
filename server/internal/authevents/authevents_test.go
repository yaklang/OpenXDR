package authevents

import (
	"testing"
)

func TestParse3002AndSyslogSSHD(t *testing.T) {
	// 1. Linux SSH 3002 失败与成功
	p1, ok := Parse(3002, "agent", "linux", "root", []byte(`{"activity_id":1,"status_id":2,"user":{"name":"root"},"service":{"name":"sshd"},"src_endpoint":{"ip":"203.0.113.10"}}`))
	if !ok || !p1.Failure || p1.Success || p1.SrcIP != "203.0.113.10" || p1.ServiceSlug != "ssh" || p1.SourceKind != "agent" || p1.Account != "root" {
		t.Fatalf("Linux 3002 失败解析不符: ok=%v %+v", ok, p1)
	}

	// 2. Windows RDP 4625 失败
	p2, ok := Parse(3002, "agent", "windows", "", []byte(`{"activity_id":1,"event_id":4625,"status_id":2,"log_name":"Security","user":{"name":"Administrator"},"service":{"name":"logon-type-10"},"src_endpoint":{"ip":"::ffff:198.51.100.22"}}`))
	if !ok || !p2.Failure || p2.SrcIP != "198.51.100.22" || p2.ServiceSlug != "windows-rdp" || p2.ServiceLabel != "Windows RDP" {
		t.Fatalf("Windows RDP 3002 解析不符: ok=%v %+v", ok, p2)
	}

	// 3. Windows 账户创建 4720（activity_id=3）与审计清日志不得进入认证物化表
	if _, ok := Parse(3002, "agent", "windows", "admin", []byte(`{"activity_id":3,"event_id":4720,"status_id":1,"user":{"name":"backdoor"}}`)); ok {
		t.Fatal("账户管理 4720 不应被物化为登录认证事件")
	}

	// 4. Authentik 3002
	p4, ok := Parse(3002, "authentik", "linux", "akadmin", []byte(`{"activity_id":1,"status":"Failure","user":{"name":"akadmin"},"src_endpoint":{"ip":"203.0.113.99"}}`))
	if !ok || !p4.Failure || p4.ServiceSlug != "authentik" || p4.SourceKind != "authentik" {
		t.Fatalf("Authentik 3002 解析不符: ok=%v %+v", ok, p4)
	}

	// 5. Syslog sshd Accepted 防伪造用户名注入 "from 1.2.3.4"
	p5, ok := Parse(100001, "syslog", "linux", "", []byte(`{"metadata":{"product":{"name":"sshd"}},"message":"Accepted publickey for invalid user fake from 1.2.3.4 port 22 from 198.51.100.88 port 54321 ssh2"}`))
	if !ok || !p5.Success || p5.SrcIP != "198.51.100.88" || p5.ServiceSlug != "ssh" || p5.SourceKind != "syslog" {
		t.Fatalf("Syslog sshd Accepted 解析不符: ok=%v %+v", ok, p5)
	}

	// 6. Syslog sshd PAM authentication failure
	p6, ok := Parse(100001, "syslog", "linux", "", []byte(`{"metadata":{"product":{"name":"sshd"}},"message":"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.77  user=ubuntu"}`))
	if !ok || !p6.Failure || p6.SrcIP != "203.0.113.77" || p6.Account != "ubuntu" {
		t.Fatalf("Syslog PAM failure 解析不符: ok=%v %+v", ok, p6)
	}

	// 7. 非 sshd 的 100001 syslog 忽略
	if _, ok := Parse(100001, "syslog", "linux", "", []byte(`{"metadata":{"product":{"name":"nginx"}},"message":"Accepted something from 203.0.113.1 port 80"}`)); ok {
		t.Fatal("非 sshd 的 syslog 事件不应物化进 auth_events")
	}
}
