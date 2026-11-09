package response

import (
	"net/netip"
	"strings"
	"testing"
)

func TestNormalizeTarget(t *testing.T) {
	server := ProtectedAddrs([]string{"10.1.1.199:8081", "[2001:db8::9]:8081", "garbage"})
	if len(server) != 2 {
		t.Fatalf("放行地址解析不对: %v", server)
	}
	ok := map[[2]string]string{
		{"block_network", " 45.9.148.10 "}:         "45.9.148.10",
		{"block_network", "45.9.148.0/24"}:         "45.9.148.0/24",
		{"block_network", "C2.Example.COM."}:       "c2.example.com",
		{"unblock_network", "10.0.0.0/8"}:          "10.0.0.0/8",
		{"quarantine_file", "/tmp/x.sh"}:           "/tmp/x.sh",
		{"restore_file", `C:\Users\a\evil.exe`}:    `C:\Users\a\evil.exe`,
		{"disable_account", "deploy"}:              "deploy",
		{"isolate_container", "4F173E0D45B0"}:      "4f173e0d45b0",
		{"unisolate_container", "101"}:             "101",
		{"block_execution", `C:\Users\a\evil.exe`}: `C:\Users\a\evil.exe`,
		{"unblock_execution", `D:\x y\a.exe`}:      `D:\x y\a.exe`,
	}
	for in, want := range ok {
		got, err := NormalizeTarget(in[0], in[1], server)
		if err != nil || got != want {
			t.Errorf("%v: 期望 %q，得到 %q %v", in, want, got, err)
		}
	}
	bad := map[[2]string]string{
		{"block_network", ""}:                    "未指定",
		{"block_network", "10.0.0.0/8"}:          "过宽",
		{"block_network", "10.1.1.0/24"}:         "server",
		{"block_network", "2001:db8::9"}:         "server",
		{"block_network", "127.0.0.1"}:           "不能封锁",
		{"block_network", "evil';drop"}:          "IP、网段或域名",
		{"block_network", "localhost"}:           "IP、网段或域名",
		{"quarantine_file", "relative/x"}:        "绝对路径",
		{"quarantine_file", "/tmp/../etc/x"}:     "绝对路径",
		{"disable_account", "root"}:              "内置",
		{"disable_account", "a b"}:               "账号名",
		{"isolate_container", "abc"}:             "容器 ID",
		{"block_execution", "/tmp/../x"}:         "规范文件绝对路径",
		{"block_execution", `relative\a.exe`}:    "规范文件绝对路径",
		{"block_execution", "C:\\a.exe\nC:\\b"}:  "规范文件绝对路径",
		{"isolate_container", "4f173e0d45b0;id"}: "容器 ID",
		{"disable_account", "-e"}:                "账号名",
		{"kill_process", "x"}:                    "不需要目标",
	}
	for in, want := range bad {
		if _, err := NormalizeTarget(in[0], in[1], server); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: 应因「%s」拒绝，得到 %v", in, want, err)
		}
	}
	if _, err := NormalizeTarget("block_network", "10.1.0.0/16", []netip.Addr{}); err != nil {
		t.Errorf("没有放行地址时只按范围检查: %v", err)
	}
}

func TestExecutionTargetOS(t *testing.T) {
	for _, kind := range []string{"block_execution", "unblock_execution"} {
		for _, tc := range []struct {
			os, target string
			valid      bool
		}{
			{"linux", "/tmp/evil", true},
			{"windows", `C:\tmp\evil.exe`, true},
			{"linux", `C:\tmp\evil.exe`, false},
			{"windows", "/tmp/evil", false},
			{"", "/tmp/evil", false},
			{"darwin", "/tmp/evil", false},
			{"linux", "/", false},
			{"linux", "/tmp/../evil", false},
			{"linux", "relative", false},
			{"linux", "/tmp/a\x00b", false},
		} {
			_, err := validateExecutionTarget(tc.os, kind, tc.target)
			if (err == nil) != tc.valid {
				t.Errorf("%s %s %q: %v", kind, tc.os, tc.target, err)
			}
		}
	}
}
