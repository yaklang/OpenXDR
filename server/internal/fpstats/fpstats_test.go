package fpstats

import (
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/suppress"
)

// 被拒的是整条规则时，同规则下更窄的按实体草案照样可以提；拒了窄的，宽的不提
func TestCovered(t *testing.T) {
	now := time.Now()
	narrow := []suppress.Condition{{Field: "file.path", Op: "equals", Value: "/a"}}
	rejected := func(conds []suppress.Condition) *ent.Suppression {
		at := now.Add(-time.Hour)
		return &ent.Suppression{Status: "rejected", ReviewedAt: &at, Conditions: conds}
	}
	if covered(rejected(nil), narrow, now, time.Hour*24) {
		t.Error("拒了整条规则不该挡住按实体的草案")
	}
	if !covered(rejected(narrow), nil, now, time.Hour*24) {
		t.Error("拒了按实体的，整条规则更不该提")
	}
	past := now.Add(-time.Minute)
	if covered(&ent.Suppression{Status: "active", ExpiresAt: &past}, narrow, now, 0) {
		t.Error("过期的抑制不算覆盖")
	}
}

func TestGeneric(t *testing.T) {
	for _, v := range []string{"/usr/bin/bash", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "/usr/bin/python3.11"} {
		if !generic(imageField, v) || !generic(cmdLineField, v) {
			t.Errorf("%s 应算通用映像/裸解释器命令行", v)
		}
	}
	if generic(imageField, "/opt/adguardhome/AdGuardHome") || generic("file.path", "/usr/bin/bash") ||
		generic(cmdLineField, "/bin/sh -c /opt/check.sh") {
		t.Error("具体程序、带参数的具体命令行与非映像字段不算通用")
	}
}

func TestTempDirPrefix(t *testing.T) {
	if got, ok := tempDirPrefix("/tmp/go-build3516107513/b001/feishu.test"); !ok || got != "/tmp/go-build" {
		t.Fatalf("got (%q, %v), want (/tmp/go-build, true)", got, ok)
	}
	if got, ok := tempDirPrefix("/var/tmp/go-build987654/b012/sigma.test"); !ok || got != "/var/tmp/go-build" {
		t.Fatalf("got (%q, %v), want (/var/tmp/go-build, true)", got, ok)
	}
	for _, p := range []string{"/tmp/evil12345", "/tmp/a12345/x", "/usr/bin/bash"} {
		if _, ok := tempDirPrefix(p); ok {
			t.Errorf("%s 不应提取为临时构建目录前缀", p)
		}
	}
}
