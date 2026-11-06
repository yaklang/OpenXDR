package repairpolicy

import (
	"openxdr/server/ent"
	"strings"
	"testing"
	"time"
)

func TestDiskFindingScope(t *testing.T) {
	for _, f := range []*ent.Finding{{Key: "disk-full"}, {Title: "磁盘将满"}, {Title: "根分区空间不足"}, {Title: "root filesystem capacity"}, {Key: "disk-usage"}} {
		if !diskFinding(f) {
			t.Errorf("磁盘容量待办被拒绝: %+v", f)
		}
	}
	for _, f := range []*ent.Finding{nil, {Title: "service failed"}, {Title: "磁盘 I/O 错误"}, {Title: "内存空间不足"}, {Key: "disk", Title: "正常"}} {
		if diskFinding(f) {
			t.Errorf("非容量待办被接受: %+v", f)
		}
	}
	g := Grant{Action: ReclaimDisk, Paths: []string{"/srv/cache"}}
	if !actionScope(g, ReclaimDisk, ReclaimDisk, "find -- /srv/cache -xdev -type f -mtime +7 -delete") {
		t.Fatal("授权目录被拒绝")
	}
	for _, cmd := range []string{"find -- /srv/other -xdev -type f -mtime +7 -delete", "find -- /srv/cache/sub -xdev -type f -mtime +7 -delete", "find -- /srv -xdev -type f -mtime +7 -delete"} {
		if actionScope(g, ReclaimDisk, ReclaimDisk, cmd) {
			t.Fatal("越过精确目录授权", cmd)
		}
	}
	if actionScope(g, RestartFailedService, "a.service", "systemctl restart -- a.service") {
		t.Fatal("借用其它动作的授权")
	}
}

func TestDiskProbeValidation(t *testing.T) {
	now := time.Now()
	cmd := "df -P /srv"
	good := "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/data 1000 950 50 95% /srv\n"
	code := int32(0)
	for _, tc := range []struct {
		name, out string
		change    func(*ent.Command)
		valid     bool
	}{
		{"valid", good, nil, true},
		{"bad-number", strings.Replace(good, "1000", "-1000", 1), nil, false},
		{"bad-percent", strings.Replace(good, "95%", "94%", 1), nil, false},
		{"bad-mount", strings.Replace(good, "/srv", "/other", 1), nil, false},
		{"incomplete", "", nil, false},
		{"extra-line", good + "/dev/extra 1000 950 50 95% /extra\n", nil, false},
		{"truncated", good, func(c *ent.Command) { c.Truncated = true }, false},
		{"stderr", good, func(c *ent.Command) { s := "df: error"; c.Stderr = &s }, false},
		{"future", good, func(c *ent.Command) { t := now.Add(time.Hour); c.CompletedAt = &t }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.out
			c := &ent.Command{Kind: "exec", Cmd: &cmd, Status: "succeeded", ExitCode: &code, Stdout: &out, CreatedAt: now.Add(-time.Second), CompletedAt: &now}
			if tc.change != nil {
				tc.change(c)
			}
			_, err := diskSample(c, "/srv")
			if (err == nil) != tc.valid {
				t.Fatal(err)
			}
		})
	}
}
