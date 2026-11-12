package repaircmd

import (
	"strings"
	"testing"
)

func TestReclaimTemplates(t *testing.T) {
	for _, cmd := range []string{
		"docker image prune -f",
		"docker image prune -a --filter until=168h -f",
		"docker builder prune -f",
		"docker builder prune --filter until=168h -f",
		"apt-get clean",
		"journalctl --vacuum-size=500M",
		"find -- /srv/cache -xdev -type f -mtime +7 -delete",
		"find -- /srv/cache -xdev -type f -mtime +3650 -delete",
	} {
		if _, ok := Parse(cmd); !ok {
			t.Errorf("模板被拒绝: %s", cmd)
		}
	}
	for _, cmd := range []string{
		"docker image prune -af",
		"docker image prune -a --filter until=24h -f",
		"docker volume prune -f",
		"journalctl --vacuum-time=1s",
		"docker image prune -f\n",
		"sudo apt-get clean",
		"apt-get clean; id",
		"find -- /srv/cache -xdev -type f -mtime +6 -delete",
		"find -- /srv/cache -xdev -type f -mtime +3651 -delete",
		"find -- /srv/cache -xdev -type f -mtime +007 -delete",
		"find -- /srv/cache/../data -xdev -type f -mtime +7 -delete",
		"find -- /srv/cache -type f -mtime +7 -delete",
		"find -- /srv/cache -xdev -type f -mtime +7 -delete && id",
		"find -- /var/lib/docker -xdev -type f -mtime +7 -delete",
	} {
		if _, ok := Parse(cmd); ok {
			t.Errorf("接受了非模板命令: %s", cmd)
		}
	}
}

func TestReclaimPaths(t *testing.T) {
	for _, p := range []string{"/", "relative", "/srv/../etc", "/srv/cache/", "/srv//cache", "/etc", "/etc/apt", "/bin", "/sbin", "/usr/local", "/lib", "/lib64", "/lib32/x", "/boot/x", "/proc/1", "/sys/x", "/dev/shm", "/root/.ssh", "/root", "/var", "/var/lib", "/var/lib/postgresql/x", "/var/lib/docker/x", "/var/log", "/var/log/audit/x", "/opt", "/opt/openxdr", "/opt/openxdr-backup/x", "/tmp/$(id)", "/tmp/a b"} {
		if Path(p) {
			t.Errorf("接受了禁止目录: %s", p)
		}
	}
	for _, p := range []string{"/srv/cache", "/tmp/cache", "/var/cache/apt", "/var/log/app", "/opt/app/cache"} {
		if !Path(p) {
			t.Errorf("拒绝了合法目录: %s", p)
		}
	}
}

func TestDockerPrune7dAndBackupCompress(t *testing.T) {
	vol := strings.Repeat("a1", 32)
	cmd, ok := FormatDockerPrune7d([]string{vol})
	if !ok || !IsStandingDiskAction(cmd) {
		t.Fatalf("合法匿名卷回收被拒绝: %q %v", cmd, ok)
	}
	if _, ok := FormatDockerPrune7d([]string{"pgdata"}); ok {
		t.Fatal("具名卷不应通过匿名卷校验")
	}

	bCmd, undo, ok := FormatBackupCompress("/var/backups", []string{"/var/backups/db-2026-10-01.sql"})
	if !ok || !IsStandingDiskAction(bCmd) {
		t.Fatalf("合法旧备份无损压缩被拒绝: %q %v", bCmd, ok)
	}
	if !strings.Contains(bCmd, "gzip -9 -k -- /var/backups/db-2026-10-01.sql") ||
		!strings.Contains(bCmd, "gzip -t -- /var/backups/db-2026-10-01.sql.gz") ||
		undo != "gzip -d -- /var/backups/db-2026-10-01.sql.gz" {
		t.Fatalf("压缩或回退命令不符: cmd=%q undo=%q", bCmd, undo)
	}
	for _, bad := range []string{
		"/var/backups/already.sql.gz",
		"/etc/passwd",
		"/var/backups/../etc/passwd",
		"/var/lib/postgresql/16/main/base.tar",
		"/opt/openxdr/data.bak",
	} {
		if _, _, ok := FormatBackupCompress("/var/backups", []string{bad}); ok {
			t.Errorf("不安全或已压缩文件被接受: %s", bad)
		}
	}
}
