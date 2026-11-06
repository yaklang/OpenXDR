package repaircmd

import "testing"

func TestReclaimTemplates(t *testing.T) {
	for _, cmd := range []string{"docker image prune -f", "docker builder prune -f", "apt-get clean", "find -- /srv/cache -xdev -type f -mtime +7 -delete", "find -- /srv/cache -xdev -type f -mtime +3650 -delete"} {
		if _, ok := Parse(cmd); !ok {
			t.Errorf("模板被拒绝: %s", cmd)
		}
	}
	for _, cmd := range []string{"docker image prune -af", "docker image prune -f\n", "sudo apt-get clean", "apt-get clean; id", "find -- /srv/cache -xdev -type f -mtime +6 -delete", "find -- /srv/cache -xdev -type f -mtime +3651 -delete", "find -- /srv/cache -xdev -type f -mtime +007 -delete", "find -- /srv/cache/../data -xdev -type f -mtime +7 -delete", "find -- /srv/cache -type f -mtime +7 -delete", "find -- /srv/cache -xdev -type f -mtime +7 -delete && id", "find -- /var/lib/docker -xdev -type f -mtime +7 -delete"} {
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
