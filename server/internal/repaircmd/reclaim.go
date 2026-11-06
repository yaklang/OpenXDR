// Package repaircmd 定义磁盘回收的封闭命令语法，不授予执行权限。
package repaircmd

import (
	"path"
	"regexp"
	"strconv"
	"strings"
)

var fixed = regexp.MustCompile(`^(docker image prune -f|docker builder prune -f|apt-get clean)$`)
var aged = regexp.MustCompile(`^find -- (/[a-zA-Z0-9_./-]+) -xdev -type f -mtime \+([0-9]{1,4}) -delete$`)
var absolute = regexp.MustCompile(`^/[a-zA-Z0-9_./-]*$`)

// Mount 只接受可直接放入单条 df 命令的规范绝对路径。
func Mount(p string) bool {
	return absolute.MatchString(p) && path.Clean(p) == p && !strings.Contains(p, "..")
}

func Path(p string) bool {
	if !Mount(p) || p == "/" {
		return false
	}
	for _, forbidden := range []string{"/etc", "/bin", "/sbin", "/usr", "/boot", "/proc", "/sys", "/dev", "/root/.ssh", "/var/lib/postgresql", "/var/lib/docker", "/var/log/audit"} {
		if p == forbidden || strings.HasPrefix(p, forbidden+"/") || strings.HasPrefix(forbidden, p+"/") {
			return false
		}
	}
	first := strings.Split(strings.TrimPrefix(p, "/"), "/")[0]
	return !strings.HasPrefix(first, "lib") && !strings.HasPrefix(p, "/opt/openxdr") && p != "/opt"
}

// Parse 返回精确删除目录；空目录表示三条固定缓存回收命令之一。
func Parse(cmd string) (string, bool) {
	if fixed.MatchString(cmd) {
		return "", true
	}
	m := aged.FindStringSubmatch(cmd)
	if len(m) != 3 || !Path(m[1]) {
		return "", false
	}
	n, err := strconv.Atoi(m[2])
	return m[1], err == nil && n >= 7 && n <= 3650 && strconv.Itoa(n) == m[2]
}
