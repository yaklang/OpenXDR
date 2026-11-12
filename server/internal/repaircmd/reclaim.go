// Package repaircmd 定义磁盘回收与无损压缩的封闭命令语法，不授予执行权限。
package repaircmd

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var fixed = regexp.MustCompile(`^(docker image prune -f|docker image prune -a --filter until=168h -f|docker builder prune -f|docker builder prune --filter until=168h -f|apt-get clean|journalctl --vacuum-size=500M)$`)
var aged = regexp.MustCompile(`^find -- (/[a-zA-Z0-9_./-]+) -xdev -type f -mtime \+([0-9]{1,4}) -delete$`)
var absolute = regexp.MustCompile(`^/[a-zA-Z0-9_./-]*$`)
var anonVolumeID = regexp.MustCompile(`^[0-9a-f]{64}$`)

var compressedSuffixes = []string{".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".zst", ".tzst", ".zip", ".7z", ".lz4", ".rar"}

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

// BackupDir 校验旧备份无损压缩的扫描目录：允许 /var/backups 等备份目录，仍排除系统运行目录、数据库目录、SSH 钥匙与平台自身目录。
func BackupDir(p string) bool {
	if !Mount(p) || p == "/" || p == "/var" || p == "/var/lib" || p == "/opt" || p == "/root" || p == "/home" {
		return false
	}
	for _, forbidden := range []string{"/etc", "/bin", "/sbin", "/usr", "/boot", "/proc", "/sys", "/dev", "/run", "/root/.ssh", "/var/lib/postgresql", "/var/lib/docker", "/var/lib/openxdr", "/var/log/audit"} {
		if p == forbidden || strings.HasPrefix(p, forbidden+"/") || strings.HasPrefix(forbidden, p+"/") {
			return false
		}
	}
	first := strings.Split(strings.TrimPrefix(p, "/"), "/")[0]
	if strings.HasPrefix(first, "lib") || strings.HasPrefix(p, "/opt/openxdr") {
		return false
	}
	if strings.HasPrefix(p, "/home/") && strings.Contains(p, "/.ssh") {
		return false
	}
	return true
}

// BackupFile 校验单个待压缩备份文件：必须位于已授权备份目录下、规范绝对路径、未压缩。
func BackupFile(dir, file string) bool {
	if !BackupDir(dir) || !Mount(file) || !strings.HasPrefix(file, dir+"/") {
		return false
	}
	lower := strings.ToLower(file)
	for _, suf := range compressedSuffixes {
		if strings.HasSuffix(lower, suf) {
			return false
		}
	}
	return true
}

// AnonVolumeID 仅接受 Docker 自动生成的 64 位十六进制匿名卷 ID，绝不匹配具名卷。
func AnonVolumeID(id string) bool {
	return anonVolumeID.MatchString(id)
}

// FormatDockerPrune7d 生成常设规矩 Docker 清理封闭命令。
// 注意 docker image prune --filter until=168h 按镜像创建时间过滤（Docker 不记录最后使用时间），
// 删除的是 7 天前创建且当前没有任何容器（含已停止）引用的镜像；匿名卷列表须由服务端预探针核实 dangling、匿名标签与创建超过 168h。
func FormatDockerPrune7d(anonVolumes []string) (string, bool) {
	if len(anonVolumes) > 32 {
		return "", false
	}
	base := "docker image prune -a --filter until=168h -f && docker builder prune --filter until=168h -f"
	if len(anonVolumes) == 0 {
		return base, true
	}
	ids := slices.Clone(anonVolumes)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	for _, id := range ids {
		if !AnonVolumeID(id) {
			return "", false
		}
	}
	return base + " && docker volume rm -f -- " + strings.Join(ids, " "), true
}

// FormatPkgJournalClean 生成常设规矩「包管理缓存、过大的 journal」的封闭命令。
func FormatPkgJournalClean() string {
	return "if command -v apt-get >/dev/null 2>&1; then apt-get clean; fi && journalctl --vacuum-size=500M"
}

// FormatBackupCompress 为一组已核实的旧备份文件生成无损压缩命令与回退命令：
// 先保留原文件压缩，若压缩失败立即清掉残缺 .gz 并保留原文件；仅在 gzip -t 完整性校验通过且同步时间戳后才移除未压缩原件。
func FormatBackupCompress(dir string, files []string) (cmd string, rollback string, ok bool) {
	if !BackupDir(dir) || len(files) == 0 || len(files) > 20 {
		return "", "", false
	}
	clean := slices.Clone(files)
	slices.Sort(clean)
	clean = slices.Compact(clean)
	steps := make([]string, 0, len(clean))
	undos := make([]string, 0, len(clean))
	for _, f := range clean {
		if !BackupFile(dir, f) {
			return "", "", false
		}
		gz := f + ".gz"
		step := fmt.Sprintf("[ ! -e %s ] && { gzip -9 -k -- %s || { rm -f -- %s; exit 1; }; } && gzip -t -- %s && touch -r %s -- %s && rm -f -- %s", gz, f, gz, gz, f, gz, f)
		steps = append(steps, step)
		undos = append(undos, "gzip -d -- "+gz)
	}
	return strings.Join(steps, " &&\n"), strings.Join(undos, " &&\n"), true
}

// IsStandingDiskAction 判断命令是否为常设规矩使用的封闭磁盘回收/压缩动作，并校验目录型命令与备份文件落在规矩配置的 allowedPaths 内。
func IsStandingDiskAction(cmd string, allowedPaths []string) bool {
	if dir, ok := Parse(cmd); ok {
		return dir == "" || slices.Contains(allowedPaths, dir)
	}
	if cmd == FormatPkgJournalClean() {
		return true
	}
	const prefix = "docker image prune -a --filter until=168h -f && docker builder prune --filter until=168h -f"
	if cmd == prefix {
		return true
	}
	if rest, ok := strings.CutPrefix(cmd, prefix+" && docker volume rm -f -- "); ok {
		parts := strings.Split(rest, " ")
		if len(parts) == 0 || len(parts) > 32 {
			return false
		}
		for _, p := range parts {
			if !AnonVolumeID(p) {
				return false
			}
		}
		return true
	}
	return isBackupCompressCmd(cmd, allowedPaths)
}

var backupStepRe = regexp.MustCompile(`^\[ ! -e (/[a-zA-Z0-9_./-]+\.gz) \] && \{ gzip -9 -k -- (/[a-zA-Z0-9_./-]+) \|\| \{ rm -f -- (/[a-zA-Z0-9_./-]+\.gz); exit 1; \}; \} && gzip -t -- (/[a-zA-Z0-9_./-]+\.gz) && touch -r (/[a-zA-Z0-9_./-]+) -- (/[a-zA-Z0-9_./-]+\.gz) && rm -f -- (/[a-zA-Z0-9_./-]+)$`)

func isBackupCompressCmd(cmd string, allowedPaths []string) bool {
	if len(allowedPaths) == 0 {
		return false
	}
	steps := strings.Split(cmd, " &&\n")
	if len(steps) == 0 || len(steps) > 20 {
		return false
	}
	for _, step := range steps {
		m := backupStepRe.FindStringSubmatch(step)
		if len(m) != 8 {
			return false
		}
		f, gz := m[2], m[1]
		if gz != f+".gz" || m[3] != gz || m[4] != gz || m[5] != f || m[6] != gz || m[7] != f {
			return false
		}
		if !BackupDir(path.Dir(f)) {
			return false
		}
		inAllowed := false
		for _, allowed := range allowedPaths {
			if BackupFile(allowed, f) {
				inAllowed = true
				break
			}
		}
		if !inAllowed {
			return false
		}
	}
	return true
}

// Parse 返回精确删除目录；空目录表示固定缓存/日志回收命令之一。
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
