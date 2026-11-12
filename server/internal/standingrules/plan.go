package standingrules

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/repaircmd"
	"openxdr/server/internal/repairpolicy"
)

// ActionPlan 表示经只读预探针核实后的精确动作方案。
type ActionPlan struct {
	Applicable bool
	Unit       string // 服务单元名或 repairpolicy.ReclaimDisk（仅 auto 可用的模板填充）
	Mount      string // 磁盘类动作对应的 df -P 挂载点
	Summary    string
	Command    string
	Rollback   string
}

var serviceTokenRe = regexp.MustCompile(`\b([a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}\.service)\b`)

// ProbeSpec 返回给定常设规矩在命中待办后需先执行的只读预探针命令。返回空字符串表示无需主机探针（如 human 档）。
func ProbeSpec(r *ent.StandingRule, f *ent.Finding) (string, error) {
	switch r.ActionTemplate {
	case TplStaleConnArchive:
		return "", nil
	case TplDockerUnused7d:
		return `if command -v docker >/dev/null 2>&1; then
docker images --format 'IMG|{{.Repository}}:{{.Tag}}|{{.ID}}|{{.CreatedAt}}' 2>/dev/null
docker ps -a --format 'CTR|{{.Image}}' 2>/dev/null
docker volume ls -q -f dangling=true -f label=com.docker.volume.anonymous 2>/dev/null | head -n 32 | while read -r v; do [ -n "$v" ] && docker volume inspect -f 'VOL|{{.Name}}|{{.CreatedAt}}' "$v" 2>/dev/null; done
docker system df --format 'DF|{{.Type}}|{{.Reclaimable}}' 2>/dev/null
fi`, nil
	case TplPkgJournalClean:
		return `du -sk /var/cache/apt/archives 2>/dev/null | awk '{print "APT_KB|" $1}'; journalctl --disk-usage 2>/dev/null`, nil
	case TplOldBackupCompress:
		paths := paramStringSlice(r.ActionParams, "paths")
		if len(paths) == 0 {
			paths = []string{"/var/backups"}
		}
		for _, p := range paths {
			if !repaircmd.BackupDir(p) {
				return "", fmt.Errorf("不安全的备份目录 %s", p)
			}
		}
		days := paramInt(r.ActionParams, "min_age_days", 7)
		if days < 1 || days > 3650 {
			return "", errors.New("无效的备份保留天数")
		}
		return fmt.Sprintf("find -- %s -xdev -maxdepth 3 -type f -mtime +%d ! -name '*.gz' ! -name '*.tgz' ! -name '*.bz2' ! -name '*.tbz2' ! -name '*.xz' ! -name '*.txz' ! -name '*.zst' ! -name '*.tzst' ! -name '*.zip' ! -name '*.7z' ! -name '*.lz4' ! -name '*.rar' -print 2>/dev/null | head -n 20", strings.Join(paths, " "), days), nil
	case TplLowMemAddSwap:
		return `awk '/^MemTotal:/ {print "MEM_KB|" $2} /^SwapTotal:/ {print "SWAP_KB|" $2}' /proc/meminfo; df -Pk / | awk 'NR==2 {print "ROOT_AVAIL_KB|" $4}'; if [ -e /swapfile ]; then echo "SWAPFILE_EXISTS|1"; fi`, nil
	case TplExpiredNeverLogin:
		return `today=$(( $(date +%s) / 86400 ))
awk -F: '$3>=1000 && $3<65534 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1}' /etc/passwd | while read -r u; do
  exp=$(awk -F: -v u="$u" '$1==u && $2 !~ /^[!*]/ && $8 != "" && $8+0 > 0 {print $8}' /etc/shadow 2>/dev/null)
  if [ -n "$exp" ] && [ "$exp" -lt "$today" ]; then
    if lastlog -u "$u" 2>/dev/null | grep -qiE 'Never logged in|从未登录'; then
      echo "EXPIRED_USER|$u"
    fi
  fi
done`, nil
	case TplSystemdCrashLoop:
		unit := pickServiceFromFinding(r, f)
		if unit == "" {
			return "", errors.New("待办中未找到允许操作的非核心 .service 名称")
		}
		return "systemctl show --property=Id,ActiveState,SubState,NRestarts,UnitFileState -- " + unit, nil
	case TplMgmtPortRestrict:
		return "ss -lntpH 2>/dev/null", nil
	case TplRestartFailedService:
		unit := pickConfiguredUnit(r, f)
		if unit == "" {
			return "", errors.New("待办未命中规矩授权列表中的具体 .service")
		}
		return repairpolicy.ProbeCommand(unit), nil
	case TplReclaimDisk:
		paths := paramStringSlice(r.ActionParams, "paths")
		days := paramInt(r.ActionParams, "min_age_days", 7)
		var valid []string
		for _, p := range paths {
			if repaircmd.Path(p) {
				valid = append(valid, p)
			}
		}
		if len(valid) == 0 || days < 7 || days > 3650 {
			return "", errors.New("目录清理规矩缺少有效目录或保留天数")
		}
		checks := make([]string, 0, len(valid))
		for _, p := range valid {
			checks = append(checks, fmt.Sprintf(`if [ -n "$(find -- %s -xdev -type f -mtime +%d -print -quit 2>/dev/null)" ]; then echo "AGED_DIR|%s"; fi`, p, days, p))
		}
		return strings.Join(checks, "\n"), nil
	default:
		return "", errors.New("未知规矩动作模板")
	}
}

// BuildPlan 根据只读预探针输出构造封闭命令与回退方式。
func BuildPlan(r *ent.StandingRule, f *ent.Finding, probeOut string, now time.Time) (ActionPlan, error) {
	mount := paramString(r.ActionParams, "mount", "/")
	if !repaircmd.Mount(mount) {
		mount = "/"
	}
	switch r.ActionTemplate {
	case TplDockerUnused7d:
		return buildDockerPlan(mount, probeOut, now)
	case TplPkgJournalClean:
		return buildPkgJournalPlan(mount, probeOut)
	case TplOldBackupCompress:
		return buildBackupCompressPlan(r, mount, probeOut)
	case TplLowMemAddSwap:
		return buildSwapPlan(r, probeOut)
	case TplExpiredNeverLogin:
		return buildExpiredAccountPlan(f, probeOut)
	case TplSystemdCrashLoop:
		return buildCrashLoopPlan(r, f, probeOut)
	case TplMgmtPortRestrict:
		return buildMgmtPortPlan(r, f, probeOut)
	case TplRestartFailedService:
		return buildRestartServicePlan(r, f, probeOut)
	case TplReclaimDisk:
		return buildReclaimDiskPlan(r, mount, probeOut)
	default:
		return ActionPlan{}, errors.New("不支持构建动作方案的模板")
	}
}

func buildDockerPlan(mount, out string, now time.Time) (ActionPlan, error) {
	cutoff := now.Add(-168 * time.Hour)
	usedImages := map[string]bool{}
	type imgRow struct{ tag, id string }
	var oldImages []imgRow
	var oldVols []string
	hasBuildCache := false

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		parts := strings.Split(line, "|")
		switch {
		case len(parts) == 2 && parts[0] == "CTR":
			usedImages[strings.TrimSpace(parts[1])] = true
		case len(parts) == 4 && parts[0] == "IMG":
			if ts, ok := parseDockerTime(parts[3]); ok && !ts.After(cutoff) {
				oldImages = append(oldImages, imgRow{tag: strings.TrimSpace(parts[1]), id: strings.TrimSpace(parts[2])})
			}
		case len(parts) == 3 && parts[0] == "VOL":
			name := strings.TrimSpace(parts[1])
			if ts, ok := parseDockerTime(parts[2]); ok && !ts.After(cutoff) && repaircmd.AnonVolumeID(name) {
				oldVols = append(oldVols, name)
			}
		case len(parts) == 3 && parts[0] == "DF":
			typ, rec := strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
			if strings.EqualFold(typ, "Build Cache") && rec != "" && !strings.HasPrefix(rec, "0B") {
				hasBuildCache = true
			}
		}
	}

	var pullCmds []string
	reclaimableImages := 0
	for _, img := range oldImages {
		if usedImages[img.tag] || usedImages[img.id] {
			continue
		}
		reclaimableImages++
		if img.tag != "" && !strings.Contains(img.tag, "<none>") && safeDockerRef.MatchString(img.tag) {
			pullCmds = append(pullCmds, "docker pull "+img.tag)
		}
	}
	slices.Sort(pullCmds)
	pullCmds = slices.Compact(pullCmds)

	if reclaimableImages == 0 && len(oldVols) == 0 && !hasBuildCache {
		return ActionPlan{Applicable: false, Summary: "未发现超过 7 天未使用的 Docker 镜像、构建缓存或悬空匿名卷"}, nil
	}
	cmd, ok := repaircmd.FormatDockerPrune7d(oldVols)
	if !ok {
		return ActionPlan{}, errors.New("匿名卷标识校验未通过")
	}
	rollback := "本次仅清理无标签层、构建缓存或超过 7 天的悬空 64 位匿名卷，具名镜像与具名卷未改动"
	if len(pullCmds) > 0 {
		rollback = "如需恢复被清理的旧镜像可执行：\n" + strings.Join(pullCmds, "\n")
	}
	return ActionPlan{
		Applicable: true,
		Unit:       repairpolicy.ReclaimDisk,
		Mount:      mount,
		Summary:    fmt.Sprintf("待清理 >7d 镜像 %d 个、悬空匿名卷 %d 个（构建缓存可回收：%v）", reclaimableImages, len(oldVols), hasBuildCache),
		Command:    cmd,
		Rollback:   rollback,
	}, nil
}

var safeDockerRef = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,199}$`)

func parseDockerTime(raw string) (time.Time, bool) {
	s := strings.TrimSpace(raw)
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05 -0700",
		"2006-01-02T15:04:05Z07:00",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	// Docker 部分版本格式形如 "2026-10-01 12:00:00 +0800 CST"，去掉尾部未知时区缩写兜底解析
	if fields := strings.Fields(s); len(fields) >= 3 {
		if t, err := time.Parse("2006-01-02 15:04:05 -0700", strings.Join(fields[:3], " ")); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

var journalSizeRe = regexp.MustCompile(`(?i)take up\s+([0-9]+(?:\.[0-9]+)?)\s*([KMGT])`)

func buildPkgJournalPlan(mount, out string) (ActionPlan, error) {
	var aptKB uint64
	journalOver500M := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if rest, ok := strings.CutPrefix(line, "APT_KB|"); ok {
			aptKB, _ = strconv.ParseUint(strings.TrimSpace(rest), 10, 64)
		}
		if m := journalSizeRe.FindStringSubmatch(line); len(m) == 3 {
			val, _ := strconv.ParseFloat(m[1], 64)
			switch strings.ToUpper(m[2]) {
			case "G", "T":
				journalOver500M = val > 0.5 || strings.ToUpper(m[2]) == "T" || val >= 1
				if strings.ToUpper(m[2]) == "G" {
					journalOver500M = val*1024 > 500
				}
			case "M":
				journalOver500M = val > 500
			}
		}
	}
	if aptKB <= 4096 && !journalOver500M {
		return ActionPlan{Applicable: false, Summary: "apt 缓存不超过 4MB 且 journal 未超过 500MB，无需清理"}, nil
	}
	return ActionPlan{
		Applicable: true,
		Unit:       repairpolicy.ReclaimDisk,
		Mount:      mount,
		Summary:    fmt.Sprintf("apt 缓存 %d KB，journal 超 500MB=%v", aptKB, journalOver500M),
		Command:    repaircmd.FormatPkgJournalClean(),
		Rollback:   "apt-get update 可重新拉取索引；journalctl --vacuum-size=500M 仅裁剪超额旧归档并保留最近 500MB",
	}, nil
}

func buildBackupCompressPlan(r *ent.StandingRule, mount, out string) (ActionPlan, error) {
	dirs := paramStringSlice(r.ActionParams, "paths")
	if len(dirs) == 0 {
		dirs = []string{"/var/backups"}
	}
	var allSteps, allUndos, matchedFiles []string
	byDir := map[string][]string{}
	for _, raw := range strings.Split(out, "\n") {
		f := strings.TrimSpace(raw)
		if f == "" {
			continue
		}
		for _, d := range dirs {
			if repaircmd.BackupFile(d, f) {
				pDir := path.Dir(f)
				if repaircmd.BackupDir(pDir) {
					byDir[pDir] = append(byDir[pDir], f)
					matchedFiles = append(matchedFiles, f)
				}
				break
			}
		}
	}
	if len(matchedFiles) == 0 {
		return ActionPlan{Applicable: false, Summary: "备份目录下无超过保留天数的未压缩备份文件"}, nil
	}
	var sortedDirs []string
	for d := range byDir {
		sortedDirs = append(sortedDirs, d)
	}
	slices.Sort(sortedDirs)
	total := 0
	for _, d := range sortedDirs {
		files := byDir[d]
		if total+len(files) > 20 {
			files = files[:20-total]
		}
		if len(files) == 0 {
			break
		}
		cmd, undo, ok := repaircmd.FormatBackupCompress(d, files)
		if !ok {
			return ActionPlan{}, errors.New("备份文件路径未通过无损压缩安全校验")
		}
		allSteps = append(allSteps, cmd)
		allUndos = append(allUndos, undo)
		total += len(files)
	}
	fullCmd := strings.Join(allSteps, " &&\n")
	if !repaircmd.IsStandingDiskAction(fullCmd) {
		return ActionPlan{}, errors.New("生成的备份无损压缩命令未通过封闭语法复核")
	}
	return ActionPlan{
		Applicable: true,
		Unit:       repairpolicy.ReclaimDisk,
		Mount:      mount,
		Summary:    fmt.Sprintf("无损压缩 %d 个旧备份文件（gzip -9 -k + gzip -t 校验通过后移除未压缩原件）", total),
		Command:    fullCmd,
		Rollback:   strings.Join(allUndos, " &&\n"),
	}, nil
}

func buildSwapPlan(r *ent.StandingRule, out string) (ActionPlan, error) {
	swapGB := paramInt(r.ActionParams, "swap_size_gb", 2)
	if swapGB < 1 || swapGB > 8 {
		swapGB = 2
	}
	var memKB, swapKB, availKB uint64
	hasMem, exists := false, false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "MEM_KB|"):
			memKB, _ = strconv.ParseUint(strings.TrimPrefix(line, "MEM_KB|"), 10, 64)
			hasMem = true
		case strings.HasPrefix(line, "SWAP_KB|"):
			swapKB, _ = strconv.ParseUint(strings.TrimPrefix(line, "SWAP_KB|"), 10, 64)
		case strings.HasPrefix(line, "ROOT_AVAIL_KB|"):
			availKB, _ = strconv.ParseUint(strings.TrimPrefix(line, "ROOT_AVAIL_KB|"), 10, 64)
		case line == "SWAPFILE_EXISTS|1":
			exists = true
		}
	}
	if !hasMem || memKB == 0 || memKB > 4*1024*1024 || swapKB > 0 || exists {
		return ActionPlan{Applicable: false, Summary: "主机内存高于 4GB、已有活动 swap 或已存在 /swapfile"}, nil
	}
	minAvailKB := uint64(swapGB+2) * 1024 * 1024
	if availKB < minAvailKB {
		return ActionPlan{Applicable: false, Summary: fmt.Sprintf("根分区可用空间不足 %dGB，跳过创建 /swapfile", swapGB+2)}, nil
	}
	cmd := fmt.Sprintf(`[ ! -e /swapfile ] && [ "$(swapon --noheadings | wc -l)" -eq 0 ] && fallocate -l %dG /swapfile && chmod 0600 /swapfile && mkswap /swapfile && swapon /swapfile && { grep -q '^/swapfile[[:space:]]' /etc/fstab || printf '/swapfile none swap sw 0 0\n' >> /etc/fstab; }`, swapGB)
	return ActionPlan{
		Applicable: true,
		Summary:    fmt.Sprintf("物理内存 %d MB 且无 swap，提议创建 %dGB /swapfile 并写入 /etc/fstab", memKB/1024, swapGB),
		Command:    cmd,
		Rollback:   `swapoff /swapfile && sed -i '\|/swapfile[[:space:]]|d' /etc/fstab && rm -f -- /swapfile`,
	}, nil
}

var protectedUsers = map[string]bool{
	"root": true, "ubuntu": true, "debian": true, "centos": true, "rocky": true,
	"almalinux": true, "fedora": true, "ec2-user": true, "admin": true, "openxdr": true,
}

func buildExpiredAccountPlan(f *ent.Finding, out string) (ActionPlan, error) {
	var users []string
	text := ""
	if f != nil {
		text = strings.ToLower(f.Key + " " + f.Title + " " + f.Detail)
	}
	var mentioned []string
	for _, raw := range strings.Split(out, "\n") {
		u, ok := strings.CutPrefix(strings.TrimSpace(raw), "EXPIRED_USER|")
		if !ok {
			continue
		}
		u = strings.TrimSpace(u)
		if !linuxUserRe.MatchString(u) || protectedUsers[u] {
			continue
		}
		users = append(users, u)
		if text != "" && strings.Contains(text, strings.ToLower(u)) {
			mentioned = append(mentioned, u)
		}
	}
	if len(mentioned) > 0 {
		users = mentioned
	}
	slices.Sort(users)
	users = slices.Compact(users)
	if len(users) == 0 {
		return ActionPlan{Applicable: false, Summary: "未核实到密码已过期且从未登录的普通本地账号"}, nil
	}
	if len(users) > 5 {
		users = users[:5]
	}
	locks := make([]string, 0, len(users))
	unlocks := make([]string, 0, len(users))
	for _, u := range users {
		locks = append(locks, "usermod -L -- "+u)
		unlocks = append(unlocks, "usermod -U -- "+u)
	}
	return ActionPlan{
		Applicable: true,
		Summary:    "提议锁定密码过期且从未登录的本地账号：" + strings.Join(users, ", "),
		Command:    strings.Join(locks, " && "),
		Rollback:   strings.Join(unlocks, " && "),
	}, nil
}

func buildCrashLoopPlan(r *ent.StandingRule, f *ent.Finding, out string) (ActionPlan, error) {
	unit := pickServiceFromFinding(r, f)
	if unit == "" {
		return ActionPlan{Applicable: false, Summary: "待办未指明允许操作的非核心 systemd 服务"}, nil
	}
	minRestarts := paramInt(r.ActionParams, "min_restarts", 5)
	fields := parseKeyValueLines(out)
	restarts, _ := strconv.Atoi(fields["NRestarts"])
	active := fields["ActiveState"]
	if fields["Id"] != unit || restarts < minRestarts || (active != "activating" && active != "failed") {
		return ActionPlan{Applicable: false, Summary: fmt.Sprintf("服务 %s 当前状态 %s（NRestarts=%d），未达崩溃循环阈值 %d", unit, active, restarts, minRestarts)}, nil
	}
	return ActionPlan{
		Applicable: true,
		Summary:    fmt.Sprintf("非核心服务 %s 崩溃循环（NRestarts=%d，状态=%s），提议停用并保留配置", unit, restarts, active),
		Command:    "systemctl disable --now -- " + unit,
		Rollback:   "systemctl enable --now -- " + unit,
	}, nil
}

func buildMgmtPortPlan(r *ent.StandingRule, f *ent.Finding, out string) (ActionPlan, error) {
	ports := paramIntSlice(r.ActionParams, "ports")
	if len(ports) == 0 {
		ports = []int{3389, 5900, 8006, 9090}
	}
	rawCIDRs := paramStringSlice(r.ActionParams, "allowed_cidrs")
	var cidrs []string
	for _, c := range rawCIDRs {
		if norm, err := parseIPv4PrefixOrAddr(c); err == nil {
			cidrs = append(cidrs, norm)
		}
	}
	if len(cidrs) == 0 {
		return ActionPlan{Applicable: false, Summary: "尚未配置允许访问的管理网段（allowed_cidrs），不生成封堵提议"}, nil
	}
	listeningWildcard := map[int]bool{}
	for _, raw := range strings.Split(out, "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 4 {
			continue
		}
		local := fields[3]
		for _, p := range ports {
			suf := ":" + strconv.Itoa(p)
			if strings.HasSuffix(local, suf) && (strings.HasPrefix(local, "0.0.0.0:") || strings.HasPrefix(local, "*:") || strings.HasPrefix(local, "[::]:")) {
				listeningWildcard[p] = true
			}
		}
	}
	var targetPorts []int
	fText := ""
	if f != nil {
		fText = f.Key + " " + f.Title + " " + f.Detail
	}
	for _, p := range ports {
		if listeningWildcard[p] && (fText == "" || strings.Contains(fText, strconv.Itoa(p)) || len(listeningWildcard) == 1) {
			targetPorts = append(targetPorts, p)
		}
	}
	if len(targetPorts) == 0 {
		for _, p := range ports {
			if listeningWildcard[p] {
				targetPorts = append(targetPorts, p)
			}
		}
	}
	slices.Sort(targetPorts)
	targetPorts = slices.Compact(targetPorts)
	if len(targetPorts) == 0 {
		return ActionPlan{Applicable: false, Summary: "未检测到配置清单中的管理端口对 0.0.0.0/:: 全开"}, nil
	}
	var cmds, undos []string
	var portStrs []string
	for _, p := range targetPorts {
		chain := fmt.Sprintf("OPENXDR_MGMT_%d", p)
		portStrs = append(portStrs, strconv.Itoa(p))
		lines := []string{
			fmt.Sprintf("(iptables -N %s 2>/dev/null || iptables -F %s)", chain, chain),
			fmt.Sprintf("iptables -A %s -i lo -j RETURN", chain),
			fmt.Sprintf("iptables -A %s -i docker0 -j RETURN", chain),
			fmt.Sprintf("iptables -A %s -i br-+ -j RETURN", chain),
			fmt.Sprintf("iptables -A %s -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN", chain),
		}
		for _, cidr := range cidrs {
			lines = append(lines, fmt.Sprintf("iptables -A %s -s %s -j RETURN", chain, cidr))
		}
		lines = append(lines,
			fmt.Sprintf("iptables -A %s -j DROP", chain),
			fmt.Sprintf("(iptables -C INPUT -p tcp --dport %d -j %s 2>/dev/null || iptables -I INPUT 1 -p tcp --dport %d -j %s)", p, chain, p, chain),
		)
		cmds = append(cmds, strings.Join(lines, " && "))
		undos = append(undos, fmt.Sprintf("iptables -D INPUT -p tcp --dport %d -j %s && iptables -F %s && iptables -X %s", p, chain, chain, chain))
	}
	return ActionPlan{
		Applicable: true,
		Summary:    fmt.Sprintf("管理端口 %s 对全网段开放，提议仅允许网段 %s 访问", strings.Join(portStrs, ","), strings.Join(cidrs, ",")),
		Command:    strings.Join(cmds, " && "),
		Rollback:   strings.Join(undos, " && "),
	}, nil
}

func buildRestartServicePlan(r *ent.StandingRule, f *ent.Finding, out string) (ActionPlan, error) {
	unit := pickConfiguredUnit(r, f)
	if unit == "" {
		return ActionPlan{Applicable: false, Summary: "待办未匹配已授权服务"}, nil
	}
	fields := parseKeyValueLines(out)
	if fields["Id"] != unit || fields["ActiveState"] != "failed" || fields["UnitFileState"] != "enabled" {
		return ActionPlan{Applicable: false, Summary: fmt.Sprintf("服务 %s 当前状态为 %s/%s，非 failed+enabled", unit, fields["ActiveState"], fields["UnitFileState"])}, nil
	}
	return ActionPlan{
		Applicable: true,
		Unit:       unit,
		Summary:    fmt.Sprintf("授权非核心服务 %s 处于 failed 且 enabled，执行重启", unit),
		Command:    "systemctl restart -- " + unit,
		Rollback:   "systemctl stop -- " + unit,
	}, nil
}

func buildReclaimDiskPlan(r *ent.StandingRule, mount, out string) (ActionPlan, error) {
	days := paramInt(r.ActionParams, "min_age_days", 7)
	allowed := paramStringSlice(r.ActionParams, "paths")
	var target string
	for _, raw := range strings.Split(out, "\n") {
		if dir, ok := strings.CutPrefix(strings.TrimSpace(raw), "AGED_DIR|"); ok {
			dir = strings.TrimSpace(dir)
			if slices.Contains(allowed, dir) && repaircmd.Path(dir) {
				target = dir
				break
			}
		}
	}
	if target == "" {
		return ActionPlan{Applicable: false, Summary: "已授权目录下没有超过保留天数的待清理文件"}, nil
	}
	cmd := fmt.Sprintf("find -- %s -xdev -type f -mtime +%d -delete", target, days)
	if _, ok := repaircmd.Parse(cmd); !ok {
		return ActionPlan{}, errors.New("目录清理命令未通过封闭模板校验")
	}
	return ActionPlan{
		Applicable: true,
		Unit:       repairpolicy.ReclaimDisk,
		Mount:      mount,
		Summary:    fmt.Sprintf("清理授权目录 %s 下超过 %d 天的过期文件", target, days),
		Command:    cmd,
		Rollback:   fmt.Sprintf("仅清理已授权目录 %s 下 mtime > +%d 天的过期文件（执行前后经 df -P 独立核验空间释放）", target, days),
	}, nil
}

func pickServiceFromFinding(r *ent.StandingRule, f *ent.Finding) string {
	for _, u := range paramStringSlice(r.ActionParams, "units") {
		if repairpolicy.ValidServiceUnit(u) {
			if f == nil || strings.Contains(strings.ToLower(f.Key+" "+f.Title+" "+f.Detail), strings.ToLower(strings.TrimSuffix(u, ".service"))) {
				return u
			}
		}
	}
	if f == nil {
		return ""
	}
	for _, m := range serviceTokenRe.FindAllStringSubmatch(f.Key+" "+f.Title+" "+f.Detail, 10) {
		if len(m) == 2 && repairpolicy.ValidServiceUnit(m[1]) {
			return m[1]
		}
	}
	return ""
}

func pickConfiguredUnit(r *ent.StandingRule, f *ent.Finding) string {
	units := paramStringSlice(r.ActionParams, "units")
	if f == nil {
		return ""
	}
	lower := strings.ToLower(f.Key + " " + f.Title + " " + f.Detail)
	for _, u := range units {
		if !repairpolicy.ValidServiceUnit(u) {
			continue
		}
		base := strings.ToLower(strings.TrimSuffix(u, ".service"))
		if base != "" && strings.Contains(lower, base) {
			return u
		}
	}
	return ""
}

func parseKeyValueLines(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			res[k] = v
		}
	}
	return res
}
