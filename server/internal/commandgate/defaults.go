package commandgate

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/commandpolicy"
	"openxdr/server/ent/predicate"
)

// cmdPos 命令位置：开头、shell 分隔符或引号之后，或 sudo/nohup/xargs 等包装之后，允许绝对路径。
// 只给与只读命令参数撞名的程序用（last reboot、getent passwd 不该挂起），其余用 \b 宽匹配。
const cmdPos = `(?:^|[;&|(\x60'"\n]|\b(?:sudo|doas|nohup|exec|xargs)\s)\s*(?:-\S+\s+)*(?:(?:/usr)?(?:/local)?/s?bin/)?`

// legacyCmdPos 旧版命令位置前缀：允许任意路径，`awk ... "$3==0" /etc/passwd` 这种读文件的命令也会被当成在执行 passwd。
// 只留着给 UpgradeDefaults 认出库里还是旧写法的默认条目
const legacyCmdPos = `(?:^|[;&|(\x60'"\n]|\b(?:sudo|doas|nohup|exec|xargs)\s)\s*(?:-\S+\s+)*(?:[^\s;&|'"]*/)?`

// DefaultAIDeny 新建组自带的 AI 高风险命令名单：在整条命令里非锚定搜索，任一段命中即挂起等组管理员批准，
// 其余命令直接执行。只覆盖破坏性、改配置、停服务与读密钥的操作，只读巡检不受影响。
// Linux 经 sh -c、Windows 经 PowerShell 执行，Windows 的条目不区分大小写。
var DefaultAIDeny = append([]string{
	// Linux：删除、格式化与写盘
	`\brm\s+(?:[^\s;&|]+\s+)*(?:-[a-zA-Z]*[rRf]|--recursive|--force)`,
	`\b(?:mkfs(?:\.\w+)?|mke2fs|wipefs|fdisk|sfdisk|parted|sgdisk)\b`,
	`\bdd\s(?:[^;&|]*\s)?of=`,
	// 关机重启与停服务
	cmdPos + `(?:shutdown|reboot|poweroff|halt)\b`,
	cmdPos + `(?:tel)?init\s+[06]\b`,
	`\bsystemctl\s+(?:-\S+\s+)*(?:stop|disable|mask|kill|isolate|reboot|poweroff|halt|kexec)\b`,
	`\bservice\s+\S+\s+stop\b`,
	`\b(?:kill|pkill|killall)\b`,
	// 防火墙
	`\bip6?tables(?:-legacy|-nft)?\s+(?:[^;&|]*\s)?(?:-[ADIRFPXNEZ]\b|--(?:append|delete|insert|replace|flush|policy|new-chain|delete-chain|rename-chain|zero)\b)`,
	`\bip6?tables(?:-legacy|-nft)?-restore\b`,
	`\bnft\s+(?:-[a-zA-Z]+\s+)*(?:add|delete|destroy|flush|insert|replace|create|reset|-f)\b`,
	`\bufw\s+(?:--\S+\s+)*(?:enable|disable|reset|reload|allow|deny|reject|limit|delete|insert|prepend|route|default)\b`,
	`\bfirewall-cmd\s+(?:[^;&|]*\s)?--(?:add|remove|set|change|new|delete|reload|complete-reload|panic-on|runtime-to-permanent|reset)`,
	// 账户
	cmdPos + `(?:useradd|userdel|usermod|adduser|deluser|groupadd|groupdel|groupmod|gpasswd|passwd|chpasswd|visudo)\b`,
	// 卸载软件包
	`\b(?:apt|apt-get|aptitude|yum|dnf|zypper)\s+(?:-\S+\s+)*(?:remove|purge|autoremove|erase|rm)\b`,
	`\bpacman\s+(?:-\S+\s+)*(?:-R[a-zA-Z]*|--remove)\b`,
	`\bdpkg\s+(?:-\S+\s+)*(?:-[rP]|--remove|--purge)\b`,
	`\brpm\s+(?:-\S+\s+)*(?:-e[a-zA-Z]*|--erase)\b`,
	// 存储与虚拟化
	`\bz(?:fs|pool)\s+(?:-\S+\s+)*(?:destroy|rollback)\b`,
	`\b(?:qm|pct)\s+(?:stop|destroy|shutdown|reboot|reset|rollback)\b`,
	`\bpvecm\s+(?:add|delnode|expected|create|updatecerts)\b`,
	// 计划任务、远程脚本、写系统目录
	`\bcrontab\s+(?:[^;&|]*\s)?-[a-zA-Z]*r[a-zA-Z]*\b`,
	`\b(?:curl|wget)\b[^;&]*\|\s*(?:sudo\s+)?(?:[^\s;&|]*/)?(?:ba|da|z|k)?sh\b`,
	`\b(?:ba|da|z|k)?sh\s+(?:-\S+\s+)*(?:-c\s+["']?)?(?:\$\(|<\()\s*(?:curl|wget)\b`,
	`>\s*["']?/(?:etc|boot|usr|bin|sbin|lib(?:32|64)?)(?:[/\s"']|$)`,
	`\btee\s+(?:-\S+\s+)*["']?/(?:etc|boot|usr|bin|sbin|lib(?:32|64)?)(?:[/\s"']|$)`,
	// 读密钥：shadow 与 SSH 私钥（.pub 公钥不算）
	`/etc/g?shadow\b`,
	`\bid_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?(?:$|[^\w.]|\.(?:$|[^p]|p(?:$|[^u]|u(?:$|[^b]))))`,
	// Windows（PowerShell）
	`(?i)\b(?:Stop|Restart)-Computer\b`,
	`(?i)\b(?:Remove-Item|ri|rmdir|rd|del|erase)\s+(?:[^;|\n]*\s)?(?:-r\w*|/s)\b`,
	`(?i)\b(?:Format-Volume|Clear-Disk|Remove-Partition)\b`,
	`(?i)\bStop-Service\b`,
	`(?i)\bSet-Service\b[^;|\n]*-StartupType\s+["']?Disabled\b`,
	`(?i)\bDisable-NetAdapter\b`,
	`(?i)\b(?:New|Remove|Disable|Set|Rename)-LocalUser\b`,
	`(?i)\b(?:Add|Remove)-LocalGroupMember\b`,
	`(?i)\b(?:Set|Add)-MpPreference\b`,
	`(?i)\b(?:Stop-Process|taskkill)\b`,
	`(?i)\bnetsh(?:\.exe)?\s+advfirewall\s+(?:firewall\s+)?(?:set|add|delete|reset|import)\b`,
	`(?i)\b(?:New|Set|Remove|Disable|Enable)-NetFirewall\w+`,
}, append(containerDeny, fileDeny...)...)

// containerDeny 容器重建、拉起与删除：compose 编排、docker / podman 的容器与镜像生命周期、写 compose 文件。
// 非锚定搜索，套在 pct exec、docker exec、lxc-attach、sh -c 里照样命中；ps、logs、inspect 这类查看不命中
var containerDeny = []string{
	`\b(?:docker|podman)(?:-compose\s+|\s+(?:[^;&|]*\s)?compose\s+)(?:[^;&|]*\s)?(?:up|down|restart|rm|stop|kill|start|create|run|pull)(?:$|[\s;&|)'"])`,
	`\b(?:docker|podman)\s+(?:-\S+\s+(?:[^-\s;&|]\S*\s+)?)*(?:(?:container|image|system|volume|network)\s+)?(?:run|create|start|pull|rm|rmi|restart|stop|kill|prune)(?:$|[\s;&|)'"])`,
	`(?:>|\btee\s+(?:-\S+\s+)*)\s*["']?[^\s;&|'"<>]*compose[^\s;&|'"<>]*\.ya?ml\b`,
}

// fileDeny 删文件与回收缓存：曾在硬拒绝清单里，改为交 AI 审计员评审；系统目录、数据与备份仍硬拒绝（review.go）
var fileDeny = []string{
	cmdPos + `(?:rm|unlink|shred|truncate)\b`,
	`\bfind\b[^;&|]*\s-delete\b`,
	`\bdocker\s+(?:image|builder|system|container)\s+prune\b`,
	`\bapt(?:-get)?\s+(?:-\S+\s+)*(?:clean|autoclean)\b`,
}

// defaultsAdded 已上线后才加进默认名单的条目，下标 + 1 是默认名单版本号，只许往后追加。
// 老库里已有默认名单的组由 UpgradeDefaults 按版本补上，每个版本只补一次
var defaultsAdded = [][]string{containerDeny, fileDeny}

// defaultsVersionKey settings 表里记已补到第几版默认名单
const defaultsVersionKey = "commandgate.defaults_version"

// SeedDefaults 给组写入默认 AI 高风险命令名单。
func SeedDefaults(ctx context.Context, db *ent.Client, groupID uuid.UUID) error {
	creates := make([]*ent.CommandPolicyCreate, len(DefaultAIDeny))
	for i, pattern := range DefaultAIDeny {
		creates[i] = db.CommandPolicy.Create().SetGroupID(groupID).SetOrigin(commandpolicy.OriginAi).
			SetMode(commandpolicy.ModeDeny).SetPattern(pattern)
	}
	return db.CommandPolicy.CreateBulk(creates...).Exec(ctx)
}

// UpgradeDefaults 把各组里仍是旧版默认写法的条目换成新版：只动与旧默认逐字相同的行，管理员改过的不碰；再跑一次没有可换的。
// 之后按版本补上新加的默认条目
func UpgradeDefaults(ctx context.Context, db *ent.Client) error {
	total := 0
	for _, pattern := range DefaultAIDeny {
		old := strings.Replace(pattern, cmdPos, legacyCmdPos, 1)
		if old == pattern {
			continue
		}
		n, err := db.CommandPolicy.Update().Where(commandpolicy.PatternEQ(old)).SetPattern(pattern).Save(ctx)
		if err != nil {
			return err
		}
		total += n
	}
	if total > 0 {
		slog.Info("默认高风险名单已升级到新写法", "rows", total)
	}
	return addDefaults(ctx, db)
}

// addDefaults 给还留着 AI 高风险名单的组补上库里版本之后新加的默认条目，组里已有同样写法的跳过；
// 把 AI 名单整个清空的组不补。补完记下版本，管理员之后删掉新条目也不会再被补回来
func addDefaults(ctx context.Context, db *ent.Client) error {
	tx, err := db.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	version := 0
	row, err := tx.Setting.Get(ctx, defaultsVersionKey)
	switch {
	case err == nil:
		if err := json.Unmarshal(row.Value, &version); err != nil {
			return fmt.Errorf("默认名单版本无法解析: %w", err)
		}
	case !ent.IsNotFound(err):
		return err
	}
	if version >= len(defaultsAdded) {
		return nil
	}
	aiDeny := []predicate.CommandPolicy{commandpolicy.OriginEQ(commandpolicy.OriginAi), commandpolicy.ModeEQ(commandpolicy.ModeDeny)}
	rows, err := tx.CommandPolicy.Query().Where(aiDeny...).All(ctx)
	if err != nil {
		return err
	}
	have := map[uuid.UUID]map[string]bool{}
	for _, r := range rows {
		if have[r.GroupID] == nil {
			have[r.GroupID] = map[string]bool{}
		}
		have[r.GroupID][r.Pattern] = true
	}
	var creates []*ent.CommandPolicyCreate
	for _, added := range defaultsAdded[version:] {
		for groupID, patterns := range have {
			for _, pattern := range added {
				if !patterns[pattern] {
					creates = append(creates, tx.CommandPolicy.Create().SetGroupID(groupID).SetOrigin(commandpolicy.OriginAi).
						SetMode(commandpolicy.ModeDeny).SetPattern(pattern))
				}
			}
		}
	}
	if len(creates) > 0 {
		if err := tx.CommandPolicy.CreateBulk(creates...).Exec(ctx); err != nil {
			return err
		}
	}
	value, _ := json.Marshal(len(defaultsAdded))
	if row != nil {
		err = tx.Setting.UpdateOneID(defaultsVersionKey).SetValue(value).Exec(ctx)
	} else {
		err = tx.Setting.Create().SetID(defaultsVersionKey).SetValue(value).Exec(ctx)
	}
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	slog.Info("默认高风险名单已补上新条目", "from_version", version, "to_version", len(defaultsAdded), "rows", len(creates), "groups", len(have))
	return nil
}

// MigrateAllowToDeny 把旧版 AI 免审批名单换成默认高风险名单：删掉全部 ai/allow 行，
// 只给本次确实删到行的组补默认名单。幂等：再跑一次没有 allow 行可删，
// 管理员主动清空的黑名单也不会被反复补回来。
func MigrateAllowToDeny(ctx context.Context, db *ent.Client) error {
	tx, err := db.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	aiAllow := []predicate.CommandPolicy{commandpolicy.OriginEQ(commandpolicy.OriginAi), commandpolicy.ModeEQ(commandpolicy.ModeAllow)}
	rows, err := tx.CommandPolicy.Query().Where(aiAllow...).All(ctx)
	if err != nil || len(rows) == 0 {
		return err
	}
	groups := map[uuid.UUID]bool{}
	for _, row := range rows {
		groups[row.GroupID] = true
	}
	if _, err := tx.CommandPolicy.Delete().Where(aiAllow...).Exec(ctx); err != nil {
		return err
	}
	for id := range groups {
		if err := SeedDefaults(ctx, tx.Client(), id); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	slog.Info("AI 免审批名单已迁移为高风险名单：删除旧条目并给这些组补默认名单", "removed", len(rows), "groups", len(groups), "per_group", len(DefaultAIDeny))
	return nil
}
