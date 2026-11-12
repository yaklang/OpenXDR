// Package standingrules 实现自治总控的常设规矩：内置规矩种子、模板参数校验、待办匹配、三档执行与连续出错降级。
package standingrules

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/standingrule"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/repaircmd"
	"openxdr/server/internal/repairpolicy"
)

const (
	TplDockerUnused7d       = "docker_unused_7d"
	TplPkgJournalClean      = "pkg_journal_clean"
	TplLowMemAddSwap        = "low_mem_add_swap"
	TplOldBackupCompress    = "old_backup_compress"
	TplExpiredNeverLogin    = "expired_never_login_account"
	TplSystemdCrashLoop     = "systemd_crash_loop"
	TplStaleConnArchive     = "stale_conn_archive"
	TplMgmtPortRestrict     = "mgmt_port_restrict"
	TplRestartFailedService = repairpolicy.RestartFailedService
	TplReclaimDisk          = repairpolicy.ReclaimDisk

	// MaxConsecutiveFailures 同一 auto 规矩连续执行/校验出错达到该阈值时自动降级为 propose。
	MaxConsecutiveFailures = 2
)

// Template 描述一条固定规矩动作模板的档位边界与默认元数据。
type Template struct {
	Key               string         `json:"key"`
	Name              string         `json:"name"`
	ConditionSummary  string         `json:"conditionSummary"`
	DefaultTier       string         `json:"defaultTier"`
	AllowedTiers      []string       `json:"allowedTiers"`
	DefaultWindow     string         `json:"defaultWindow,omitempty"`
	DefaultCooldown   int            `json:"defaultCooldownMinutes"`
	DefaultParams     map[string]any `json:"defaultParams,omitempty"`
	RollbackHint      string         `json:"rollbackHint"`
	Builtin           bool           `json:"builtin"`
	RequiresHostScope bool           `json:"requiresHostScope,omitempty"`
}

var templates = []Template{
	{
		Key:              TplDockerUnused7d,
		Name:             "docker 未使用超过 7 天的镜像与匿名卷",
		ConditionSummary: "磁盘容量待办命中，且主机存在超过 7 天未使用的 Docker 镜像、构建缓存或悬空匿名卷",
		DefaultTier:      "auto",
		AllowedTiers:     []string{"auto", "propose", "human"},
		DefaultWindow:    "02:00-05:00",
		DefaultCooldown:  360,
		DefaultParams:    map[string]any{"mount": "/"},
		RollbackHint:     "执行前记录被清理的带标签镜像，需要时用 docker pull <repo:tag> 重新拉取；仅清理悬空 64 位匿名卷，不触碰具名卷",
		Builtin:          true,
	},
	{
		Key:              TplPkgJournalClean,
		Name:             "包管理缓存、过大的 journal",
		ConditionSummary: "磁盘容量待办命中，且 apt 包缓存非空或 systemd journal 占用超过 500MB",
		DefaultTier:      "auto",
		AllowedTiers:     []string{"auto", "propose", "human"},
		DefaultWindow:    "",
		DefaultCooldown:  360,
		DefaultParams:    map[string]any{"mount": "/"},
		RollbackHint:     "apt-get update 可重新拉取索引；journalctl --vacuum-size=500M 仅裁剪超额旧归档并保留最近 500MB",
		Builtin:          true,
	},
	{
		Key:              TplLowMemAddSwap,
		Name:             "内存 4G 以下且无 swap 的主机",
		ConditionSummary: "内存或 swap 待办命中，且主机物理内存 ≤ 4GB、当前无启用 swap、根分区可用空间充足",
		DefaultTier:      "propose",
		AllowedTiers:     []string{"propose", "human"},
		DefaultWindow:    "02:00-05:00",
		DefaultCooldown:  1440,
		DefaultParams:    map[string]any{"swap_size_gb": 2},
		RollbackHint:     "swapoff /swapfile && sed -i '\\|^/swapfile[[:space:]]|d' /etc/fstab && rm -f -- /swapfile",
		Builtin:          true,
	},
	{
		Key:              TplOldBackupCompress,
		Name:             "旧备份无损压缩",
		ConditionSummary: "磁盘或备份待办命中，且备份目录下存在超过保留天数的未压缩备份文件（只做 gzip 无损压缩并经完整性校验后移除原件，从不删除备份）",
		DefaultTier:      "auto",
		AllowedTiers:     []string{"auto", "propose", "human"},
		DefaultWindow:    "02:00-05:00",
		DefaultCooldown:  360,
		DefaultParams:    map[string]any{"paths": []string{"/var/backups"}, "min_age_days": 7, "mount": "/"},
		RollbackHint:     "gzip -d -- <备份文件.gz> 原地无损解压恢复原备份文件与时间戳",
		Builtin:          true,
	},
	{
		Key:              TplExpiredNeverLogin,
		Name:             "密码过期且从未登录的本地账号",
		ConditionSummary: "账号审计待办命中密码已过期且从未登录的本地普通账号（先锁定不删除）",
		DefaultTier:      "propose",
		AllowedTiers:     []string{"propose", "human"},
		DefaultWindow:    "",
		DefaultCooldown:  1440,
		RollbackHint:     "usermod -U -- <账号名> 解除密码锁定",
		Builtin:          true,
	},
	{
		Key:              TplSystemdCrashLoop,
		Name:             "崩溃循环超过阈值的 systemd 服务",
		ConditionSummary: "服务异常待办命中非核心 systemd 服务重启次数达到阈值且持续崩溃（停用并保留配置）",
		DefaultTier:      "propose",
		AllowedTiers:     []string{"propose", "human"},
		DefaultWindow:    "",
		DefaultCooldown:  720,
		DefaultParams:    map[string]any{"min_restarts": 5},
		RollbackHint:     "systemctl enable --now -- <服务.service> 重新启用并拉起",
		Builtin:          true,
	},
	{
		Key:              TplStaleConnArchive,
		Name:             "指向不存在目标的密钥与连接配置",
		ConditionSummary: "巡检发现 SSH 密钥或连接配置指向疑似不存在或长期不可达的目标主机",
		DefaultTier:      "human",
		AllowedTiers:     []string{"human"},
		DefaultWindow:    "",
		DefaultCooldown:  1440,
		RollbackHint:     "主机侧无法单独区分目标永久下线与关机/隧道离线，固定转交人工队列确认，不自动改动密钥或连接配置",
		Builtin:          true,
	},
	{
		Key:              TplMgmtPortRestrict,
		Name:             "管理端口对内网全开",
		ConditionSummary: "暴露面或监听审计待办命中管理端口对全网段开放，限制到已配置的允许管理网段",
		DefaultTier:      "propose",
		AllowedTiers:     []string{"propose", "human"},
		DefaultWindow:    "02:00-05:00",
		DefaultCooldown:  1440,
		DefaultParams:    map[string]any{"ports": []int{3389, 5900, 8006, 9090}, "allowed_cidrs": []string{}},
		RollbackHint:     "iptables -D INPUT -p tcp --dport <端口> -j OPENXDR_MGMT_<端口> && iptables -F OPENXDR_MGMT_<端口> && iptables -X OPENXDR_MGMT_<端口>",
		Builtin:          true,
	},
	{
		Key:               TplRestartFailedService,
		Name:              "按主机长期授权：重启失败的非核心服务",
		ConditionSummary:  "指定主机上已登记的非核心 systemd 服务处于 failed 且 enabled 状态时自动重启",
		DefaultTier:       "auto",
		AllowedTiers:      []string{"auto", "propose", "human"},
		DefaultWindow:     "",
		DefaultCooldown:   180,
		DefaultParams:     map[string]any{"units": []string{}},
		RollbackHint:      "systemctl stop -- <服务.service>（或查看 journalctl -u <服务.service> -n 100 排查异常）",
		RequiresHostScope: true,
	},
	{
		Key:               TplReclaimDisk,
		Name:              "按主机长期授权：清理指定目录过期文件",
		ConditionSummary:  "指定主机磁盘容量待办命中时，按保留天数清理已授权非关键目录下的过期文件",
		DefaultTier:       "auto",
		AllowedTiers:      []string{"auto", "propose", "human"},
		DefaultWindow:     "02:00-05:00",
		DefaultCooldown:   360,
		DefaultParams:     map[string]any{"paths": []string{}, "min_age_days": 7, "mount": "/"},
		RollbackHint:      "仅清理已授权缓存/日志目录下超过保留天数的旧文件，执行前后留存 df -P 独立空间证据",
		RequiresHostScope: true,
	},
}

// Templates 返回所有常设规矩模板定义副本。
func Templates() []Template {
	out := make([]Template, len(templates))
	copy(out, templates)
	return out
}

// LookupTemplate 按 key 查找模板定义。
func LookupTemplate(key string) (Template, bool) {
	for _, tpl := range templates {
		if tpl.Key == key {
			return tpl, true
		}
	}
	return Template{}, false
}

// Ref 生成总控常设规矩编号 R-xxxxxxxx。
func Ref(id uuid.UUID) string {
	return facts.Ref("R", id)
}

// SeedBuiltins 幂等写入首批 8 条内置常设规矩，全部默认停用（enabled=false），不覆盖管理员已改过的配置。
func SeedBuiltins(ctx context.Context, db *ent.Client) error {
	existing, err := db.StandingRule.Query().Where(standingrule.BuiltinKeyNEQ("")).All(ctx)
	if err != nil {
		return err
	}
	have := make(map[string]bool, len(existing))
	for _, r := range existing {
		have[r.BuiltinKey] = true
	}
	for _, tpl := range templates {
		if !tpl.Builtin || have[tpl.Key] {
			continue
		}
		q := db.StandingRule.Create().
			SetBuiltinKey(tpl.Key).
			SetName(tpl.Name).
			SetConditionSummary(tpl.ConditionSummary).
			SetActionTemplate(tpl.Key).
			SetTier(standingrule.Tier(tpl.DefaultTier)).
			SetMaintenanceWindow(tpl.DefaultWindow).
			SetCooldownMinutes(tpl.DefaultCooldown).
			SetCreatedBy("platform").
			SetEnabled(false)
		if tpl.DefaultParams != nil {
			q.SetActionParams(tpl.DefaultParams)
		}
		if err := q.Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// RuleInput 用于创建与更新规矩时的统一参数校验。
type RuleInput struct {
	BuiltinKey        string
	Name              string
	ConditionSummary  string
	Condition         map[string]any
	ActionTemplate    string
	ActionParams      map[string]any
	Tier              string
	GroupID           *uuid.UUID
	AssetIDs          []uuid.UUID
	MaintenanceWindow string
	CooldownMinutes   int
	Enabled           bool
}

var linuxUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidateInput 校验常设规矩配置：核对模板档位上界、维护窗口、冷却、作用范围与动作参数。
func ValidateInput(ctx context.Context, db *ent.Client, in RuleInput) error {
	tpl, ok := LookupTemplate(in.ActionTemplate)
	if !ok {
		return errors.New("不支持的常设规矩动作模板")
	}
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 200 {
		return errors.New("规矩名称长度须在 1 至 200 字符之间")
	}
	if strings.TrimSpace(in.ConditionSummary) == "" || len(in.ConditionSummary) > 500 {
		return errors.New("条件摘要长度须在 1 至 500 字符之间")
	}
	if !slices.Contains(tpl.AllowedTiers, in.Tier) {
		return fmt.Errorf("动作模板 %s 不允许设为 %s 档（允许：%s）", tpl.Key, in.Tier, strings.Join(tpl.AllowedTiers, "/"))
	}
	if in.CooldownMinutes < 60 || in.CooldownMinutes > 10080 {
		return errors.New("资产冷却时间须在 60 至 10080 分钟之间")
	}
	if strings.TrimSpace(in.MaintenanceWindow) != "" {
		if _, _, err := repairpolicy.ParseWindow(in.MaintenanceWindow); err != nil {
			return err
		}
	}
	if tpl.RequiresHostScope && (in.GroupID == nil || *in.GroupID == uuid.Nil || len(in.AssetIDs) == 0) {
		return errors.New("按主机长期授权规矩必须明确指定所属组与至少一台目标 Linux 主机")
	}
	if len(in.AssetIDs) > 50 {
		return errors.New("单条规矩最多指定 50 台主机")
	}
	if len(in.AssetIDs) > 0 && (in.GroupID == nil || *in.GroupID == uuid.Nil) {
		return errors.New("指定主机列表时必须同时指定所属组")
	}
	if in.GroupID != nil && *in.GroupID != uuid.Nil && db != nil {
		seen := map[uuid.UUID]bool{}
		for _, id := range in.AssetIDs {
			if id == uuid.Nil || seen[id] {
				return errors.New("目标主机列表无效或包含重复项")
			}
			seen[id] = true
			exists, err := db.Asset.Query().Where(asset.IDEQ(id), asset.GroupIDEQ(*in.GroupID), asset.OsEQ("linux")).Exist(ctx)
			if err != nil {
				return err
			}
			if !exists {
				return errors.New("目标主机不属于指定组或不是 Linux 主机")
			}
		}
	}
	return validateTemplateParams(tpl.Key, in.ActionParams, in.Enabled)
}

func validateTemplateParams(tplKey string, params map[string]any, enabled bool) error {
	if mount := paramString(params, "mount", "/"); !repaircmd.Mount(mount) {
		return errors.New("磁盘挂载点必须为规范绝对路径")
	}
	switch tplKey {
	case TplOldBackupCompress:
		paths := paramStringSlice(params, "paths")
		if len(paths) == 0 {
			paths = []string{"/var/backups"}
		}
		if len(paths) > 20 {
			return errors.New("备份目录最多配置 20 个")
		}
		for _, p := range paths {
			if !repaircmd.BackupDir(p) {
				return fmt.Errorf("备份目录 %s 不符合安全边界（须为规范绝对路径且排除系统/数据库/平台目录）", p)
			}
		}
		days := paramInt(params, "min_age_days", 7)
		if days < 1 || days > 3650 {
			return errors.New("备份最小保留天数须在 1 至 3650 天之间")
		}
	case TplRestartFailedService:
		units := paramStringSlice(params, "units")
		if len(units) == 0 || len(units) > 20 {
			return errors.New("服务重启规矩须指定 1 至 20 个精确非核心 .service 名称")
		}
		seen := map[string]bool{}
		for _, u := range units {
			if !repairpolicy.ValidServiceUnit(u) || seen[u] {
				return fmt.Errorf("服务名 %s 无效、重复或属于核心基础设施服务", u)
			}
			seen[u] = true
		}
	case TplReclaimDisk:
		paths := paramStringSlice(params, "paths")
		if len(paths) == 0 || len(paths) > 20 {
			return errors.New("目录清理规矩须指定 1 至 20 个非关键规范绝对路径")
		}
		seen := map[string]bool{}
		for _, p := range paths {
			if !repaircmd.Path(p) || seen[p] {
				return fmt.Errorf("清理目录 %s 无效、重复或属于受保护目录", p)
			}
			seen[p] = true
		}
		days := paramInt(params, "min_age_days", 7)
		if days < 7 || days > 3650 {
			return errors.New("目录清理保留天数须在 7 至 3650 天之间")
		}
	case TplMgmtPortRestrict:
		ports := paramIntSlice(params, "ports")
		if len(ports) > 20 {
			return errors.New("管理端口最多配置 20 个")
		}
		for _, p := range ports {
			if p < 1 || p > 65535 {
				return fmt.Errorf("管理端口 %d 无效", p)
			}
		}
		cidrs := paramStringSlice(params, "allowed_cidrs")
		if enabled && len(cidrs) == 0 {
			return errors.New("启用「管理端口对内网全开」规矩前，须先配置至少一个允许访问的管理网段（allowed_cidrs）")
		}
		for _, c := range cidrs {
			if _, err := parseIPv4PrefixOrAddr(c); err != nil {
				return fmt.Errorf("允许管理网段 %s 无效：%w", c, err)
			}
		}
	case TplSystemdCrashLoop:
		minRestarts := paramInt(params, "min_restarts", 5)
		if minRestarts < 3 || minRestarts > 1000 {
			return errors.New("崩溃循环重启阈值须在 3 至 1000 之间")
		}
	}
	return nil
}

func parseIPv4PrefixOrAddr(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return "", errors.New("须为合法 IPv4 地址或 CIDR")
		}
		return p.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is4() {
		return "", errors.New("须为合法 IPv4 地址或 CIDR")
	}
	return netip.PrefixFrom(addr, 32).String(), nil
}

// MatchFinding 判断一条运维待办是否命中常设规矩的范围与条件。
func MatchFinding(r *ent.StandingRule, f *ent.Finding) bool {
	if r == nil || f == nil || !r.Enabled || f.Status != "open" {
		return false
	}
	if r.GroupID != nil && *r.GroupID != f.GroupID {
		return false
	}
	if len(r.AssetIds) > 0 && !slices.Contains(r.AssetIds, f.AssetID) {
		return false
	}
	text := strings.ToLower(f.Key + " " + f.Title + " " + f.Detail)
	if kw := paramStringSlice(r.Condition, "keywords"); len(kw) > 0 {
		matched := false
		for _, w := range kw {
			if w = strings.ToLower(strings.TrimSpace(w)); w != "" && strings.Contains(text, w) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	switch r.ActionTemplate {
	case TplDockerUnused7d:
		return isDiskCapacityText(text) || containsAny(text, "docker", "镜像", "volume", "buildkit")
	case TplPkgJournalClean:
		return isDiskCapacityText(text) || containsAny(text, "journal", "apt", "cache", "日志占用")
	case TplReclaimDisk:
		return isDiskCapacityText(text)
	case TplOldBackupCompress:
		return isDiskCapacityText(text) || containsAny(text, "backup", "备份", ".sql", ".dump", ".bak")
	case TplLowMemAddSwap:
		return containsAny(text, "swap", "oom", "out of memory", "内存不足", "无 swap", "无swap", "memory pressure", "low memory")
	case TplExpiredNeverLogin:
		return containsAny(text, "account", "passwd", "password", "shadow", "expired", "never logged", "账号", "账户", "密码过期", "从未登录")
	case TplSystemdCrashLoop:
		return containsAny(text, "crash", "restart", "activating", "auto-restart", "崩溃", "反复重启", "重启循环", "systemd")
	case TplStaleConnArchive:
		return containsAny(text, "ssh", "known_hosts", "authorized_keys", "identityfile", "stale", "unreachable", "decommission", "不存在目标", "失效连接", "废弃密钥", "下线主机")
	case TplMgmtPortRestrict:
		return containsAny(text, "0.0.0.0", "管理端口", "暴露", "全开", "3389", "5900", "8006", "9090", "exposed", "listen")
	case TplRestartFailedService:
		for _, u := range paramStringSlice(r.ActionParams, "units") {
			base := strings.ToLower(strings.TrimSuffix(u, ".service"))
			if base != "" && strings.Contains(text, base) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func isDiskCapacityText(lower string) bool {
	disk := containsAny(lower, "disk", "filesystem", "磁盘", "分区", "根盘")
	cap := containsAny(lower, "full", "capacity", "space", "pressure", "usage", "满", "容量", "空间", "使用率")
	return disk && cap
}

func containsAny(lower string, words ...string) bool {
	for _, w := range words {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func paramString(m map[string]any, key, def string) string {
	if m == nil {
		return def
	}
	if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func paramInt(m map[string]any, key string, def int) int {
	if m == nil {
		return def
	}
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func paramStringSlice(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	switch v := m[key].(type) {
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

func paramIntSlice(m map[string]any, key string) []int {
	if m == nil {
		return nil
	}
	switch v := m[key].(type) {
	case []int:
		return slices.Clone(v)
	case []any:
		var out []int
		for _, item := range v {
			switch n := item.(type) {
			case float64:
				out = append(out, int(n))
			case int:
				out = append(out, n)
			}
		}
		return out
	}
	return nil
}
