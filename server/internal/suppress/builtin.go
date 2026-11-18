package suppress

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"openxdr/server/ent"
	"openxdr/server/ent/suppression"
	"openxdr/server/internal/sigma"
)

// CreatedByBuiltin 仓库随发版同步的内置良性链来源标记
const CreatedByBuiltin = "builtin"

// WildcardRule 通配所有满足低危且非高危类别闸门的规则
const WildcardRule = "*"

// MaxBuiltinSeverity 内置良性链允许放行的最高级别（low=2, medium=3；high=4 与 critical=5 一律禁止）
const MaxBuiltinSeverity = 3

var builtinIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)

// 无论通配还是显式点名都绝对禁止放行的战术：凭据窃取、持久化
var alwaysBlockedTactics = map[string]bool{
	"credential-access": true,
	"persistence":       true,
}

// 通配（*）时额外禁止放行的战术：削弱防御、破坏影响
var wildcardBlockedTactics = map[string]bool{
	"defense-impairment": true,
	"impact":             true,
}

// 无论通配还是显式点名都绝对禁止放行的 ATT&CK 技术前缀（含子技术）：
// 凭据窃取（T1003/T1552/T1555/T1558/T1110/T1539/T1606/T1649）、
// 清痕（T1070 指标清除、T1685.004 清审计规则、T1685.006 清系统日志）、
// 削弱防御（T1562、T1686 停安全工具/关防火墙、T1690 改日志配置、T1553 信任篡改、T1556 认证篡改）、
// 破坏（T1485 数据销毁、T1486 加密勒索、T1490 禁恢复/删卷影、T1561 擦盘、T1565 数据篡改、T1529 关机重启、T1531 删账户）、
// 容器逃逸（T1611）、持久化（T1053/T1098/T1136/T1543/T1546/T1547/T1505/T1574）
var alwaysBlockedTechniquePrefixes = []string{
	"T1003", "T1552", "T1555", "T1558", "T1110", "T1539", "T1606", "T1649",
	"T1070", "T1685.", "T1562", "T1686", "T1690", "T1553", "T1556",
	"T1485", "T1486", "T1490", "T1561", "T1565", "T1495", "T1491", "T1529", "T1531",
	"T1611",
	"T1053", "T1098", "T1136", "T1543", "T1546", "T1547", "T1505", "T1574",
}

// BuiltinChain 一条内置已知良性链定义（rules/benign-chains/*.yml）
type BuiltinChain struct {
	ID          string      `yaml:"id"`
	Title       string      `yaml:"title"`
	Description string      `yaml:"description"`
	Sample      string      `yaml:"sample"`
	Rules       []string    `yaml:"rules"`
	Conditions  []Condition `yaml:"conditions"`
}

// Reason 组合成落库与控制台展示的完整依据说明
func (b BuiltinChain) Reason() string {
	desc := strings.TrimSpace(b.Description)
	sample := strings.TrimSpace(b.Sample)
	if sample == "" {
		return desc
	}
	return desc + "\n样例：" + sample
}

// SplitRuleIDs 解析 suppression.rule_id（支持单条、逗号分隔多条或 "*"）
func SplitRuleIDs(ruleID string) []string {
	parts := strings.Split(ruleID, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// JoinRuleIDs 合并内置链的 rules 列表存入 suppression.rule_id
func JoinRuleIDs(rules []string) string {
	if slices.Contains(rules, WildcardRule) {
		return WildcardRule
	}
	return strings.Join(rules, ",")
}

// BuiltinAllowedRule 判断某条检测规则是否允许被内置良性链压掉。
// explicit=true 表示内置链在 rules 字段中点名了该规则 ID；explicit=false 表示来自 rules: ["*"] 通配。
// 拿不准（如规则不在目录中）、级别高于 medium（severity > 3）、情报/诱饵命中或高危类别一律返回 false。
func BuiltinAllowedRule(ruleID string, catalog sigma.Catalog, explicit bool) bool {
	var byID map[string]*sigma.Rule
	if catalog != nil {
		list := catalog.Rules()
		byID = make(map[string]*sigma.Rule, len(list))
		for _, r := range list {
			byID[r.ID] = r
		}
	}
	return builtinAllowedInMap(ruleID, byID, explicit)
}

func builtinAllowedInMap(ruleID string, byID map[string]*sigma.Rule, explicit bool) bool {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" || strings.HasPrefix(ruleID, "intel:") || strings.HasPrefix(ruleID, "decoy:") {
		return false
	}
	if strings.HasPrefix(ruleID, "xdr:") {
		// 平台合成规则中仅首次出现进程（low, severity=2）属于例行进程噪声；爆破得手、横向喷洒、新公钥、新监听端口、信标外联一律不放行
		return ruleID == sigma.RuleNewProcess
	}
	if byID == nil {
		return false
	}
	r, ok := byID[ruleID]
	if !ok || r == nil {
		return false
	}
	if r.Severity <= 0 || r.Severity > MaxBuiltinSeverity {
		return false
	}
	for _, tac := range r.Tactics {
		t := strings.ToLower(tac)
		if alwaysBlockedTactics[t] {
			return false
		}
		if !explicit && wildcardBlockedTactics[t] {
			return false
		}
	}
	for _, tech := range r.Techniques {
		upper := strings.ToUpper(tech)
		for _, prefix := range alwaysBlockedTechniquePrefixes {
			if strings.HasPrefix(upper, prefix) {
				return false
			}
		}
		if !explicit && (strings.HasPrefix(upper, "T1685") || strings.HasPrefix(upper, "T1489")) {
			return false
		}
	}
	return true
}

// LoadBuiltinDir 加载并严格校验目录下的全部内置良性链 YAML 文件
func LoadBuiltinDir(dir string, catalog sigma.Catalog) ([]BuiltinChain, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("内置良性链路径不是目录: %s", dir)
	}

	var byID map[string]*sigma.Rule
	if catalog != nil {
		list := catalog.Rules()
		byID = make(map[string]*sigma.Rule, len(list))
		for _, r := range list {
			byID[r.ID] = r
		}
	}

	var chains []BuiltinChain
	seen := map[string]string{}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var c BuiltinChain
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil {
			return fmt.Errorf("%s 解析失败: %w", filepath.Base(path), err)
		}
		if err := validateBuiltinChain(&c, byID); err != nil {
			return fmt.Errorf("%s 校验失败: %w", filepath.Base(path), err)
		}
		if prev, dup := seen[c.ID]; dup {
			return fmt.Errorf("%s 与 %s 的内置链 id %q 重复", filepath.Base(path), prev, c.ID)
		}
		seen[c.ID] = filepath.Base(path)
		chains = append(chains, c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(chains, func(a, b BuiltinChain) int {
		return strings.Compare(a.ID, b.ID)
	})
	return chains, nil
}

func validateBuiltinChain(c *BuiltinChain, byID map[string]*sigma.Rule) error {
	c.ID = strings.TrimSpace(c.ID)
	c.Title = strings.TrimSpace(c.Title)
	c.Description = strings.TrimSpace(c.Description)
	c.Sample = strings.TrimSpace(c.Sample)
	if !builtinIDPattern.MatchString(c.ID) {
		return fmt.Errorf("id %q 不符合 ^[a-z0-9][a-z0-9-]{2,63}$", c.ID)
	}
	if c.Title == "" {
		return errors.New("缺少 title")
	}
	if c.Description == "" || c.Sample == "" {
		return errors.New("必须同时填写 description（依据）与 sample（真实样例）")
	}
	if len(c.Rules) == 0 {
		return errors.New("rules 不能为空")
	}
	cleaned := make([]string, 0, len(c.Rules))
	for _, r := range c.Rules {
		r = strings.TrimSpace(r)
		if r == "" {
			return errors.New("rules 含空元素")
		}
		if r != WildcardRule && byID != nil && !builtinAllowedInMap(r, byID, true) {
			return fmt.Errorf("规则 %q 超出内置良性链允许范围（高危级别或高危战术/技术）或不存在", r)
		}
		if !slices.Contains(cleaned, r) {
			cleaned = append(cleaned, r)
		}
	}
	if slices.Contains(cleaned, WildcardRule) && len(cleaned) > 1 {
		return errors.New("rules 使用 * 时不能再混写其他规则 ID")
	}
	c.Rules = cleaned
	return ValidateBuiltin(c.Conditions)
}

// SyncBuiltins 启动时把仓库内置良性链幂等同步到 suppressions 表：
// 新增链默认 active；已存在链更新标题、规则、依据与条件，但保留管理员停用状态（disabled）与累计命中计数。
func SyncBuiltins(ctx context.Context, db *ent.Client, catalog sigma.Catalog, dir string) (int, error) {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	chains, err := LoadBuiltinDir(dir, catalog)
	if err != nil {
		return 0, err
	}
	existing, err := db.Suppression.Query().Where(suppression.CreatedByEQ(CreatedByBuiltin)).All(ctx)
	if err != nil {
		return 0, err
	}
	byKey := make(map[string]*ent.Suppression, len(existing))
	for _, row := range existing {
		if row.BuiltinKey != nil {
			byKey[*row.BuiltinKey] = row
		}
	}

	keep := make(map[string]bool, len(chains))
	for _, c := range chains {
		keep[c.ID] = true
		ruleID := JoinRuleIDs(c.Rules)
		reason := c.Reason()
		if cur, ok := byKey[c.ID]; ok {
			upd := db.Suppression.UpdateOneID(cur.ID).
				SetBuiltinTitle(c.Title).
				SetRuleID(ruleID).
				SetReason(reason).
				SetConditions(c.Conditions)
			// 仓库里又有这条链、而它是被同步自动停用的（没有人工启停记录）：重新启用。
			// 滚动发布或回滚时旧版本节点会把它没见过的新链当成「已移除」停掉，不恢复就永远停着
			if cur.Status == "disabled" && cur.ReviewedBy == nil {
				upd.SetStatus("active")
			}
			if err := upd.Exec(ctx); err != nil {
				return 0, err
			}
			continue
		}
		if err := db.Suppression.Create().
			SetCreatedBy(CreatedByBuiltin).
			SetStatus("active").
			SetBuiltinKey(c.ID).
			SetBuiltinTitle(c.Title).
			SetRuleID(ruleID).
			SetReason(reason).
			SetConditions(c.Conditions).
			Exec(ctx); err != nil {
			return 0, err
		}
	}

	// 仓库中已移除的旧内置链自动停用，不删历史计数记录；管理员手动停用的链（reviewed_by 非空）同步不会再启用
	for _, row := range existing {
		key := ""
		if row.BuiltinKey != nil {
			key = *row.BuiltinKey
		}
		// 清掉人工启停记录：reviewed_by 只表示最后一次人工启停，自动停用的链回到仓库时据此重新启用
		if !keep[key] && row.Status == "active" {
			if err := db.Suppression.UpdateOneID(row.ID).SetStatus("disabled").ClearReviewedBy().ClearReviewedAt().Exec(ctx); err != nil {
				return 0, err
			}
		}
	}
	return len(chains), nil
}
