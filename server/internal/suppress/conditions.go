package suppress

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"openxdr/server/ent/schema"
)

// Condition 抑制的字段条件，见 schema.SuppressCondition
type Condition = schema.SuppressCondition

// MaxConditions 人工与 AI 提议的抑制最多几个字段条件
const MaxConditions = 3

// MaxBuiltinConditions 内置良性链最多几个字段条件（需同时约束可执行路径、父进程与多跳祖先）
const MaxBuiltinConditions = 12

// MaxConditionGroup ancestor 分组编号上限
const MaxConditionGroup = 8

const ancestorPrefix = "ancestor."

var fieldPath = regexp.MustCompile(`^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*){0,5}$`)

var builtinOps = map[string]bool{
	"equals":       true,
	"contains":     true,
	"startswith":   true,
	"endswith":     true,
	"in":           true,
	"not_contains": true,
	"regex":        true,
}

// Validate 校验人工或 AI 提议的字段条件：字段是事件体的 dot path，op 只认 equals / contains / endswith，值 1–500 字
func Validate(conds []Condition) error {
	if len(conds) > MaxConditions {
		return fmt.Errorf("字段条件最多 %d 个", MaxConditions)
	}
	for _, c := range conds {
		if strings.HasPrefix(c.Field, ancestorPrefix) || !fieldPath.MatchString(c.Field) {
			return fmt.Errorf("字段 %q 不是事件体的 dot path（如 query.hostname、process.cmd_line）", c.Field)
		}
		if c.Op != "equals" && c.Op != "contains" && c.Op != "endswith" {
			return errors.New("op 只能是 equals / contains / endswith")
		}
		if len(c.Values) > 0 || c.Group != 0 {
			return errors.New("仅内置良性链支持多值或祖先分组条件")
		}
		if n := utf8.RuneCountInString(c.Value); n == 0 || n > 500 {
			return errors.New("条件值须为 1–500 字")
		}
	}
	return nil
}

// ValidateBuiltin 校验内置良性链条件：必须至少包含可执行文件路径与血缘条件，禁止仅靠命令名或单字段放行
func ValidateBuiltin(conds []Condition) error {
	if len(conds) < 2 || len(conds) > MaxBuiltinConditions {
		return fmt.Errorf("内置良性链条件须为 2–%d 个，实际 %d 个", MaxBuiltinConditions, len(conds))
	}
	hasSelfExe := false
	hasLineageExe := false
	for i, c := range conds {
		sub, ancestor := strings.CutPrefix(c.Field, ancestorPrefix)
		target := c.Field
		if ancestor {
			target = sub
		}
		if !fieldPath.MatchString(target) {
			return fmt.Errorf("条件 #%d 字段 %q 不是合法 dot path", i+1, c.Field)
		}
		if !builtinOps[c.Op] {
			return fmt.Errorf("条件 #%d 不支持的 op %q", i+1, c.Op)
		}
		if c.Group < 0 || c.Group > MaxConditionGroup {
			return fmt.Errorf("条件 #%d group %d 超出 0..%d", i+1, c.Group, MaxConditionGroup)
		}
		if c.Group > 0 && !ancestor {
			return fmt.Errorf("条件 #%d 非 ancestor.* 字段不能设置 group", i+1)
		}
		if c.Op == "in" {
			if c.Value != "" || len(c.Values) == 0 || len(c.Values) > 32 {
				return fmt.Errorf("条件 #%d in 须使用 1–32 个 values 且不设 value", i+1)
			}
			for _, v := range c.Values {
				if n := utf8.RuneCountInString(v); n == 0 || n > 500 {
					return fmt.Errorf("条件 #%d values 元素须为 1–500 字", i+1)
				}
			}
		} else {
			if len(c.Values) > 0 {
				return fmt.Errorf("条件 #%d op=%s 不能设置 values", i+1, c.Op)
			}
			if n := utf8.RuneCountInString(c.Value); n == 0 || n > 500 {
				return fmt.Errorf("条件 #%d value 须为 1–500 字", i+1)
			}
			if c.Op == "regex" {
				if _, err := regexp.Compile(c.Value); err != nil {
					return fmt.Errorf("条件 #%d 正则无效: %w", i+1, err)
				}
			}
		}
		if c.Op != "not_contains" {
			if c.Field == "process.file.path" {
				hasSelfExe = true
			}
			if c.Field == "process.parent_process.file.path" || (ancestor && target == "file.path") {
				hasLineageExe = true
			}
		}
	}
	if !hasSelfExe || !hasLineageExe {
		return errors.New("内置良性链必须同时约束当前进程可执行路径（process.file.path）与父/祖先可执行路径")
	}
	return nil
}

// NeedsLineageConditions 条件列表是否引用了多跳祖先字段（ancestor.*）
func NeedsLineageConditions(conds []Condition) bool {
	return slices.ContainsFunc(conds, func(c Condition) bool {
		return strings.HasPrefix(c.Field, ancestorPrefix)
	})
}

type compiledCond struct {
	field    string
	ancestor bool
	group    int
	op       string
	want     string
	wants    []string
	re       *regexp.Regexp
}

type compiledSet struct {
	direct   []compiledCond
	anyAnc   []compiledCond
	grouped  [][]compiledCond
	ancestor bool
}

func compileConditions(conds []Condition) compiledSet {
	var out compiledSet
	byGroup := map[int][]compiledCond{}
	var groupOrder []int
	for _, c := range conds {
		sub, anc := strings.CutPrefix(c.Field, ancestorPrefix)
		cc := compiledCond{
			field:    c.Field,
			ancestor: anc,
			group:    c.Group,
			op:       c.Op,
			want:     strings.ToLower(c.Value),
		}
		if anc {
			cc.field = sub
			out.ancestor = true
		}
		if c.Op == "in" {
			cc.wants = make([]string, len(c.Values))
			for i, v := range c.Values {
				cc.wants[i] = strings.ToLower(v)
			}
		} else if c.Op == "regex" {
			cc.re, _ = regexp.Compile(c.Value)
		}
		switch {
		case !anc:
			out.direct = append(out.direct, cc)
		case cc.group == 0:
			out.anyAnc = append(out.anyAnc, cc)
		default:
			if _, seen := byGroup[cc.group]; !seen {
				groupOrder = append(groupOrder, cc.group)
			}
			byGroup[cc.group] = append(byGroup[cc.group], cc)
		}
	}
	slices.Sort(groupOrder)
	for _, g := range groupOrder {
		out.grouped = append(out.grouped, byGroup[g])
	}
	return out
}

func (c compiledCond) matchMap(m map[string]any) bool {
	rawVal, ok := Lookup(m, c.field)
	if !ok {
		return false
	}
	if c.op == "regex" {
		return c.re != nil && c.re.MatchString(rawVal)
	}
	v := strings.ToLower(rawVal)
	switch c.op {
	case "equals":
		return v == c.want
	case "contains":
		return strings.Contains(v, c.want)
	case "startswith":
		return strings.HasPrefix(v, c.want)
	case "endswith":
		return strings.HasSuffix(v, c.want)
	case "not_contains":
		return !strings.Contains(v, c.want)
	case "in":
		return slices.Contains(c.wants, v)
	default:
		return false
	}
}

func (s compiledSet) matches(raw map[string]any, lineage []map[string]any) bool {
	for _, c := range s.direct {
		if !c.matchMap(raw) {
			return false
		}
	}
	if !s.ancestor {
		return true
	}
	if lineage == nil {
		lineage = DefaultLineage(raw)
	}
	for _, c := range s.anyAnc {
		if !slices.ContainsFunc(lineage, c.matchMap) {
			return false
		}
	}
	for _, grp := range s.grouped {
		matched := slices.ContainsFunc(lineage, func(anc map[string]any) bool {
			for _, c := range grp {
				if !c.matchMap(anc) {
					return false
				}
			}
			return true
		})
		if !matched {
			return false
		}
	}
	return true
}

// DefaultLineage 从事件内嵌的 process.parent_process 提取单跳父进程作为兜底血缘
func DefaultLineage(raw map[string]any) []map[string]any {
	proc, ok := raw["process"].(map[string]any)
	if !ok {
		return nil
	}
	parent, ok := proc["parent_process"].(map[string]any)
	if !ok || len(parent) == 0 {
		return nil
	}
	return []map[string]any{parent}
}

// Matches 事件体是否满足全部条件（仅用事件自身与内嵌 parent_process）；没有条件视为满足
func Matches(conds []Condition, raw map[string]any) bool {
	return MatchesWithLineage(conds, raw, nil)
}

// MatchesWithLineage 事件体与多跳祖先链是否满足全部条件；lineage 为 nil 时退回 DefaultLineage(raw)
func MatchesWithLineage(conds []Condition, raw map[string]any, lineage []map[string]any) bool {
	if len(conds) == 0 {
		return true
	}
	return compileConditions(conds).matches(raw, lineage)
}

// Lookup 按 dot path 取事件体里的标量值；路径不存在或落在对象、数组上返回 false
func Lookup(raw map[string]any, path string) (string, bool) {
	var cur any = raw
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		if cur, ok = m[part]; !ok {
			return "", false
		}
	}
	switch v := cur.(type) {
	case nil, map[string]any, []any:
		return "", false
	case string:
		return v, true
	default:
		return fmt.Sprint(v), true
	}
}
