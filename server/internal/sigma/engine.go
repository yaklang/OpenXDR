// Package sigma 实现 Sigma 规则引擎。启动时加载规则目录并编译，运行期对入库事件同步匹配。
// 支持子集：字段匹配、contains/startswith/endswith/re/all 修饰符、通配符、and/or/not 条件。
// 不支持的规则（如 'x of y' 聚合条件）加载时告警跳过。
package sigma

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Sigma 标准字段名 -> OCSF raw 内的 dot path；未映射的字段名按 dot path 直接使用
var fieldMap = map[string]string{
	"image":             "process.file.path",
	"commandline":       "process.cmd_line",
	"parentimage":       "process.parent_process.file.path",
	"parentcommandline": "process.parent_process.cmd_line",
	"user":              "actor.user.name",
}

var categoryMap = map[string]int{
	"process_creation":   1007,
	"network_connection": 4001,
	"dns_query":          4003,
}

var levelMap = map[string]int16{
	"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
}

var aggregateCond = regexp.MustCompile(`\bof\b`)

type Rule struct {
	ID       string
	Title    string
	Severity int16
	ClassUID int // 0 = 不限
	sels     map[string]selection
	cond     node
}

// selection：map 列表是 OR，map 内字段是 AND。
type selection [][]fieldTest

func (s selection) matches(raw map[string]any) bool {
	for _, branch := range s {
		ok := true
		for _, t := range branch {
			if !t.matches(raw) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// fieldTest：值列表是 OR（带 |all 修饰符时为 AND），expectNull 表示字段必须缺失。
type fieldTest struct {
	path       []string
	patterns   []*regexp.Regexp
	expectNull bool
	matchAll   bool
}

func (t fieldTest) matches(raw map[string]any) bool {
	value, ok := resolve(raw, t.path)
	if t.expectNull {
		return !ok
	}
	if !ok {
		return false
	}
	for _, p := range t.patterns {
		if p.MatchString(value) {
			if !t.matchAll {
				return true
			}
		} else if t.matchAll {
			return false
		}
	}
	return t.matchAll
}

func resolve(raw map[string]any, path []string) (string, bool) {
	var current any = raw
	for _, part := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		if current, ok = m[part]; !ok {
			return "", false
		}
	}
	switch v := current.(type) {
	case nil:
		return "", false
	case string:
		return v, true
	default:
		return fmt.Sprint(v), true
	}
}

type Engine struct {
	rules []*Rule
	byID  map[string]*Rule
}

func LoadDir(dir string) *Engine {
	e := &Engine{byID: map[string]*Rule{}}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := filepath.Ext(path); ext != ".yml" && ext != ".yaml" {
			return nil
		}
		rule, err := compileFile(path)
		if err != nil {
			slog.Warn("跳过规则", "file", filepath.Base(path), "reason", err)
			return nil
		}
		e.rules = append(e.rules, rule)
		if _, dup := e.byID[rule.ID]; !dup {
			e.byID[rule.ID] = rule
		}
		return nil
	})
	if err != nil {
		slog.Warn("Sigma 规则目录不可读", "dir", dir, "err", err)
	}
	slog.Info("Sigma 规则加载完成", "count", len(e.rules))
	return e
}

func (e *Engine) Evaluate(classUID int, raw map[string]any) []*Rule {
	var hits []*Rule
	for _, r := range e.rules {
		if r.ClassUID != 0 && r.ClassUID != classUID {
			continue
		}
		sel := make(map[string]bool, len(r.sels))
		for name, s := range r.sels {
			sel[name] = s.matches(raw)
		}
		if r.cond.eval(sel) {
			hits = append(hits, r)
		}
	}
	return hits
}

func (e *Engine) TitleOf(ruleID string) string {
	if r, ok := e.byID[ruleID]; ok {
		return r.Title
	}
	return ""
}

func compileFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	detection, ok := doc["detection"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("缺少 detection 段")
	}
	condText, ok := detection["condition"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少 condition")
	}
	if aggregateCond.MatchString(condText) {
		return nil, fmt.Errorf("暂不支持聚合条件: %q", condText)
	}
	cond, err := parseCondition(condText)
	if err != nil {
		return nil, err
	}

	sels := map[string]selection{}
	for name, value := range detection {
		if name == "condition" {
			continue
		}
		sel, err := compileSelection(value)
		if err != nil {
			return nil, fmt.Errorf("selection %s: %w", name, err)
		}
		sels[name] = sel
	}

	rule := &Rule{Severity: 3, sels: sels, cond: cond}
	if id, ok := doc["id"].(string); ok {
		rule.ID = id
	}
	if title, ok := doc["title"].(string); ok {
		rule.Title = title
	}
	if rule.ID == "" {
		if rule.Title == "" {
			return nil, fmt.Errorf("缺少 id 和 title")
		}
		rule.ID = rule.Title
	}
	if level, ok := doc["level"].(string); ok {
		if sev, ok := levelMap[strings.ToLower(level)]; ok {
			rule.Severity = sev
		}
	}
	if ls, ok := doc["logsource"].(map[string]any); ok {
		if cat, ok := ls["category"].(string); ok {
			uid, ok := categoryMap[strings.ToLower(cat)]
			if !ok {
				return nil, fmt.Errorf("未知 logsource category: %s", cat)
			}
			rule.ClassUID = uid
		}
	}
	return rule, nil
}

func compileSelection(value any) (selection, error) {
	switch v := value.(type) {
	case map[string]any:
		branch, err := compileBranch(v)
		if err != nil {
			return nil, err
		}
		return selection{branch}, nil
	case []any:
		var sel selection
		for _, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("暂不支持关键字列表 selection")
			}
			branch, err := compileBranch(m)
			if err != nil {
				return nil, err
			}
			sel = append(sel, branch)
		}
		return sel, nil
	default:
		return nil, fmt.Errorf("暂不支持的 selection 类型 %T", value)
	}
}

func compileBranch(m map[string]any) ([]fieldTest, error) {
	var branch []fieldTest
	for key, value := range m {
		t, err := compileFieldTest(key, value)
		if err != nil {
			return nil, err
		}
		branch = append(branch, t)
	}
	return branch, nil
}

func compileFieldTest(key string, value any) (fieldTest, error) {
	parts := strings.Split(key, "|")
	field := parts[0]
	mods := map[string]bool{}
	for _, m := range parts[1:] {
		mods[strings.ToLower(m)] = true
	}

	path := field
	if mapped, ok := fieldMap[strings.ToLower(field)]; ok {
		path = mapped
	}
	t := fieldTest{path: strings.Split(path, "."), matchAll: mods["all"]}

	if value == nil {
		t.expectNull = true
		return t, nil
	}
	values, ok := value.([]any)
	if !ok {
		values = []any{value}
	}
	for _, v := range values {
		p, err := buildRegex(fmt.Sprint(v), mods)
		if err != nil {
			return fieldTest{}, err
		}
		t.patterns = append(t.patterns, p)
	}
	return t, nil
}

func buildRegex(value string, mods map[string]bool) (*regexp.Regexp, error) {
	if mods["re"] {
		return regexp.Compile("(?i)" + value)
	}
	// Sigma 通配符 * ? -> 正则；修饰符决定锚点；大小写不敏感是 Sigma 默认语义
	escaped := regexp.QuoteMeta(value)
	escaped = strings.ReplaceAll(escaped, `\*`, `.*`)
	escaped = strings.ReplaceAll(escaped, `\?`, `.`)
	switch {
	case mods["contains"]:
	case mods["startswith"]:
		escaped = "^" + escaped
	case mods["endswith"]:
		escaped += "$"
	default:
		escaped = "^" + escaped + "$"
	}
	return regexp.Compile("(?i)" + escaped)
}
