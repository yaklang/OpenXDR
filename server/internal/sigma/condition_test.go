package sigma

import (
	"sort"
	"testing"
)

// selNames 取 selection 名并排序，与编译期建表顺序一致。
func selNames(sel map[string]bool) []string {
	names := make([]string, 0, len(sel))
	for name := range sel {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// eval 把条件表达式按给定的 selection 命中表求值。
// selection 的真假直接预置进 memo，不经过实际字段匹配。
func eval(t *testing.T, cond string, sel map[string]bool) bool {
	t.Helper()
	names := selNames(sel)
	n, err := parseCondition(cond, names)
	if err != nil {
		t.Fatalf("parseCondition(%q) err = %v", cond, err)
	}
	c := &evalCtx{sels: make([]selection, len(names)), memo: make([]int8, len(names))}
	for i, name := range names {
		if sel[name] {
			c.memo[i] = 1
		} else {
			c.memo[i] = 2
		}
	}
	return n.eval(c)
}

// parseCond 用固定的 selection 名集合解析条件，供只关心解析结果的用例使用。
func parseCond(cond string) (node, error) {
	return parseCondition(cond, []string{"a", "b", "c", "selection", "selection_a", "selection_b", "filter", "filter_a"})
}

func TestParseConditionIdent(t *testing.T) {
	if !eval(t, "selection_a", map[string]bool{"selection_a": true}) {
		t.Fatal("ident 命中应为 true")
	}
	if eval(t, "selection_a", map[string]bool{"selection_a": false}) {
		t.Fatal("ident 未命中的 selection 应为 false")
	}
	// 未出现在表里的 selection 视为未命中
	if eval(t, "missing", map[string]bool{"selection_a": true}) {
		t.Fatal("表中不存在的 selection 应为 false")
	}
}

func TestParseConditionBoolean(t *testing.T) {
	cases := []struct {
		cond string
		sel  map[string]bool
		want bool
	}{
		{"not a", map[string]bool{"a": true}, false},
		{"not a", map[string]bool{"a": false}, true},
		{"a and b", map[string]bool{"a": true, "b": false}, false},
		{"a and b", map[string]bool{"a": true, "b": true}, true},
		{"a or b", map[string]bool{"a": false, "b": true}, true},
		{"a or b", map[string]bool{"a": false, "b": false}, false},
		// and 优先级高于 or：(a and b) or c
		{"a and b or c", map[string]bool{"a": true, "b": false, "c": false}, false},
		{"a and b or c", map[string]bool{"a": true, "b": false, "c": true}, true},
		// 括号优先
		{"(a or b) and c", map[string]bool{"a": true, "c": true}, true},
		{"(a or b) and c", map[string]bool{"a": true, "c": false}, false},
		{"not (a and b)", map[string]bool{"a": true, "b": true}, false},
	}
	for _, c := range cases {
		if got := eval(t, c.cond, c.sel); got != c.want {
			t.Errorf("eval(%q) = %v, want %v", c.cond, got, c.want)
		}
	}
}

func TestParseConditionsErrors(t *testing.T) {
	bad := []string{
		"a and", // 右侧缺失 → 意外结束
		"a or",  // 右侧缺失
		"(",     // 缺少右括号
		"(a",    // 缺少右括号
		"a)",    // 多余 token
		"a b",   // ident 后多余 token
		"",      // 空条件
		"not",   // not 后无内容
	}
	for _, cond := range bad {
		if _, err := parseCond(cond); err == nil {
			t.Errorf("parseCond(%q) 应报错", cond)
		}
	}
}

func TestQuantifierEval(t *testing.T) {
	cases := []struct {
		cond string
		sel  map[string]bool
		want bool
	}{
		// them 作用于全部 selection，1 of = 任一命中
		{"1 of them", map[string]bool{"s1": false, "s2": true, "s3": false}, true},
		{"1 of them", map[string]bool{"s1": false, "s2": false, "s3": false}, false},
		// all of them：全部命中
		{"all of them", map[string]bool{"s1": true, "s2": true, "s3": true}, true},
		{"all of them", map[string]bool{"s1": true, "s2": false, "s3": true}, false},
		// any == 1 of
		{"any of them", map[string]bool{"s1": false, "s2": false, "s3": true}, true},
		// 数字下限
		{"2 of them", map[string]bool{"s1": true, "s2": true, "s3": false}, true},
		{"2 of them", map[string]bool{"s1": true, "s2": false, "s3": false}, false},
		{"500 of them", map[string]bool{"s1": true, "s2": true, "s3": false}, false},
		// 通配符只统计匹配前缀的 selection
		{"all of selection_*", map[string]bool{"selection_a": true, "selection_b": true, "other": false}, true},
		{"all of selection_*", map[string]bool{"selection_a": true, "selection_b": false, "other": true}, false},
		{"1 of selection_*", map[string]bool{"selection_a": false, "other": true, "filter_x": true}, false},
		// 完全匹配非通配名
		{"all of filter_x", map[string]bool{"filter_x": true, "filter_y": false}, true},
		{"1 of filter_x", map[string]bool{"filter_x": false, "filter_y": true}, false},
	}
	for _, c := range cases {
		if got := eval(t, c.cond, c.sel); got != c.want {
			t.Errorf("eval(%q) = %v, want %v (sel=%v)", c.cond, got, c.want, c.sel)
		}
	}
}

// total 为 0 时无论 all 与否都不能算命中，避免空集自洽成真。
func TestQuantifierEmptySet(t *testing.T) {
	if eval(t, "all of them", map[string]bool{}) {
		t.Fatal("空 selection 集上 all of them 应为 false")
	}
	if eval(t, "1 of them", map[string]bool{}) {
		t.Fatal("空 selection 集上 1 of them 应为 false")
	}
}

// 非法量词头（不是 all/any/正整数）不能吞掉 token，应退回为普通 ident。
func TestQuantifierNotConsumed(t *testing.T) {
	// "0 of them" 的量词非法，应解析成 ident("0") of ...；但这在语法上仍会报错（多余 token），
	// 关键在于它不该被当成合法量词成功解析。
	for _, cond := range []string{"0 of them", "-1 of them", "1.5 of them", "of them"} {
		if _, err := parseCond(cond); err == nil {
			t.Errorf("parseCond(%q) 应报错", cond)
		}
	}
}

// 前缀通配逻辑：them 全匹配、尾随 * 按前缀、其余精确匹配。
// 展开在编译期完成，这里直接验 parser.expand 的结果。
func TestQuantifierMatches(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"them", "selection_a", true},
		{"them", "anything", true},
		{"selection_*", "selection_a", true},
		{"selection_*", "selectionb", false},
		{"selection_*", "x", false},
		{"exact", "exact", true},
		{"exact", "exac", false},
		{"selection_a*", "selection_alpha", true}, // 前缀带下划线
	}
	for _, c := range cases {
		p := &parser{names: []string{c.name}}
		got := len(p.expand(c.pattern)) == 1
		if got != c.want {
			t.Errorf("expand(pattern=%q, name=%q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

// 解析出的 AST 类型应是 quantNode，保证 parseQuantifier 真的被走到。
func TestQuantifierParsedAsNode(t *testing.T) {
	n, err := parseCond("1 of them")
	if err != nil {
		t.Fatalf("parseCondition err = %v", err)
	}
	if _, ok := n.(quantNode); !ok {
		t.Fatalf("期望 quantNode，得到 %T", n)
	}
	n2, err := parseCond("all of selection_*")
	if err != nil {
		t.Fatalf("parseCondition err = %v", err)
	}
	if _, ok := n2.(quantNode); !ok {
		t.Fatalf("期望 quantNode，得到 %T", n2)
	}
}

func TestParseConditionNormalizesWhitespace(t *testing.T) {
	for _, cond := range []string{"(a or b) and c", " ( a or b ) and c ", "a\nand\nb"} {
		if _, err := parseCond(cond); err != nil {
			t.Errorf("parseCond(%q) err = %v", cond, err)
		}
	}
}
