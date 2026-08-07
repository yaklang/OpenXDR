package sigma

import (
	"fmt"
	"strconv"
	"strings"
)

// condition 表达式：ident、not、and、or、括号。优先级 not > and > or。
type node interface {
	eval(sel map[string]bool) bool
}

type identNode string

func (n identNode) eval(sel map[string]bool) bool { return sel[string(n)] }

type notNode struct{ inner node }

func (n notNode) eval(sel map[string]bool) bool { return !n.inner.eval(sel) }

type andNode struct{ left, right node }

func (n andNode) eval(sel map[string]bool) bool { return n.left.eval(sel) && n.right.eval(sel) }

type orNode struct{ left, right node }

func (n orNode) eval(sel map[string]bool) bool { return n.left.eval(sel) || n.right.eval(sel) }

// quantNode 聚合条件：`1 of them`、`all of selection_*`、`any of filter_*`。
// pattern 为 "them" 时作用于全部 selection，否则按通配符前缀匹配 selection 名。
type quantNode struct {
	all     bool // all of ...
	min     int  // x of ...（any 等价于 1）
	pattern string
}

func (n quantNode) eval(sel map[string]bool) bool {
	matched, total := 0, 0
	for name, ok := range sel {
		if !n.matches(name) {
			continue
		}
		total++
		if ok {
			matched++
		}
	}
	if total == 0 {
		return false
	}
	if n.all {
		return matched == total
	}
	return matched >= n.min
}

func (n quantNode) matches(name string) bool {
	if n.pattern == "them" {
		return true
	}
	if prefix, ok := strings.CutSuffix(n.pattern, "*"); ok {
		return strings.HasPrefix(name, prefix)
	}
	return name == n.pattern
}

type parser struct {
	tokens []string
	pos    int
}

func parseCondition(text string) (node, error) {
	text = strings.ReplaceAll(text, "(", " ( ")
	text = strings.ReplaceAll(text, ")", " ) ")
	p := &parser{tokens: strings.Fields(text)}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.tokens) {
		return nil, fmt.Errorf("condition 有多余 token: %q", p.tokens[p.pos])
	}
	return n, nil
}

func (p *parser) parseOr() (node, error) {
	n, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		n = orNode{n, right}
	}
	return n, nil
}

func (p *parser) parseAnd() (node, error) {
	n, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek() == "and" {
		p.pos++
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		n = andNode{n, right}
	}
	return n, nil
}

func (p *parser) parseUnary() (node, error) {
	switch p.peek() {
	case "":
		return nil, fmt.Errorf("condition 意外结束")
	case "not":
		p.pos++
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{inner}, nil
	case "(":
		p.pos++
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("缺少右括号")
		}
		p.pos++
		return n, nil
	default:
		if n, ok := p.parseQuantifier(); ok {
			return n, nil
		}
		n := identNode(p.tokens[p.pos])
		p.pos++
		return n, nil
	}
}

// parseQuantifier 识别 `<all|any|数字> of <them|pattern>`，不是这个形式则原样退回。
func (p *parser) parseQuantifier() (node, bool) {
	if p.pos+2 >= len(p.tokens) || p.tokens[p.pos+1] != "of" {
		return nil, false
	}
	head, pattern := p.tokens[p.pos], p.tokens[p.pos+2]

	var n quantNode
	switch head {
	case "all":
		n = quantNode{all: true, pattern: pattern}
	case "any":
		n = quantNode{min: 1, pattern: pattern}
	default:
		count, err := strconv.Atoi(head)
		if err != nil || count < 1 {
			return nil, false
		}
		n = quantNode{min: count, pattern: pattern}
	}
	p.pos += 3
	return n, true
}

func (p *parser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}
