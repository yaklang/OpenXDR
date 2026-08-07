package sigma

import (
	"fmt"
	"strconv"
	"strings"
)

// condition 表达式：ident、not、and、or、括号、聚合。优先级 not > and > or。
//
// selection 名在编译期就解析成下标，运行期不做任何字符串查找；
// 求值走 evalCtx 惰性计算，主 selection 不中时后面的 filter 一次都不算。
type node interface {
	eval(c *evalCtx) bool
}

// evalCtx 单条规则对单条事件的求值上下文。memo 由调用方复用，避免每次分配。
type evalCtx struct {
	sels []selection
	raw  map[string]any
	memo []int8 // 0=未算 1=真 2=假
	// 关键字匹配用的事件平铺串，整条事件算一次，跨规则复用
	flat     string
	flatDone bool
}

func (c *evalCtx) value(i int) bool {
	if i < 0 {
		return false // condition 引用了不存在的 selection
	}
	if c.memo[i] == 0 {
		if c.sels[i].matches(c) {
			c.memo[i] = 1
		} else {
			c.memo[i] = 2
		}
	}
	return c.memo[i] == 1
}

func (c *evalCtx) flattened() string {
	if !c.flatDone {
		c.flat = strings.ToLower(flatten(c.raw))
		c.flatDone = true
	}
	return c.flat
}

type identNode int

func (n identNode) eval(c *evalCtx) bool { return c.value(int(n)) }

type notNode struct{ inner node }

func (n notNode) eval(c *evalCtx) bool { return !n.inner.eval(c) }

type andNode struct{ left, right node }

func (n andNode) eval(c *evalCtx) bool { return n.left.eval(c) && n.right.eval(c) }

type orNode struct{ left, right node }

func (n orNode) eval(c *evalCtx) bool { return n.left.eval(c) || n.right.eval(c) }

// quantNode 聚合条件：`1 of them`、`all of selection_*`、`any of filter_*`。
// 通配符在编译期就展开成下标集合。
type quantNode struct {
	all     bool // all of ...
	min     int  // x of ...（any 等价于 1）
	targets []int
}

func (n quantNode) eval(c *evalCtx) bool {
	if len(n.targets) == 0 {
		return false
	}
	matched := 0
	for _, i := range n.targets {
		if c.value(i) {
			matched++
			if !n.all && matched >= n.min {
				return true
			}
		} else if n.all {
			return false
		}
	}
	return n.all
}

type parser struct {
	tokens []string
	pos    int
	names  []string // selection 名，下标即求值下标
}

func parseCondition(text string, names []string) (node, error) {
	text = strings.ReplaceAll(text, "(", " ( ")
	text = strings.ReplaceAll(text, ")", " ) ")
	p := &parser{tokens: strings.Fields(text), names: names}
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
		n := identNode(p.indexOf(p.tokens[p.pos]))
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
		n = quantNode{all: true}
	case "any":
		n = quantNode{min: 1}
	default:
		count, err := strconv.Atoi(head)
		if err != nil || count < 1 {
			return nil, false
		}
		n = quantNode{min: count}
	}
	n.targets = p.expand(pattern)
	p.pos += 3
	return n, true
}

// expand 把 `them` 或带通配符的 selection 名展开成下标集合。
func (p *parser) expand(pattern string) []int {
	if pattern == "them" {
		targets := make([]int, len(p.names))
		for i := range p.names {
			targets[i] = i
		}
		return targets
	}
	prefix, wildcard := strings.CutSuffix(pattern, "*")
	var targets []int
	for i, name := range p.names {
		if (wildcard && strings.HasPrefix(name, prefix)) || name == pattern {
			targets = append(targets, i)
		}
	}
	return targets
}

func (p *parser) indexOf(name string) int {
	for i, n := range p.names {
		if n == name {
			return i
		}
	}
	return -1
}

func (p *parser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}
