package sigma

import (
	"fmt"
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
		n := identNode(p.tokens[p.pos])
		p.pos++
		return n, nil
	}
}

func (p *parser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}
