package sigma

import (
	"errors"
	"fmt"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

// Overlay 规则目录之上叠一层控制台自定义规则。两层各自热加载、各自原子切换，
// 自定义规则写坏或删掉只影响它自己，不会动规则目录的检测面。
type Overlay struct {
	Base   Catalog
	custom atomic.Pointer[Engine]
}

var _ Catalog = (*Overlay)(nil)

var noCustom = &Engine{}

func (o *Overlay) customs() *Engine {
	if e := o.custom.Load(); e != nil {
		return e
	}
	return noCustom
}

func (o *Overlay) Evaluate(classUID int, os string, raw map[string]any) []*Rule {
	return append(o.Base.Evaluate(classUID, os, raw), o.customs().Evaluate(classUID, os, raw)...)
}

func (o *Overlay) Rules() []*Rule {
	base, custom := o.Base.Rules(), o.customs().Rules()
	return append(append(make([]*Rule, 0, len(base)+len(custom)), base...), custom...)
}

func (o *Overlay) TitleOf(id string) string {
	if r, ok := o.customs().load().byID[id]; ok {
		return r.Title
	}
	return o.Base.TitleOf(id)
}

func (o *Overlay) AuthorOf(id string) string {
	if r, ok := o.customs().load().byID[id]; ok {
		return r.Author
	}
	return o.Base.AuthorOf(id)
}

// CheckCustom 自定义规则的准入：能编译、显式写了 id、不是信号规则、不与规则目录重名。
// 信号规则只给时序规则当输入，时序快照只认规则目录，放进来也不会生效。
func (o *Overlay) CheckCustom(content []byte) (*Rule, error) {
	rule, err := Compile(content)
	if err != nil {
		return nil, err
	}
	var doc struct {
		ID string `yaml:"id"`
	}
	if yaml.Unmarshal(content, &doc) != nil || doc.ID == "" {
		return nil, errors.New("缺少 id：自定义规则必须显式写 id（建议 UUID）")
	}
	if rule.Signal {
		return nil, errors.New("自定义规则不支持 openxdr_signal 信号规则")
	}
	for _, r := range o.Base.Rules() {
		if r.ID == rule.ID {
			return nil, fmt.Errorf("id 与内置规则「%s」重复", r.Title)
		}
	}
	rule.Custom = true
	return rule, nil
}

// SetCustom 用一批自定义规则原文（id → YAML）整体替换自定义层，返回加载失败的 id 与原因。
func (o *Overlay) SetCustom(sources map[string]string) map[string]error {
	state := &engineState{byID: map[string]*Rule{}}
	failed := map[string]error{}
	for id, content := range sources {
		rule, err := o.CheckCustom([]byte(content))
		if err == nil && rule.ID != id {
			err = fmt.Errorf("原文 id %s 与记录不符", rule.ID)
		}
		if err != nil {
			failed[id] = err
			continue
		}
		state.rules = append(state.rules, rule)
		state.byID[id] = rule
	}
	state.index()
	e := &Engine{}
	e.state.Store(state)
	o.custom.Store(e)
	return failed
}
