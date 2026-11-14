// detectcheck 检测验证对拍：把攻击手法的真实事件回放过规则引擎与内置良性链闸门，
// 报告每个 ATT&CK 技术是否真的被抓住、良性例行链是否被正确放行且仿冒血缘仍照常告警。
//
// 语料来自 Atomic Red Team 的测试过程（命令行原文）与生产脱敏样本，归一化成本平台的
// 事件格式。这是合成回放，不是实机执行——它验证"规则能否匹配真实命令"，
// 不验证"采集端能否看见这个动作"。后者要实机跑。
//
// 判定标准刻意严格：命中的规则必须标了该技术。只要"有规则响了"就算过，
// ATT&CK 标注错了也发现不了，覆盖矩阵就会开始骗人。
//
// 用法: go run ./cmd/detectcheck [--strict] [规则目录] [语料目录]
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

type corpusFile struct {
	// 文件级技术是组内默认值，用例可以覆盖——一个手法组里
	// 常常混着相邻技术（打包与外传、侦察的几个子项）
	Technique string `yaml:"technique"`
	Name      string `yaml:"name"`
	Cases     []struct {
		Name      string         `yaml:"name"`
		Technique string         `yaml:"technique"`
		Source    string         `yaml:"source"`
		Class     int            `yaml:"class"`
		OS        string         `yaml:"os"`
		Event     map[string]any `yaml:"event"`
		// Ancestors 可选：父进程之上的多跳祖先链（[祖父进程, 曾祖父进程, ...]），验证内置良性链多跳血缘匹配
		Ancestors []map[string]any `yaml:"ancestors"`
		// NewProcess 可选：模拟 UEBA 学习期后的首次出现进程命中（xdr:ueba:new_process）
		NewProcess bool `yaml:"new_process"`
		// expect: detected（默认）| undetected（已知缺口或良性对照，显式记录）
		// | signal（不出告警，但有标了该技术的信号规则命中，供时序规则关联，见 temporal-rules/README.md）
		Expect string `yaml:"expect"`
		// level 可选：命中规则里最高的级别必须正好是它——降噪后的维护动作必须停在 low，
		// 劫持必须还是 high，只看"有没有响"验证不了分级
		Level string `yaml:"level"`
	} `yaml:"cases"`
}

type result struct {
	technique string
	group     string
	caseName  string
	source    string
	expect    string
	detected  bool
	signal    bool // 没有告警规则命中、但标了该技术的信号规则命中
	by        string
	wantLevel string // 语料要求的最高级别，空表示不检查
	gotLevel  string // 命中规则里的最高级别，没有命中为空
}

// levelNames 规则 severity（1–5）对应的 Sigma level 名
var levelNames = []string{"", "informational", "low", "medium", "high", "critical"}

func main() {
	args := os.Args[1:]
	strict := false
	for i, a := range args {
		if a == "--strict" {
			strict = true
			args = append(args[:i:i], args[i+1:]...)
			break
		}
	}
	rulesDir, corpusDir := "../rules", "../validation"
	if len(args) > 0 {
		rulesDir = args[0]
	}
	if len(args) > 1 {
		corpusDir = args[1]
	}

	engine, report := sigma.LoadDirReport(rulesDir)
	chains, err := suppress.LoadBuiltinDir(filepath.Join(rulesDir, "benign-chains"), engine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载内置良性链失败: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("规则: %d 条已加载（共 %d），内置良性链: %d 条\n", report.Loaded, report.Total, len(chains))

	files, err := filepath.Glob(filepath.Join(corpusDir, "*.yml"))
	if err != nil || len(files) == 0 {
		fmt.Fprintf(os.Stderr, "语料目录没有 .yml 文件: %s\n", corpusDir)
		os.Exit(2)
	}
	sort.Strings(files)

	var results []result
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取 %s 失败: %v\n", path, err)
			os.Exit(2)
		}
		var cf corpusFile
		if err := yaml.Unmarshal(data, &cf); err != nil {
			fmt.Fprintf(os.Stderr, "解析 %s 失败: %v\n", path, err)
			os.Exit(2)
		}
		for _, c := range cf.Cases {
			expect := c.Expect
			if expect == "" {
				expect = "detected"
			}
			technique, group := cf.Technique, cf.Name
			if c.Technique != "" {
				// 用例自带技术时组名不适用了，别贴错标签
				technique, group = c.Technique, ""
			}
			if expect != "detected" && expect != "undetected" && expect != "signal" {
				fmt.Fprintf(os.Stderr, "%s / %s: 未知 expect %q\n", path, c.Name, expect)
				os.Exit(2)
			}
			if c.Level != "" && !slices.Contains(levelNames[1:], c.Level) {
				fmt.Fprintf(os.Stderr, "%s / %s: 未知 level %q\n", path, c.Name, c.Level)
				os.Exit(2)
			}
			r := result{technique: technique, group: group, caseName: c.Name, source: c.Source, expect: expect, wantLevel: c.Level}
			lineage := buildLineage(c.Event, c.Ancestors)
			hits := filterBuiltinChains(engine.Evaluate(c.Class, c.OS, c.Event), c.Event, lineage, chains, engine)
			if c.Level != "" {
				r.gotLevel = maxLevel(hits)
			}
			if r.by = matchedBy(hits, technique); r.by != "" {
				r.detected = true
			} else if c.NewProcess && strings.EqualFold(technique, "UEBA-NEW-PROCESS") && !suppressedByBuiltin(sigma.RuleNewProcess, c.Event, lineage, chains, engine) {
				r.detected = true
				r.by = "首次出现进程 (" + sigma.RuleNewProcess + ")"
			} else if r.by = matchedBy(engine.EvaluateSignals(c.Class, c.OS, c.Event), technique); r.by != "" {
				r.signal = true
			}
			results = append(results, r)
		}
	}

	printReport(results)
	if strict && countMismatch(results) > 0 {
		os.Exit(1)
	}
}

func buildLineage(raw map[string]any, ancestors []map[string]any) []map[string]any {
	base := suppress.DefaultLineage(raw)
	if len(ancestors) == 0 {
		return base
	}
	return append(base, ancestors...)
}

func filterBuiltinChains(hits []*sigma.Rule, raw map[string]any, lineage []map[string]any, chains []suppress.BuiltinChain, catalog sigma.Catalog) []*sigma.Rule {
	if len(hits) == 0 || len(chains) == 0 {
		return hits
	}
	out := make([]*sigma.Rule, 0, len(hits))
	for _, h := range hits {
		if !suppressedByBuiltin(h.ID, raw, lineage, chains, catalog) {
			out = append(out, h)
		}
	}
	return out
}

func suppressedByBuiltin(ruleID string, raw map[string]any, lineage []map[string]any, chains []suppress.BuiltinChain, catalog sigma.Catalog) bool {
	for _, ch := range chains {
		wildcard := slices.Contains(ch.Rules, suppress.WildcardRule)
		explicit := !wildcard && slices.Contains(ch.Rules, ruleID)
		if !wildcard && !explicit {
			continue
		}
		if !suppress.BuiltinAllowedRule(ruleID, catalog, explicit) {
			continue
		}
		if suppress.MatchesWithLineage(ch.Conditions, raw, lineage) {
			return true
		}
	}
	return false
}

// matchedBy 返回命中的规则标题，未命中返回空。
// 只认标了目标技术的规则——父技术与子技术互认（T1059 ↔ T1059.004）。
func matchedBy(hits []*sigma.Rule, technique string) string {
	for _, rule := range hits {
		for _, tech := range rule.Techniques {
			if techniqueMatch(tech, technique) {
				return rule.Title
			}
		}
	}
	return ""
}

// maxLevel 命中规则里的最高级别，没有命中为空。
func maxLevel(hits []*sigma.Rule) string {
	var top int16
	for _, rule := range hits {
		top = max(top, rule.Severity)
	}
	return levelNames[top]
}

func techniqueMatch(ruleTech, caseTech string) bool {
	ruleTech, caseTech = strings.ToUpper(ruleTech), strings.ToUpper(caseTech)
	return ruleTech == caseTech ||
		strings.HasPrefix(ruleTech, caseTech+".") ||
		strings.HasPrefix(caseTech, ruleTech+".")
}

func printReport(results []result) {
	// 按技术分组输出，组内保持语料顺序
	var order []string
	byTech := map[string][]result{}
	for _, r := range results {
		if _, seen := byTech[r.technique]; !seen {
			order = append(order, r.technique)
		}
		byTech[r.technique] = append(byTech[r.technique], r)
	}

	for _, tech := range order {
		group := byTech[tech]
		fmt.Printf("\n%s %s\n", tech, group[0].group)
		for _, r := range group {
			switch got := r.outcome(); {
			case got == r.expect && r.wantLevel != r.gotLevel:
				fmt.Printf("  ! %-46s 最高级别 %q，预期 %q\n", trim(r.caseName), r.gotLevel, r.wantLevel)
			case got == r.expect && got == "detected":
				fmt.Printf("  ✓ %-46s → %s\n", trim(r.caseName), r.by)
			case got == r.expect && got == "signal":
				fmt.Printf("  ◇ %-46s （仅信号，供时序关联）→ %s\n", trim(r.caseName), r.by)
			case got == r.expect:
				fmt.Printf("  ○ %-46s （已知缺口/良性放行）\n", trim(r.caseName))
			case got == "undetected":
				fmt.Printf("  ✗ %-46s 无规则命中（预期 %s）\n", trim(r.caseName), r.expect)
			default:
				fmt.Printf("  ! %-46s 预期 %s 但实际 %s：%s\n", trim(r.caseName), r.expect, got, r.by)
			}
		}
	}

	var detected, signals, gaps, mismatch int
	techCovered := map[string]bool{}
	for _, r := range results {
		switch got := r.outcome(); {
		case got != r.expect || r.wantLevel != r.gotLevel:
			mismatch++
		case got == "detected":
			detected++
			techCovered[r.technique] = true
		case got == "signal":
			signals++
		default:
			gaps++
		}
	}
	fmt.Printf("\n合计 %d 个用例：%d 命中，%d 仅信号，%d 已知缺口/良性放行，%d 不符合预期\n",
		len(results), detected, signals, gaps, mismatch)
	fmt.Printf("覆盖技术数：%d / %d\n", len(techCovered), len(byTech))
	if mismatch > 0 {
		fmt.Println("\n不符合预期的用例要么补规则，要么在语料里显式标 expect: undetected / signal —— 别让它悬着。")
	}
}

// outcome 实际结果：detected（告警规则命中）、signal（只有信号规则命中）、undetected
func (r result) outcome() string {
	switch {
	case r.detected:
		return "detected"
	case r.signal:
		return "signal"
	}
	return "undetected"
}

func countMismatch(results []result) int {
	n := 0
	for _, r := range results {
		if r.outcome() != r.expect || r.wantLevel != r.gotLevel {
			n++
		}
	}
	return n
}

func trim(s string) string {
	if len(s) > 46 {
		return s[:43] + "…"
	}
	return s
}
