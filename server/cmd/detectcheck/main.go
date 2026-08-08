// detectcheck 检测验证对拍：把攻击手法的真实事件回放过规则引擎，
// 报告每个 ATT&CK 技术是否真的被抓住。
//
// 语料来自 Atomic Red Team 的测试过程（命令行原文），归一化成本平台的
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
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"openxdr/server/internal/sigma"
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
		// expect: detected（默认）| undetected（已知缺口，显式记录）
		Expect string `yaml:"expect"`
	} `yaml:"cases"`
}

type result struct {
	technique string
	group     string
	caseName  string
	source    string
	expect    string
	detected  bool
	by        string
}

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
	fmt.Printf("规则: %d 条已加载（共 %d）\n", report.Loaded, report.Total)

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
			by := matchedBy(engine, technique, c.Class, c.OS, c.Event)
			results = append(results, result{
				technique: technique, group: group, caseName: c.Name,
				source: c.Source, expect: expect, detected: by != "", by: by,
			})
		}
	}

	printReport(results)
	if strict && countMismatch(results) > 0 {
		os.Exit(1)
	}
}

// matchedBy 返回命中的规则标题，未命中返回空。
// 只认标了目标技术的规则——父技术与子技术互认（T1059 ↔ T1059.004）。
func matchedBy(engine *sigma.Engine, technique string, class int, os string, event map[string]any) string {
	for _, rule := range engine.Evaluate(class, os, event) {
		for _, tech := range rule.Techniques {
			if techniqueMatch(tech, technique) {
				return rule.Title
			}
		}
	}
	return ""
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
			switch {
			case r.detected && r.expect == "detected":
				fmt.Printf("  ✓ %-46s → %s\n", trim(r.caseName), r.by)
			case !r.detected && r.expect == "undetected":
				fmt.Printf("  ○ %-46s （已知缺口）\n", trim(r.caseName))
			case !r.detected:
				fmt.Printf("  ✗ %-46s 无规则命中\n", trim(r.caseName))
			default:
				fmt.Printf("  ! %-46s 标为已知缺口但实际命中 %s\n", trim(r.caseName), r.by)
			}
		}
	}

	var detected, gaps, mismatch int
	techCovered := map[string]bool{}
	for _, r := range results {
		switch {
		case r.detected && r.expect == "detected":
			detected++
			techCovered[r.technique] = true
		case !r.detected && r.expect == "undetected":
			gaps++
		default:
			mismatch++
		}
	}
	fmt.Printf("\n合计 %d 个用例：%d 命中，%d 已知缺口，%d 不符合预期\n",
		len(results), detected, gaps, mismatch)
	fmt.Printf("覆盖技术数：%d / %d\n", len(techCovered), len(byTech))
	if mismatch > 0 {
		fmt.Println("\n不符合预期的用例要么补规则，要么在语料里显式标 expect: undetected —— 别让它悬着。")
	}
}

func countMismatch(results []result) int {
	n := 0
	for _, r := range results {
		if (r.detected && r.expect == "undetected") || (!r.detected && r.expect == "detected") {
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
