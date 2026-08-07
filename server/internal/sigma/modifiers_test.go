package sigma

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// matcher 引入 strings 快路径，语义必须与正则完全一致：大小写不敏感。
func TestMatcherKinds(t *testing.T) {
	cases := []struct {
		name  string
		m     matcher
		value string
		want  bool
	}{
		{"exact 相等", matcher{kind: matchExact, literal: "cmd.exe"}, "CMD.EXE", true},
		{"exact 前缀不视为相等", matcher{kind: matchExact, literal: "cmd.exe"}, "C:\\cmd.exe", false},
		{"contains 命中", matcher{kind: matchContains, literal: "power"}, `C:\System32\PowerShell.exe`, true},
		{"contains 未命中", matcher{kind: matchContains, literal: "bash"}, "powershell.exe", false},
		{"prefix", matcher{kind: matchPrefix, literal: "c:\\"}, `C:\Windows\cmd.exe`, true},
		{"prefix 不匹配", matcher{kind: matchPrefix, literal: "d:\\"}, `C:\Windows`, false},
		{"suffix", matcher{kind: matchSuffix, literal: ".exe"}, "cmd.EXE", true},
		{"suffix 不匹配", matcher{kind: matchSuffix, literal: ".dll"}, "cmd.exe", false},
		{"regex 走锚定", matcher{kind: matchRegex, re: regexp.MustCompile("(?i)^a.b$")}, "aXb", true},
		{"regex 前缀不视为全等", matcher{kind: matchRegex, re: regexp.MustCompile("(?i)^a.b$")}, "aXbExtra", false},
	}
	for _, c := range cases {
		if got := c.m.match(c.value, strings.ToLower(c.value)); got != c.want {
			t.Errorf("%s: match(%q) = %v, want %v", c.name, c.value, got, c.want)
		}
	}
}

// 通配符存在时应回落为 regex；无通配符且用 contains/startswith/endswith 时
// 走快路径（不持 re）。这是父重构引入的分流，语义不能漂移。
func TestMatcherFastPathVsRegex(t *testing.T) {
	exact, _ := buildMatcher("run.exe", nil)
	if exact.kind != matchExact || exact.re != nil {
		t.Errorf("无通配符默认应走 matchExact 快路径，得到 kind=%v", exact.kind)
	}
	contains, _ := buildMatcher("pwsh", map[string]bool{"contains": true})
	if contains.kind != matchContains || contains.re != nil {
		t.Errorf("contains 无通配符应走快路径，得到 kind=%v", contains.kind)
	}
	wild, _ := buildMatcher("*.exe", nil)
	if wild.kind != matchRegex || wild.re == nil {
		t.Errorf("含通配符应回落为 regex，得到 kind=%v", wild.kind)
	}
}

// 未实现的修饰符必须拒绝加载——父强调：静默当字符串处理会让
// `not selection` 型规则对每个事件误报。
func TestUnknownModifierRejected(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "mod.yml"), []byte(`
id: m1
logsource:
  category: dns_query
detection:
  selection:
    query|base64: 'AQ=='
  condition: selection
`), 0o644)

	_, report := LoadDirReport(dir)
	if report.Loaded != 0 {
		t.Fatalf("未知修饰符规则不应加载，Loaded=%d", report.Loaded)
	}
	if len(report.Skipped["未知修饰符"]) != 1 {
		t.Fatalf("应归类为未知修饰符跳过，Skipped=%v", report.Skipped)
	}
}

// knownModifiers 已实现全部列出的修饰符都能正常编译。
func TestKnownModifiersAccepted(t *testing.T) {
	for _, mod := range []string{"contains", "startswith", "endswith", "re", "all"} {
		if !knownModifiers[mod] {
			t.Errorf("已实现修饰符 %q 应在 knownModifiers 中", mod)
		}
	}
}

// Evaluate 可并发调用（memo 按事件分配），-race 下验证无数据竞争。
func TestEvaluateConcurrent(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.yml"), []byte(`
id: c1
logsource:
  category: process_creation
detection:
  selection:
    commandline|contains: 'mimikatz'
  condition: selection
`), 0o644)
	os.WriteFile(filepath.Join(dir, "b.yml"), []byte(`
id: c2
logsource:
  category: dns
detection:
  selection:
    - 'evil.com'
  condition: selection
`), 0o644)
	eng := LoadDir(dir)

	mimikatz := map[string]any{"process": map[string]any{"cmd_line": "rundll32 mimikatz"}}
	dns := map[string]any{"query": map[string]any{"hostname": "evil.com"}}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				if got := len(eng.Evaluate(1007, "", mimikatz)); got != 1 {
					t.Errorf("并发下 mimikatz 应命中 1 条，得到 %d", got)
				}
				if got := len(eng.Evaluate(4003, "", dns)); got != 1 {
					t.Errorf("并发下 dns 应命中 1 条，得到 %d", got)
				}
			}
		}()
	}
	wg.Wait()
}
