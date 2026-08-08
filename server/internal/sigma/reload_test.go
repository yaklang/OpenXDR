package sigma

import (
	"os"
	"path/filepath"
	"testing"
)

const reloadRuleA = `
id: r-a
title: Rule A
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'aaa'
  condition: selection
`

const reloadRuleB = `
id: r-b
title: Rule B
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'bbb'
  condition: selection
`

// 热重载：目录指纹变化 → loadState 重建 → 原子替换后新规则立即生效，
// 且并发读到的永远是完整一致的版本。
func TestReloadSwapsState(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.yml", reloadRuleA)

	eng := LoadDir(dir)
	raw := map[string]any{"process": map[string]any{"cmd_line": "run bbb now"}}
	if hits := eng.Evaluate(1007, "", raw); len(hits) != 0 {
		t.Fatalf("重载前不该命中 Rule B：%v", hits)
	}
	before := dirFingerprint(dir)

	write("b.yml", reloadRuleB)
	if dirFingerprint(dir) == before {
		t.Fatal("新增文件后目录指纹应变化")
	}

	// Watch 的核心动作就是这两步
	s, report := loadState(dir)
	eng.state.Store(s)

	if report.Loaded != 2 {
		t.Fatalf("重载后应有 2 条规则，实际 %d", report.Loaded)
	}
	hits := eng.Evaluate(1007, "", raw)
	if len(hits) != 1 || hits[0].ID != "r-b" {
		t.Fatalf("重载后 Rule B 应命中：%v", hits)
	}
	if eng.TitleOf("r-b") != "Rule B" {
		t.Fatal("TitleOf 应读到新状态")
	}
}

// 零值 Engine 必须能安全求值——测试里到处这么用。
func TestZeroValueEngine(t *testing.T) {
	var eng Engine
	if hits := eng.Evaluate(1007, "", map[string]any{}); hits != nil {
		t.Fatalf("零值引擎不该命中：%v", hits)
	}
	if eng.TitleOf("x") != "" {
		t.Fatal("零值引擎 TitleOf 应为空")
	}
}
