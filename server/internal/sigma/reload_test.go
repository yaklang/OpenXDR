package sigma

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestFingerprintDetectsSameSizeSameMtimeRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rule.yml")
	if err := os.WriteFile(path, []byte(reloadRuleA), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	before := dirFingerprint(dir)

	// 两份规则等长，且把 mtime 恢复成原值，模拟元数据指纹看不见的覆盖写。
	if len(reloadRuleA) != len(reloadRuleB) {
		t.Fatalf("测试语料必须等长：A=%d B=%d", len(reloadRuleA), len(reloadRuleB))
	}
	if err := os.WriteFile(path, []byte(reloadRuleB), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if after := dirFingerprint(dir); after == before {
		t.Fatal("内容变化即使大小和 mtime 相同也必须触发热重载")
	}
}

func TestWatchReloadsSameMetadataRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rule.yml")
	if err := os.WriteFile(path, []byte(reloadRuleA), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	eng := LoadDir(dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Watch(ctx, dir, 10*time.Millisecond)

	if err := os.WriteFile(path, []byte(reloadRuleB), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{"process": map[string]any{"cmd_line": "run bbb now"}}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hits := eng.Evaluate(1007, "", raw); len(hits) == 1 && hits[0].ID == "r-b" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Watch 未在期限内加载元数据不变的新规则内容")
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
