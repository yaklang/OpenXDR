package sigma

import (
	"context"
	"os"
	"path/filepath"
	"sync"
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

// 不同快照的字段顺序和 selection 数量不同，切换期间不能借用另一版的缓存。
func TestEvaluateConcurrentSnapshotSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rule.yml")
	versions := []string{
		`id: before
logsource: {category: process_creation}
detection:
  command: {CommandLine: Alpha}
  condition: command
`,
		`id: after
logsource: {category: process_creation}
detection:
  image: {Image: /usr/bin/Beta}
  command: {CommandLine: Alpha}
  missing: {User: null}
  condition: image and command and missing
`,
	}
	states := make([]*engineState, len(versions))
	for i, body := range versions {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		state, report := loadState(dir)
		if report.Loaded != 1 {
			t.Fatalf("规则快照加载失败: %+v", report)
		}
		states[i] = state
	}
	eng := &Engine{}
	eng.state.Store(states[0])
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 500 {
				raw := map[string]any{"process": map[string]any{"cmd_line": "Alpha", "file": map[string]any{"path": "/usr/bin/Beta"}}}
				hits := eng.Evaluate(1007, "linux", raw)
				if len(hits) != 1 || (hits[0].ID != "before" && hits[0].ID != "after") {
					t.Errorf("并发切换必须命中完整快照: %v", ruleIDs(hits))
					return
				}
				if hits := eng.Evaluate(1007, "linux", nil); len(hits) != 0 {
					t.Errorf("空事件不能继承旧缓存: %v", ruleIDs(hits))
					return
				}
			}
		})
	}
	for i := range 1000 {
		eng.state.Store(states[i%len(states)])
	}
	workers.Wait()
}

// 中文译名：标题换成译名、原文留在 TitleEn；译名文件改了算目录变更，热重载会生效；坏文件不影响加载
func TestTitleTranslations(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yml"), []byte(reloadRuleA), 0o644); err != nil {
		t.Fatal(err)
	}
	before := dirFingerprint(dir)
	if err := os.WriteFile(filepath.Join(dir, titlesFile), []byte(`{"r-a":"规则甲"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if dirFingerprint(dir) == before {
		t.Fatal("译名文件变化应改变目录指纹")
	}
	e, report := LoadDirReport(dir)
	if report.Total != 1 || report.Loaded != 1 {
		t.Fatalf("译名文件不应被当成规则：%+v", report)
	}
	if r := e.Rules()[0]; r.Title != "规则甲" || r.TitleEn != "Rule A" || e.TitleOf("r-a") != "规则甲" {
		t.Fatalf("译名未生效：%+v", r)
	}
	if err := os.WriteFile(filepath.Join(dir, titlesFile), []byte(`{坏`), 0o644); err != nil {
		t.Fatal(err)
	}
	e, _ = LoadDirReport(dir)
	if r := e.Rules()[0]; r.Title != "Rule A" || r.TitleEn != "" {
		t.Fatalf("坏译名文件应退回原文：%+v", r)
	}
}

// 仓库译名表的每个 ID 都要对应一条真实规则，规则删了或改了 ID 要同步清理
func TestRepoTitleTranslationsMatchRules(t *testing.T) {
	titles := loadTitles("../../../rules")
	if len(titles) == 0 {
		t.Fatal("没读到仓库的规则译名表")
	}
	e, _ := LoadDirReport("../../../rules")
	known := map[string]bool{}
	for _, r := range e.Rules() {
		known[r.ID] = true
	}
	for id := range titles {
		if !known[id] {
			t.Errorf("译名表里的 %s 没有对应规则", id)
		}
	}
}
