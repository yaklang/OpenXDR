package sigma

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// matchOf 用原值与其小写形式调用 matcher，与运行期路径一致。
func matchOf(m matcher, v string) bool { return m.match(v, strings.ToLower(v)) }

// --- buildMatcher 修饰符 ---

func TestBuildRegexModifiers(t *testing.T) {
	// 默认全词锚定、大小写不敏感
	re, err := buildMatcher("cmd.exe", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if !matchOf(re, "cmd.exe") {
		t.Error("全词锚定应命中完全相等的值")
	}
	if matchOf(re, "C:\\Windows\\cmd.exe") {
		t.Error("全词锚定不应命中带路径前缀的值")
	}

	contains, _ := buildMatcher("powershell", map[string]bool{"contains": true})
	if !matchOf(contains, "C:\\Windows\\System32\\powershell.exe") {
		t.Error("contains 应命中子串")
	}

	start, _ := buildMatcher("C:\\", map[string]bool{"startswith": true})
	if !matchOf(start, "C:\\Windows\\cmd.exe") {
		t.Error("startswith 应命中前缀")
	}
	if matchOf(start, "D:\\cmd.exe") {
		t.Error("startswith 不应命中不匹配前缀")
	}

	end, _ := buildMatcher(".exe", map[string]bool{"endswith": true})
	if !matchOf(end, "cmd.exe") {
		t.Error("endswith 应命中后缀")
	}
	if matchOf(end, "cmd.exe;ls") {
		t.Error("endswith 不应命中不匹配后缀")
	}
}

func TestBuildRegexWildcards(t *testing.T) {
	re, err := buildMatcher("*.exe", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if !matchOf(re, "cmd.exe") || !matchOf(re, "powershell.EXE") {
		t.Error("通配符 * 应命中任意前缀")
	}

	q, _ := buildMatcher("bas?.exe", map[string]bool{})
	if !matchOf(q, "bash.exe") {
		t.Error("通配符 ? 应命中单字符")
	}
	if matchOf(q, "bashex.exe") {
		t.Error("通配符 ? 不应命多字符")
	}
}

func TestBuildRegexRawMode(t *testing.T) {
	re, err := buildMatcher(`^[\w]+\.\d+$`, map[string]bool{"re": true})
	if err != nil {
		t.Fatal(err)
	}
	if !matchOf(re, "abc.123") || matchOf(re, "abc.x") {
		t.Error("re 修饰符应原样按正则匹配")
	}
	if _, err := buildMatcher(`(unclosed`, map[string]bool{"re": true}); err == nil {
		t.Error("非法正则应报错")
	}
}

// --- resolve / fieldTest ---

func TestResolve(t *testing.T) {
	raw := map[string]any{
		"process": map[string]any{
			"file": map[string]any{"path": "C:\\bin\\x.exe", "name": "x.exe"},
		},
		"count": int64(3),
		"nil":   nil,
	}
	if v, ok := resolve(raw, []string{"process", "file", "path"}); !ok || v != "C:\\bin\\x.exe" {
		t.Errorf("resolve 嵌套字段 = %q, %v", v, ok)
	}
	if _, ok := resolve(raw, []string{"process", "file", "missing"}); ok {
		t.Error("缺失字段应返回 !ok")
	}
	if v, ok := resolve(raw, []string{"count"}); !ok || v != "3" {
		t.Errorf("resolve 非字符串标量应格式化为字面量，得到 %q, %v", v, ok)
	}
	if _, ok := resolve(raw, []string{"nil"}); ok {
		t.Error("nil 值应视为缺失")
	}
}

func TestFieldTestMatches(t *testing.T) {
	raw := map[string]any{
		"process": map[string]any{
			"cmd_line": "powershell -enc ZWNobyBoaQ==",
		},
	}
	// 字段路径按 fieldMap 映射：commandline -> process.cmd_line
	pwsh, _ := buildMatcher("powershell", map[string]bool{"contains": true})
	t1 := fieldTest{path: []string{"process", "cmd_line"}, patterns: []matcher{pwsh}}
	if !t1.matches(raw) {
		t.Error("contains 单值应命中")
	}

	// 多值 OR
	prog, _ := buildMatcher("bash", map[string]bool{"contains": true})
	t2 := fieldTest{path: []string{"process", "cmd_line"}, patterns: []matcher{pwsh, prog}}
	if !t2.matches(raw) {
		t.Error("多值 OR 有一个命中即可")
	}
	if t2.matchAll {
		t.Error("matchAll 默认应为 false")
	}

	// matchAll：多值全部命中
	enc, _ := buildMatcher("enc", map[string]bool{"contains": true})
	t3 := fieldTest{path: []string{"process", "cmd_line"}, patterns: []matcher{pwsh, enc}, matchAll: true}
	if !t3.matches(raw) {
		t.Error("matchAll 全部命中应为 true")
	}
	t4 := fieldTest{path: []string{"process", "cmd_line"}, patterns: []matcher{pwsh, prog}, matchAll: true}
	if t4.matches(raw) {
		t.Error("matchAll 有未命中应为 false")
	}

	// expectNull：字段缺失通过，存在则不通过
	nullOK := fieldTest{path: []string{"process", "absent"}, expectNull: true}
	if !nullOK.matches(raw) {
		t.Error("expectNull 且字段缺失应为 true")
	}
	nullBad := fieldTest{path: []string{"process", "cmd_line"}, expectNull: true}
	if nullBad.matches(raw) {
		t.Error("expectNull 且字段存在应为 false")
	}
}

// --- selection：分支 OR / 字段 AND / 关键字 ---

func selectionFrom(raw string) selection {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		panic(err)
	}
	s, err := compileSelection(m)
	if err != nil {
		panic(err)
	}
	return s
}

func TestSelectionBranchOR(t *testing.T) {
	// 值列表（map 里是并列项）→ OR；含 contains 关键字其中一项命中即可
	sel := selectionFrom(`{"commandline|contains": ["powershell", "bash"]}`)
	raw := map[string]any{"process": map[string]any{"cmd_line": "run powershell -c x"}}
	if !sel.matches(&evalCtx{raw: raw}) {
		t.Error("任一 OR 分支命中应为 true")
	}
	raw2 := map[string]any{"process": map[string]any{"cmd_line": "run python"}}
	if sel.matches(&evalCtx{raw: raw2}) {
		t.Error("两个分支都没命中应为 false")
	}
}

func TestSelectionKeyword(t *testing.T) {
	// 标量列表 → 关键字全文匹配
	s, err := compileSelection([]any{"mimikatz", "sekurlsa"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.keywords) != 2 {
		t.Fatalf("期望 2 个关键字，得到 %d", len(s.keywords))
	}
	raw := map[string]any{
		"process": map[string]any{"cmd_line": "run legitim.exe"},
		"query":   map[string]any{"hostname": "mimikatz-dns.example.com"},
	}
	if !s.matches(&evalCtx{raw: raw}) {
		t.Error("关键字命中任意字段应为 true")
	}
	if s.matches(&evalCtx{raw: map[string]any{"process": map[string]any{"cmd_line": "nothing here"}}}) {
		t.Error("关键字都没命中应为 false")
	}

	// 单个字符串 selection 也是关键字
	s2, err := compileSelection("attack")
	if err != nil {
		t.Fatal(err)
	}
	if ln := len(s2.keywords); ln != 1 {
		t.Fatalf("单个字符串选择应为 1 个关键字，得到 %d", ln)
	}
}

func TestFlatten(t *testing.T) {
	raw := map[string]any{
		"process": map[string]any{"cmd_line": "a", "pid": int64(7)},
		"query":   map[string]any{"hostname": "b"},
		"list":    []any{"x", "y"},
		"nil":     nil,
	}
	flat := flatten(raw)
	for _, sub := range []string{"a", "b", "x", "7"} {
		if !strings.Contains(flat, sub) {
			t.Errorf("flatten 应包含 %q，实际 %q", sub, flat)
		}
	}
}

// --- compileFieldTest 字段映射 ---

func TestFieldMapApplied(t *testing.T) {
	// Sigma 标准字段名映射到 OCSF dot path
	sel := selectionFrom(`{"commandline|contains": "powershell"}`)
	if sel.branches[0][0].path[0] != "process" {
		t.Errorf("commandline 应映射到 process.*，得到 %v", sel.branches[0][0].path)
	}
	sel2 := selectionFrom(`{"destinationip": "1.2.3.4"}`)
	if sel2.branches[0][0].path[0] != "dst_endpoint" {
		t.Errorf("destinationip 应映射到 dst_endpoint.*，得到 %v", sel2.branches[0][0].path)
	}
}

func TestIngestedClass(t *testing.T) {
	if _, ok := IngestedClass(1007); !ok {
		t.Error("1007 进程活动应有采集来源")
	}
	if _, ok := IngestedClass(1001); !ok {
		t.Error("1001 文件事件应有采集来源（agent inotify）")
	}
	if _, ok := IngestedClass(1005); ok {
		t.Error("1005 模块加载当前无采集来源")
	}
}

// --- Evaluate 端到端 ---

func TestEvaluate(t *testing.T) {
	dir := t.TempDir()
	files := []struct {
		name string
		body string
	}{
		{
			"proc_mimikatz.yml",
			`id: e-mimikatz
title: Mimikatz execution
logsource:
  category: process_creation
level: critical
detection:
  selection:
    CommandLine|contains: 'mimikatz'
  condition: selection
`,
		},
		{
			// 关键字 selection + 聚合量词
			"dns_susp.yml",
			`id: e-dns
title: Suspicious DNS
logsource:
  category: dns
detection:
  selection:
    - 'pastebin'
    - 'evil.com'
  filter:
    QueryName|contains: 'blob.core.windows.net'
  condition: selection and not filter
`,
		},
		{
			// 多个 selection + all of
			"multi.yml",
			`id: e-multi
title: Multi selection rule
logsource:
  category: process_creation
detection:
  selection_a:
    CommandLine|contains: 'net user'
  selection_b:
    CommandLine|contains: 'add'
  condition: all of selection_*
`,
		},
		{
			// 无 category，仅限定 product=linux → class 不限（ClassUID 0）
			"lin_dll.yml",
			`id: e-lin
title: Linux dll only
logsource:
  product: linux
detection:
  selection:
    targetfilename|endswith: '.dll'
  condition: selection
`,
		},
	}

	for _, f := range files {
		path := filepath.Join(dir, f.name)
		if err := os.WriteFile(path, []byte(f.body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	eng := LoadDir(dir)
	if got := len(eng.load().rules); got != 4 {
		t.Fatalf("期望加载 4 条规则，得到 %d", got)
	}

	// 进程事件：mimikatz 命中
	procRaw := map[string]any{
		"process": map[string]any{"cmd_line": "rundll32 mimikatz full",
			"file": map[string]any{"path": "/x/mimikatz.exe"}},
	}
	hits := eng.Evaluate(1007, "", procRaw)
	ids := ruleIDs(hits)
	if !containsStr(ids, "e-mimikatz") {
		t.Errorf("mimikatz 规则应命中进程事件，实际 %v", ids)
	}
	if containsStr(ids, "e-dns") {
		t.Errorf("DNS 规则不应命中进程事件（class 过滤），实际 %v", ids)
	}
	// multi：需要两个 selection 都命中（net user + add）
	if containsStr(ids, "e-multi") {
		t.Errorf("multi 未同时满足两个 selection，不应命中，实际 %v", ids)
	}
	// e-lin：class 不限，且 targetfilename .dll 结尾——但 cmd_line 不含 .dll 路径
	if containsStr(ids, "e-lin") {
		t.Errorf("e-lin 不应命中（无 .dll 结尾字段），实际 %v", ids)
	}

	// multi 两个 selection 都命中
	procRaw2 := map[string]any{
		"process": map[string]any{"cmd_line": "net user add hacker /add"},
	}
	ids2 := ruleIDs(eng.Evaluate(1007, "", procRaw2))
	if !containsStr(ids2, "e-multi") {
		t.Errorf("multi 两 selection 均命中应生效，实际 %v", ids2)
	}

	// DNS 事件：命中 dns_susp（命中关键字且不匹配 filter）
	dnsRaw := map[string]any{
		"query": map[string]any{"hostname": "evil.com.pasteband.example"},
	}
	ids3 := ruleIDs(eng.Evaluate(4003, "", dnsRaw))
	if !containsStr(ids3, "e-dns") {
		t.Errorf("DNS 规则应命中，实际 %v", ids3)
	}
	// filter 命中 → not filter 使整条不命中
	dnsFiltered := map[string]any{
		"query": map[string]any{"hostname": "pastebin.blob.core.windows.net"},
	}
	if containsStr(ruleIDs(eng.Evaluate(4003, "", dnsFiltered)), "e-dns") {
		t.Error("filter 命中时应被排除")
	}
}

// product 按操作系统过滤：不匹配的 OS 事件被跳过，空串不限制。
func TestEvaluateOSFilter(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "lin.yml"), []byte(`
id: e-lin
logsource:
  product: linux
detection:
  selection:
    targetfilename|endswith: '.dll'
  condition: selection
`), 0o644)
	os.WriteFile(filepath.Join(dir, "any.yml"), []byte(`
id: e-any
logsource:
  category: process_creation
detection:
  selection:
    commandline|contains: 'x'
  condition: selection
`), 0o644)
	t.Cleanup(func() { os.RemoveAll("testdata") })

	eng := LoadDir(dir)
	dllRaw := map[string]any{"file": map[string]any{"path": "evil.dll"}}

	// os 匹配 → 命中
	if !containsStr(ruleIDs(eng.Evaluate(1007, "linux", dllRaw)), "e-lin") {
		t.Error("os=linux 时 product=linux 规则应命中")
	}
	// os 不匹配 → 跳过
	if containsStr(ruleIDs(eng.Evaluate(1007, "windows", dllRaw)), "e-lin") {
		t.Error("os=windows 时 product=linux 规则不应命中")
	}
	// os 未知（空串）→ 不限制，命中
	if !containsStr(ruleIDs(eng.Evaluate(1007, "", dllRaw)), "e-lin") {
		t.Error("os 空串时不应做 product 过滤")
	}
	// 无 product 的规则不受 os 限制
	proc := map[string]any{"process": map[string]any{"cmd_line": "px"}}
	if !containsStr(ruleIDs(eng.Evaluate(1007, "windows", proc)), "e-any") {
		t.Error("无 product 规则应在任意 os 命中")
	}
}

func ruleIDs(rules []*Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// --- LoadDirReport 统计与错误分类 ---

func TestLoadDirReport(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("good.yml", `
id: good
title: Good rule
logsource:
  category: process_creation
detection:
  selection:
    commandline|contains: x
  condition: selection
`)
	write("agg.yml", `
detection:
  condition: 'selection | count() > 3'
`)
	write("yaml.bad.yml", "id: [unclosed")
	write("noclass.yml", `
title: No logsource
detection:
  selection: {commandline|contains: x}
  condition: selection
`)
	write("emptylog.yml", `
id: el
logsource: {}
detection:
  selection: {commandline|contains: x}
  condition: selection
`)
	write("badproduct.yml", `
id: bp
logsource:
  product: zeek
detection:
  selection: {commandline|contains: x}
  condition: selection
`)
	write("README.md", "not a rule") // 非 yml 应忽略
	t.Cleanup(func() { os.RemoveAll("testdata") })

	_, report := LoadDirReport(dir)
	// Total 只数 yml/yaml，不数 README.md
	if report.Total != 6 {
		t.Errorf("Total = %d, want 6", report.Total)
	}
	// 只有 good 能加载（noclass 缺 logsource、emptylog/badproduct 不过关）
	if report.Loaded != 1 {
		t.Errorf("Loaded = %d, want 1", report.Loaded)
	}
	if report.ByClass[0] != 0 {
		t.Errorf("ByClass[0] = %d, want 0", report.ByClass[0])
	}
	if report.ByClass[1007] != 1 {
		t.Errorf("ByClass[1007] = %d, want 1", report.ByClass[1007])
	}
	// agg 统计型、yaml.bad YAML 解析失败
	if len(report.Skipped["暂不支持统计型条件"]) != 1 {
		t.Errorf("统计型规则未按类别统计，Skipped=%v", report.Skipped)
	}
	if len(report.Skipped["YAML 解析失败"]) != 1 {
		t.Errorf("YAML 错误未分类，Skipped=%v", report.Skipped)
	}
	// logsource 缺失与未限定、未知 product 各有分类
	if len(report.Skipped["缺少 logsource"]) != 1 {
		t.Errorf("缺 logsource 未分类，Skipped=%v", report.Skipped)
	}
	if len(report.Skipped["logsource 未限定 category 或 product"]) != 1 {
		t.Errorf("空 logsource 未分类，Skipped=%v", report.Skipped)
	}
	if len(report.Skipped["数据源未覆盖: product=zeek"]) != 1 {
		t.Errorf("未知 product 未分类，Skipped=%v", report.Skipped)
	}
}

func TestTitleOf(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "t.yml"), []byte(`
id: t-1
logsource:
  category: process_creation
title: My Title
detection:
  selection: {commandline|contains: x}
  condition: selection
`), 0o644)
	t.Cleanup(func() { os.RemoveAll("testdata") })

	eng := LoadDir(dir)
	if got := eng.TitleOf("t-1"); got != "My Title" {
		t.Errorf("TitleOf = %q, want %q", got, "My Title")
	}
	if got := eng.TitleOf("nope"); got != "" {
		t.Errorf("未知 ID 的 TitleOf 应为空，得到 %q", got)
	}
}
