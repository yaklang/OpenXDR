// Package sigma 实现 Sigma 规则引擎。启动时加载规则目录并编译，运行期对入库事件同步匹配。
//
// 支持：字段匹配与关键字列表、contains/startswith/endswith/re/all 修饰符、通配符、
// and/or/not 与括号、`x of them` / `all of selection_*` 聚合条件。
//
// 加载时严格拒绝三类规则，宁可少加载也不产生错误语义：
//   - 用了未实现的修饰符（cidr、base64 等）——静默当字符串处理会让
//     `condition: not selection` 的规则对每个事件误报
//   - logsource 指向我们不采集的数据源
//   - logsource 既无 category 又无 product，适用范围不受约束
package sigma

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// Sigma 标准字段名 -> OCSF raw 内的 dot path；未映射的字段名按 dot path 直接使用。
// 规则能加载不等于能命中，字段对不上就是空转，这张表决定实际检测能力。
var fieldMap = map[string]string{
	// 进程
	"image":             "process.file.path",
	"originalfilename":  "process.file.name",
	"commandline":       "process.cmd_line",
	"currentdirectory":  "process.working_directory",
	"processid":         "process.pid",
	"parentimage":       "process.parent_process.file.path",
	"parentcommandline": "process.parent_process.cmd_line",
	"parentprocessid":   "process.parent_process.pid",
	"integritylevel":    "process.integrity",
	// 身份
	"user":           "actor.user.name",
	"username":       "actor.user.name",
	"targetusername": "user.name",
	"logonid":        "actor.session.uid",
	// 文件
	"targetfilename": "file.path",
	"filename":       "file.path",
	"imageloaded":    "module.file.path",
	"hashes":         "file.hashes",
	"md5":            "file.md5",
	"sha256":         "file.sha256",
	// 网络
	"destinationip":       "dst_endpoint.ip",
	"destinationport":     "dst_endpoint.port",
	"destinationhostname": "dst_endpoint.hostname",
	"sourceip":            "src_endpoint.ip",
	"sourceport":          "src_endpoint.port",
	"initiated":           "connection_info.direction",
	"protocol":            "connection_info.protocol_name",
	// DNS / HTTP / TLS
	"query":       "query.hostname",
	"queryname":   "query.hostname",
	"c-uri":       "http_request.url.path",
	"cs-uri-stem": "http_request.url.path",
	"c-useragent": "http_request.user_agent",
	"useragent":   "http_request.user_agent",
	"c-host":      "http_request.hostname",
	"ja3":         "tls.ja3_hash",
}

// Sigma logsource category -> OCSF class。
// 映射存在不代表当前已采集该类遥测：规则会加载但在对应数据接入前不会命中。
var categoryMap = map[string]int{
	// 进程活动
	"process_creation":     1007,
	"process_access":       1007,
	"process_tampering":    1007,
	"create_remote_thread": 1007,
	// 文件系统活动
	"file_event":         1001,
	"file_change":        1001,
	"file_delete":        1001,
	"file_access":        1001,
	"file_rename":        1001,
	"create_stream_hash": 1001,
	// 模块加载
	"image_load":  1005,
	"driver_load": 1005,
	// 网络
	"network_connection": 4001,
	"dns_query":          4003,
	"dns":                4003,
	"proxy":              4002,
	"webserver":          4002,
	// 应用日志（syslog 接入）。OCSF 未定义通用日志类别，用私有段编号，
	// 与 internal/syslog.ClassApplicationActivity 保持一致
	"application": 100001,
	"antivirus":   100001,
}

// 当前采集端真正会产生的 OCSF class，用于区分"规则能加载"与"规则能命中"
var ingestedClasses = map[int]string{
	1001:   "文件活动（agent inotify）",
	1007:   "进程活动（agent）",
	4001:   "网络活动（sensor）",
	4003:   "DNS 活动（sensor）",
	100001: "应用日志（syslog）",
}

// IngestedClass 报告某个 class 是否有对应的采集来源。
func IngestedClass(classUID int) (string, bool) {
	name, ok := ingestedClasses[classUID]
	return name, ok
}

var levelMap = map[string]int16{
	"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
}

// Sigma 的 near/count 聚合语法要求跨事件统计，超出单事件匹配引擎的能力
var aggregateCond = regexp.MustCompile(`\|\s*(count|min|max|avg|sum|near)\b`)

type Rule struct {
	ID       string
	Title    string
	Severity int16
	ClassUID int    // 0 = 不限
	Product  string // logsource product，空表示不限操作系统
	// selection 按下标存放，condition 里的引用编译期就解析成下标
	sels []selection
	cond node
}

// 能对得上采集端的 logsource product。其余（zeek、aws、m365……）
// 是我们不接的数据源，加载了只会在不相干的事件上乱匹配。
var knownProducts = map[string]bool{
	"windows": true, "linux": true, "macos": true,
}

// selection 两种形态：字段匹配（map 列表是 OR，map 内字段是 AND），
// 或关键字列表（不限字段，在整条事件里搜，任一命中即可）。
type selection struct {
	branches [][]fieldTest
	keywords []matcher
}

func (s selection) matches(c *evalCtx) bool {
	if len(s.keywords) > 0 {
		flat := c.flattened()
		for _, kw := range s.keywords {
			if kw.match(flat, flat) {
				return true
			}
		}
		return false
	}
	for _, branch := range s.branches {
		ok := true
		for _, t := range branch {
			if !t.matches(c.raw) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// flatten 把事件里所有标量值拼成一个字符串，供关键字搜索。
// 关键字规则本就没有字段语义，拼串是最直接的实现。
func flatten(v any) string {
	var sb strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for _, child := range t {
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		case nil:
		case string:
			sb.WriteString(t)
			sb.WriteByte('\n')
		default:
			fmt.Fprintf(&sb, "%v\n", t)
		}
	}
	walk(v)
	return sb.String()
}

// matchKind 字面量匹配方式。Sigma 里绝大多数模式不含通配符，
// 走 strings 比编译正则快一个数量级，只有真需要时才回落到 regexp。
type matchKind uint8

const (
	matchExact matchKind = iota
	matchContains
	matchPrefix
	matchSuffix
	matchRegex
)

type matcher struct {
	kind    matchKind
	literal string // 已转小写，与同样转小写的取值比对
	re      *regexp.Regexp
}

// match 接收原值与其小写形式，小写只在 fieldTest 里算一次。
func (m matcher) match(value, lower string) bool {
	switch m.kind {
	case matchExact:
		return lower == m.literal
	case matchContains:
		return strings.Contains(lower, m.literal)
	case matchPrefix:
		return strings.HasPrefix(lower, m.literal)
	case matchSuffix:
		return strings.HasSuffix(lower, m.literal)
	default:
		return m.re.MatchString(value)
	}
}

// fieldTest：值列表是 OR（带 |all 修饰符时为 AND），expectNull 表示字段必须缺失。
type fieldTest struct {
	path       []string
	patterns   []matcher
	expectNull bool
	matchAll   bool
}

func (t fieldTest) matches(raw map[string]any) bool {
	value, ok := resolve(raw, t.path)
	if t.expectNull {
		return !ok
	}
	if !ok {
		return false
	}
	lower := strings.ToLower(value)
	for _, p := range t.patterns {
		if p.match(value, lower) {
			if !t.matchAll {
				return true
			}
		} else if t.matchAll {
			return false
		}
	}
	return t.matchAll
}

func resolve(raw map[string]any, path []string) (string, bool) {
	var current any = raw
	for _, part := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		if current, ok = m[part]; !ok {
			return "", false
		}
	}
	switch v := current.(type) {
	case nil:
		return "", false
	case string:
		return v, true
	default:
		return fmt.Sprint(v), true
	}
}

// engineState 一次加载的全部规则与索引。热重载时整体原子替换，
// Evaluate 拿到的永远是某个完整一致的版本，不加锁。
type engineState struct {
	rules []*Rule
	byID  map[string]*Rule
	// 按 OCSF class 分桶：一条网络事件没必要去碰一千多条进程规则
	byClass  map[int][]*Rule
	anyClass []*Rule // 未限定 class 的规则，对所有事件都要过
	maxSels  int     // 单条规则的最多 selection 数，决定 memo 缓冲大小
}

type Engine struct {
	state atomic.Pointer[engineState]
}

// 零值 Engine（测试常用）也要能安全求值
var emptyState = &engineState{byID: map[string]*Rule{}}

func (e *Engine) load() *engineState {
	if s := e.state.Load(); s != nil {
		return s
	}
	return emptyState
}

func (s *engineState) index() {
	s.byClass = map[int][]*Rule{}
	for _, r := range s.rules {
		if r.ClassUID == 0 {
			s.anyClass = append(s.anyClass, r)
		} else {
			s.byClass[r.ClassUID] = append(s.byClass[r.ClassUID], r)
		}
		if n := len(r.sels); n > s.maxSels {
			s.maxSels = n
		}
	}
}

// Report 加载结果统计。失败原因按类别聚合，用于衡量规则库兼容率。
type Report struct {
	Total   int
	Loaded  int
	ByClass map[int]int         // OCSF class -> 已加载规则数（0 表示不限 class）
	Skipped map[string][]string // 原因 -> 规则文件名
}

func LoadDir(dir string) *Engine {
	e, report := LoadDirReport(dir)
	slog.Info("Sigma 规则加载完成", "loaded", report.Loaded, "total", report.Total)
	for reason, files := range report.Skipped {
		slog.Warn("跳过规则", "reason", reason, "count", len(files))
	}
	return e
}

func LoadDirReport(dir string) (*Engine, Report) {
	s, report := loadState(dir)
	e := &Engine{}
	e.state.Store(s)
	return e, report
}

func loadState(dir string) (*engineState, Report) {
	s := &engineState{byID: map[string]*Rule{}}
	report := Report{ByClass: map[int]int{}, Skipped: map[string][]string{}}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := filepath.Ext(path); ext != ".yml" && ext != ".yaml" {
			return nil
		}
		report.Total++
		rule, err := compileFile(path)
		if err != nil {
			reason := classify(err)
			report.Skipped[reason] = append(report.Skipped[reason], filepath.Base(path))
			return nil
		}
		report.Loaded++
		report.ByClass[rule.ClassUID]++
		s.rules = append(s.rules, rule)
		if _, dup := s.byID[rule.ID]; !dup {
			s.byID[rule.ID] = rule
		}
		return nil
	})
	if err != nil {
		slog.Warn("Sigma 规则目录不可读", "dir", dir, "err", err)
	}
	s.index()
	return s, report
}

// Watch 周期扫描规则目录，文件集合或修改时间变化时整体重载并原子切换。
// 编译失败的规则照常跳过并记日志，不会让旧规则集失效——改坏一条规则
// 的代价是那一条不生效，而不是整个检测面归零。
func (e *Engine) Watch(ctx context.Context, dir string, interval time.Duration) {
	fingerprint := dirFingerprint(dir)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fp := dirFingerprint(dir)
			if fp == fingerprint {
				continue
			}
			fingerprint = fp
			s, report := loadState(dir)
			e.state.Store(s)
			slog.Info("Sigma 规则已热重载", "loaded", report.Loaded, "total", report.Total)
			for reason, files := range report.Skipped {
				slog.Warn("跳过规则", "reason", reason, "count", len(files), "files", files)
			}
		}
	}
}

// dirFingerprint 规则目录的变更指纹：全部规则文件的路径 + mtime + 大小。
func dirFingerprint(dir string) string {
	var sb strings.Builder
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yml" && ext != ".yaml" {
			return nil
		}
		if info, err := d.Info(); err == nil {
			fmt.Fprintf(&sb, "%s|%d|%d\n", path, info.ModTime().UnixNano(), info.Size())
		}
		return nil
	})
	return sb.String()
}

// classify 把具体错误归成可统计的类别，具体值（规则名、字段名）剥掉。
func classify(err error) string {
	msg := err.Error()
	for _, prefix := range []string{
		"暂不支持统计型条件", "暂不支持关键字列表 selection",
		"暂不支持的 selection 类型", "缺少 detection 段", "缺少 condition",
		"缺少 id 和 title", "condition 有多余 token", "condition 意外结束", "缺少右括号",
		"未知修饰符",
	} {
		if strings.Contains(msg, prefix) {
			return prefix
		}
	}
	if strings.Contains(msg, "yaml:") {
		return "YAML 解析失败"
	}
	if strings.Contains(msg, "error parsing regexp") {
		return "正则编译失败"
	}
	return msg
}

// Evaluate 匹配一条事件。os 是事件所属资产的操作系统（未知时传空串），
// 用于把 Windows 规则挡在 Linux 事件之外——反之亦然。
// 可并发调用：除按事件分配的 memo 外不持有可变状态。
func (e *Engine) Evaluate(classUID int, os string, raw map[string]any) []*Rule {
	s := e.load()
	ctx := evalCtx{raw: raw, memo: make([]int8, s.maxSels)}
	var hits []*Rule
	match := func(rules []*Rule) {
		for _, r := range rules {
			// 资产 OS 未知时不做限制，宁可多看一眼也别漏；已知就必须对得上
			if r.Product != "" && os != "" && r.Product != os {
				continue
			}
			ctx.sels = r.sels
			clear(ctx.memo[:len(r.sels)])
			if r.cond.eval(&ctx) {
				hits = append(hits, r)
			}
		}
	}
	match(s.byClass[classUID])
	match(s.anyClass)
	return hits
}

func (e *Engine) TitleOf(ruleID string) string {
	if r, ok := e.load().byID[ruleID]; ok {
		return r.Title
	}
	return ""
}

func compileFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	detection, ok := doc["detection"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("缺少 detection 段")
	}
	condText, ok := detection["condition"].(string)
	if !ok {
		return nil, fmt.Errorf("缺少 condition")
	}
	// 聚合统计（count() by ... > n）需要跨事件计数，本引擎是单事件匹配，不支持
	if aggregateCond.MatchString(condText) {
		return nil, fmt.Errorf("暂不支持统计型条件: %q", condText)
	}

	// 先建 selection 表，condition 才能把名字解析成下标。
	// 名字排序是为了让下标稳定，便于排查。
	names := make([]string, 0, len(detection))
	for name := range detection {
		if name != "condition" {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	sels := make([]selection, len(names))
	for i, name := range names {
		sel, err := compileSelection(detection[name])
		if err != nil {
			return nil, fmt.Errorf("selection %s: %w", name, err)
		}
		sels[i] = sel
	}

	cond, err := parseCondition(condText, names)
	if err != nil {
		return nil, err
	}

	rule := &Rule{Severity: 3, sels: sels, cond: cond}
	if id, ok := doc["id"].(string); ok {
		rule.ID = id
	}
	if title, ok := doc["title"].(string); ok {
		rule.Title = title
	}
	if rule.ID == "" {
		if rule.Title == "" {
			return nil, fmt.Errorf("缺少 id 和 title")
		}
		rule.ID = rule.Title
	}
	if level, ok := doc["level"].(string); ok {
		if sev, ok := levelMap[strings.ToLower(level)]; ok {
			rule.Severity = sev
		}
	}
	ls, _ := doc["logsource"].(map[string]any)
	if ls == nil {
		return nil, fmt.Errorf("缺少 logsource")
	}
	if cat, ok := ls["category"].(string); ok {
		uid, ok := categoryMap[strings.ToLower(cat)]
		if !ok {
			return nil, fmt.Errorf("数据源未覆盖: %s", cat)
		}
		rule.ClassUID = uid
	}
	if product, ok := ls["product"].(string); ok {
		product = strings.ToLower(product)
		if !knownProducts[product] {
			return nil, fmt.Errorf("数据源未覆盖: product=%s", product)
		}
		rule.Product = product
	}
	// 既无 category 又无 product 的规则没有任何适用范围约束，
	// 会对所有事件求值，误报风险不可控
	if rule.ClassUID == 0 && rule.Product == "" {
		return nil, fmt.Errorf("logsource 未限定 category 或 product")
	}
	return rule, nil
}

func compileSelection(value any) (selection, error) {
	switch v := value.(type) {
	case map[string]any:
		branch, err := compileBranch(v)
		if err != nil {
			return selection{}, err
		}
		return selection{branches: [][]fieldTest{branch}}, nil

	case []any:
		var sel selection
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				branch, err := compileBranch(m)
				if err != nil {
					return selection{}, err
				}
				sel.branches = append(sel.branches, branch)
				continue
			}
			// 标量元素即关键字，不限字段全文匹配
			kw, err := buildMatcher(fmt.Sprint(item), map[string]bool{"contains": true})
			if err != nil {
				return selection{}, err
			}
			sel.keywords = append(sel.keywords, kw)
		}
		return sel, nil

	case string:
		kw, err := buildMatcher(v, map[string]bool{"contains": true})
		if err != nil {
			return selection{}, err
		}
		return selection{keywords: []matcher{kw}}, nil

	default:
		return selection{}, fmt.Errorf("暂不支持的 selection 类型 %T", value)
	}
}

func compileBranch(m map[string]any) ([]fieldTest, error) {
	var branch []fieldTest
	for key, value := range m {
		t, err := compileFieldTest(key, value)
		if err != nil {
			return nil, err
		}
		branch = append(branch, t)
	}
	return branch, nil
}

func compileFieldTest(key string, value any) (fieldTest, error) {
	parts := strings.Split(key, "|")
	field := parts[0]
	mods := map[string]bool{}
	for _, m := range parts[1:] {
		m = strings.ToLower(m)
		if !knownModifiers[m] {
			return fieldTest{}, fmt.Errorf("未知修饰符: %s", m)
		}
		mods[m] = true
	}

	path := field
	if mapped, ok := fieldMap[strings.ToLower(field)]; ok {
		path = mapped
	}
	t := fieldTest{path: strings.Split(path, "."), matchAll: mods["all"]}

	if value == nil {
		t.expectNull = true
		return t, nil
	}
	values, ok := value.([]any)
	if !ok {
		values = []any{value}
	}
	for _, v := range values {
		p, err := buildMatcher(fmt.Sprint(v), mods)
		if err != nil {
			return fieldTest{}, err
		}
		t.patterns = append(t.patterns, p)
	}
	return t, nil
}

// 本引擎实现的修饰符。未列出的一律拒绝加载——
// 静默当成普通字符串会让语义反转：cidr/base64 之类匹配不上，
// 而 `condition: not selection` 的规则就会对每个事件误报。
var knownModifiers = map[string]bool{
	"contains": true, "startswith": true, "endswith": true, "re": true, "all": true,
}

func buildMatcher(value string, mods map[string]bool) (matcher, error) {
	if mods["re"] {
		re, err := regexp.Compile("(?i)" + value)
		return matcher{kind: matchRegex, re: re}, err
	}

	// 无通配符时不用正则。大小写不敏感是 Sigma 默认语义，字面量提前转小写
	if !strings.ContainsAny(value, "*?") {
		kind := matchExact
		switch {
		case mods["contains"]:
			kind = matchContains
		case mods["startswith"]:
			kind = matchPrefix
		case mods["endswith"]:
			kind = matchSuffix
		}
		return matcher{kind: kind, literal: strings.ToLower(value)}, nil
	}

	// Sigma 通配符 * ? -> 正则；修饰符决定锚点
	escaped := regexp.QuoteMeta(value)
	escaped = strings.ReplaceAll(escaped, `\*`, `.*`)
	escaped = strings.ReplaceAll(escaped, `\?`, `.`)
	switch {
	case mods["contains"]:
	case mods["startswith"]:
		escaped = "^" + escaped
	case mods["endswith"]:
		escaped += "$"
	default:
		escaped = "^" + escaped + "$"
	}
	re, err := regexp.Compile("(?i)" + escaped)
	return matcher{kind: matchRegex, re: re}, err
}
