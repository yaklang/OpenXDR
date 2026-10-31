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
	"crypto/sha256"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
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
	// 注册表
	"targetobject": "reg_key.path",
	"details":      "reg_value.data",
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
	// 注册表（OCSF Windows 扩展：Registry Value Activity）
	"registry_set":    201002,
	"registry_add":    201002,
	"registry_event":  201002,
	"registry_delete": 201002,
	// 网络
	"network_connection": 4001,
	"dns_query":          4003,
	"dns":                4003,
	"proxy":              4002,
	"webserver":          4002,
	// 应用日志（syslog 接入）。OCSF 未定义通用日志类别，用私有段编号，
	// 与 internal/syslog.ClassApplicationActivity 保持一致
	// 认证
	"authentication": 3002,
	"application":    100001,
	"antivirus":      100001,
}

// 当前采集端真正会产生的 OCSF class，用于区分"规则能加载"与"规则能命中"
var ingestedClasses = map[int]string{
	1001:   "文件活动（agent）",
	1005:   "模块加载（agent）",
	1007:   "进程活动（agent）",
	3002:   "认证活动（agent）",
	201002: "注册表变更（agent）",
	4001:   "网络活动（sensor/agent）",
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

// Catalog 是检测与展示共用的当前规则视图。
type Catalog interface {
	Evaluate(int, string, map[string]any) []*Rule
	Rules() []*Rule
	TitleOf(string) string
	AuthorOf(string) string
}

type Rule struct {
	Kind          string
	WindowSeconds int
	Threshold     int
	References    []string
	source        string
	digest        string // 编译时读取的原文哈希，避免版本指纹与加载内容发生竞态
	ID            string
	Title         string
	// Author 规则作者。社区规则（DRL 1.1）要求基于命中产生的消息保留作者，告警、规则页与通知都带上
	Author   string
	Severity int16
	ClassUID int    // 0 = 不限
	Product  string // logsource product，空表示不限操作系统
	// Signal 信号规则（openxdr_signal: true）：只作时序规则的输入，命中不单独产生告警。
	// Evaluate 不返回它，只有 EvaluateSignals 返回，未启用时序检测时完全不生效。
	Signal bool
	// ATT&CK 标签，来自 Sigma tags。不影响匹配，用于覆盖矩阵
	Tactics    []string
	Techniques []string
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
			if !t.matchesContext(c) {
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
	matchCIDR
)

type matcher struct {
	kind    matchKind
	literal string // 已转小写，与同样转小写的取值比对
	re      *regexp.Regexp
	prefix  netip.Prefix
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
	case matchCIDR:
		addr, err := netip.ParseAddr(value)
		return err == nil && m.prefix.Contains(addr.Unmap())
	default:
		return m.re.MatchString(value)
	}
}

// fieldTest：值列表是 OR（带 |all 修饰符时为 AND），expectNull 表示字段必须缺失。
type fieldTest struct {
	path       []string
	cacheIndex int
	patterns   []matcher
	expectNull bool
	matchAll   bool
}

func (t fieldTest) matches(raw map[string]any) bool {
	value, ok := resolve(raw, t.path)
	return t.matchesValue(value, strings.ToLower(value), ok)
}

func (t fieldTest) matchesValue(value, lower string, ok bool) bool {
	if t.expectNull {
		return !ok
	}
	if !ok {
		return false
	}
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

func (t fieldTest) matchesContext(c *evalCtx) bool {
	// 零值表示尚未经过规则集索引，独立 selection 继续走原始匹配。
	if t.cacheIndex == 0 || t.cacheIndex > len(c.fields) {
		return t.matches(c.raw)
	}
	field := &c.fields[t.cacheIndex-1]
	if !field.loaded {
		field.value, field.present = resolve(c.raw, t.path)
		if field.present {
			field.lower = strings.ToLower(field.value)
		}
		field.loaded = true
	}
	return t.matchesValue(field.value, field.lower, field.present)
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
	byClass    map[int][]*Rule
	anyClass   []*Rule   // 未限定 class 的规则，对所有事件都要过
	maxSels    int       // 单条规则的最多 selection 数，决定 memo 缓冲大小
	fieldCount int       // 所有规则共享字段路径的数量，用于按事件缓存解析结果
	contexts   sync.Pool // 当前规则快照的求值缓冲，并发调用各自独占
}

type Engine struct {
	state       atomic.Pointer[engineState]
	fingerprint atomic.Pointer[string]
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
	fieldIndices := map[string]int{}
	for _, r := range s.rules {
		if r.ClassUID == 0 {
			s.anyClass = append(s.anyClass, r)
		} else {
			s.byClass[r.ClassUID] = append(s.byClass[r.ClassUID], r)
		}
		if n := len(r.sels); n > s.maxSels {
			s.maxSels = n
		}
		for i := range r.sels {
			for j := range r.sels[i].branches {
				for k := range r.sels[i].branches[j] {
					t := &r.sels[i].branches[j][k]
					key := strings.Join(t.path, ".")
					index, ok := fieldIndices[key]
					if !ok {
						index = len(fieldIndices) + 1
						fieldIndices[key] = index
					}
					t.cacheIndex = index
				}
			}
		}
	}
	s.fieldCount = len(fieldIndices)
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
	fingerprint := dirFingerprint(dir)
	s, report := loadState(dir)
	e := &Engine{}
	e.state.Store(s)
	e.fingerprint.Store(&fingerprint)
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
		report.Skipped["规则目录读取失败"] = append(report.Skipped["规则目录读取失败"], err.Error())
	}
	s.index()
	return s, report
}

// Watch 周期扫描规则目录，文件集合或修改时间变化时整体重载并原子切换。
// 编译失败的规则照常跳过并记日志，不会让旧规则集失效——改坏一条规则
// 的代价是那一条不生效，而不是整个检测面归零。
func (e *Engine) Watch(ctx context.Context, dir string, interval time.Duration) {
	fingerprint := ""
	if loaded := e.fingerprint.Load(); loaded != nil {
		fingerprint = *loaded
	}
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
			loadedFingerprint := fingerprint
			e.fingerprint.Store(&loadedFingerprint)
			slog.Info("Sigma 规则已热重载", "loaded", report.Loaded, "total", report.Total)
			for reason, files := range report.Skipped {
				slog.Warn("跳过规则", "reason", reason, "count", len(files), "files", files)
			}
		}
	}
}

// dirFingerprint 规则目录的变更指纹：全部规则文件的路径 + 内容。
// 不能只看 mtime/大小：原子替换、网络文件系统或快速连续写入可能保留相同元数据，
// 这正是热重载偶发不及时的根因。规则库很小，周期读取内容比漏重载更划算。
func dirFingerprint(dir string) string {
	h := sha256.New()
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yml" && ext != ".yaml" {
			return nil
		}
		fmt.Fprintf(h, "%s\x00", path)
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			fmt.Fprintf(h, "error:%v\x00", readErr)
			return nil
		}
		_, _ = h.Write(body)
		_, _ = h.Write([]byte{0})
		return nil
	})
	return fmt.Sprintf("%x", h.Sum(nil))
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

// Evaluate 匹配一条事件，只返回会产生告警的规则，信号规则不在其中。os 是事件所属资产的操作系统（未知时传空串），
// 用于把 Windows 规则挡在 Linux 事件之外——反之亦然。
// 可并发调用：每次独占求值缓冲，结束时清掉事件引用再归还。
func (e *Engine) Evaluate(classUID int, os string, raw map[string]any) []*Rule {
	return e.evaluate(classUID, os, raw, false)
}

// EvaluateSignals 只匹配信号规则，供时序候选使用；命中不得用来产生告警。
func (e *Engine) EvaluateSignals(classUID int, os string, raw map[string]any) []*Rule {
	return e.evaluate(classUID, os, raw, true)
}

func (e *Engine) evaluate(classUID int, os string, raw map[string]any, signal bool) []*Rule {
	s := e.load()
	ctx, _ := s.contexts.Get().(*evalCtx)
	if ctx == nil {
		ctx = &evalCtx{memo: make([]int8, s.maxSels), fields: make([]fieldValue, s.fieldCount)}
	}
	ctx.raw = raw
	defer func() {
		ctx.raw, ctx.sels = nil, nil
		ctx.flat, ctx.flatDone = "", false
		clear(ctx.fields)
		s.contexts.Put(ctx)
	}()
	var hits []*Rule
	match := func(rules []*Rule) {
		for _, r := range rules {
			if r.Signal != signal {
				continue
			}
			// 资产 OS 未知时不做限制，宁可多看一眼也别漏；已知就必须对得上
			if r.Product != "" && os != "" && r.Product != os {
				continue
			}
			ctx.sels = r.sels
			clear(ctx.memo[:len(r.sels)])
			if r.cond.eval(ctx) {
				hits = append(hits, r)
			}
		}
	}
	match(s.byClass[classUID])
	match(s.anyClass)
	return hits
}

// Rules 当前加载的全部规则。返回的切片属于某个不可变状态版本，只读。
func (e *Engine) Rules() []*Rule {
	return e.load().rules
}

// Matches 对单条事件独立求值，供控制台规则回测使用。
// 跨事件时序规则（Kind 非空）无单事件条件树，直接返回 false。
func (r *Rule) Matches(classUID int, os string, raw map[string]any) bool {
	if r == nil || r.cond == nil || r.Kind != "" {
		return false
	}
	if r.ClassUID != 0 && r.ClassUID != classUID {
		return false
	}
	if r.Product != "" && os != "" && r.Product != os {
		return false
	}
	ctx := &evalCtx{
		raw:  raw,
		sels: r.sels,
		memo: make([]int8, len(r.sels)),
	}
	return r.cond.eval(ctx)
}

// RuleBruteforceSuccess 爆破得手合成检测：多次登录失败后同用户登录成功。
// 跨事件计数超出单事件匹配引擎的能力，逻辑在 ingest 侧实现，标题在此登记。
const RuleBruteforceSuccess = "xdr:bruteforce-success"

// RuleNewProcess UEBA 合成检测：学习期满的资产上首次出现的可执行文件。
const RuleNewProcess = "xdr:new-process"

// RuleBeacon 外联心跳合成检测：学习期满的资产上新出现的规律公网外联，逻辑在 internal/beacon
const RuleBeacon = "xdr:beacon"

var syntheticTitles = map[string]string{
	RuleBruteforceSuccess: "Brute Force Success (多次失败后登录成功)",
	RuleNewProcess:        "New Process First Seen (新进程首次出现)",
	RuleBeacon:            "Periodic Beacon to New Destination (新出现的周期外联)",
}

// AuthorOf 规则作者，没有写或规则已不在返回空
func (e *Engine) AuthorOf(ruleID string) string {
	if r, ok := e.load().byID[ruleID]; ok {
		return r.Author
	}
	return ""
}

func (e *Engine) TitleOf(ruleID string) string {
	if r, ok := e.load().byID[ruleID]; ok {
		return r.Title
	}
	if title := syntheticTitles[ruleID]; title != "" {
		return title
	}
	return intelTitle(ruleID)
}

// intelTitle 情报命中的告警规则 ID 是 intel:<类别>:<值>（intel.Store），没有规则文件可查标题；
// 给出可读的标题，事件标题、Top 规则与告警列表不再露出内部 ID
func intelTitle(ruleID string) string {
	kind, value, ok := strings.Cut(strings.TrimPrefix(ruleID, "intel:"), ":")
	if !ok || !strings.HasPrefix(ruleID, "intel:") || value == "" {
		return ""
	}
	label := map[string]string{"ip": "IP", "domain": "Domain", "hash": "File Hash"}[kind]
	if label == "" {
		return ""
	}
	return fmt.Sprintf("Threat Intel Match: %s %s (威胁情报命中)", label, value)
}

func compileFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Compile(data)
}

// Compile 编译一条规则文本。规则目录里的文件逐个过这里，
// 编译不过的规则拒绝加载，不会出现"看起来在跑"的规则。
func Compile(data []byte) (*Rule, error) {
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

	rule := &Rule{source: string(data), Severity: 3, sels: sels, cond: cond, digest: fmt.Sprintf("%x", sha256.Sum256(data))}
	if id, ok := doc["id"].(string); ok {
		rule.ID = id
	}
	if title, ok := doc["title"].(string); ok {
		rule.Title = title
	}
	if author, ok := doc["author"].(string); ok {
		rule.Author = strings.TrimSpace(author)
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
	// openxdr_signal 是 OpenXDR 自有扩展字段（Sigma 允许自定义顶层字段，SigmaHQ 规则不会带）。
	// 只接受 true，且级别必须是 informational：拿不准的写法拒绝加载，不猜它该不该告警
	if v, ok := doc["openxdr_signal"]; ok {
		if v != true {
			return nil, fmt.Errorf("openxdr_signal 只能写 true")
		}
		if level, _ := doc["level"].(string); level != "informational" {
			return nil, fmt.Errorf("信号规则的 level 必须为 informational")
		}
		rule.Signal = true
	}
	rule.Tactics, rule.Techniques = parseAttackTags(doc["tags"])
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
	translate := valueMap[strings.ToLower(field)]
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
		text := fmt.Sprint(v)
		if mapped, ok := translate[strings.ToLower(text)]; ok {
			text = mapped
		}
		variants := []string{text}
		if mods["windash"] {
			variants = windash(text)
		}
		for _, variant := range variants {
			p, err := buildMatcher(variant, mods)
			if err != nil {
				return fieldTest{}, err
			}
			t.patterns = append(t.patterns, p)
		}
	}
	return t, nil
}

// 字段取值的约定也要对齐：Sigma 的 Initiated 是 true（本机发起）/ false，事件里是 outbound / inbound
var valueMap = map[string]map[string]string{
	"initiated": {"true": "outbound", "false": "inbound"},
}

// WithActor 用户名在事件信封上（事件表的 username 列），Sigma 的 User 字段按 actor.user.name 取：
// 求值前补进去，事件体里已有的不覆盖，入库的原始事件不改
func WithActor(raw map[string]any, username string) {
	if username == "" {
		return
	}
	if _, ok := raw["actor"]; !ok {
		raw["actor"] = map[string]any{"user": map[string]any{"name": username}}
	}
}

// 本引擎实现的修饰符。未列出的一律拒绝加载——
// 静默当成普通字符串会让语义反转：cidr/base64 之类匹配不上，
// 而 `condition: not selection` 的规则就会对每个事件误报。
var knownModifiers = map[string]bool{
	"contains": true, "startswith": true, "endswith": true, "re": true, "all": true,
	"cidr": true, "windash": true,
	// 正则标志：本引擎的正则本来就不区分大小写，i 无需处理；m、s 照常生效
	"i": true, "m": true, "s": true,
}

// windashChars Windows 命令行参数的前缀可以写成 - 或 /，还有人用各种长破折号绕过检测
var windashChars = []string{"-", "/", "–", "—", "―"}

var windashFlag = regexp.MustCompile(`(^|\s)[-/]`)

// windash 把参数前缀（开头或空白之后的 - 或 /）换成每一种写法各生成一个变体
func windash(value string) []string {
	out := make([]string, 0, len(windashChars))
	for _, c := range windashChars {
		v := windashFlag.ReplaceAllString(value, "${1}"+c)
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func buildMatcher(value string, mods map[string]bool) (matcher, error) {
	if mods["cidr"] {
		prefix, err := netip.ParsePrefix(value)
		return matcher{kind: matchCIDR, prefix: prefix.Masked()}, err
	}
	if mods["re"] {
		flags := "(?i"
		for _, f := range []string{"m", "s"} {
			if mods[f] {
				flags += f
			}
		}
		re, err := regexp.Compile(flags + ")" + value)
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
