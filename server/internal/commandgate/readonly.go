package commandgate

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

// ReadOnly 判断一条经 sh -c 执行的 Linux 命令是否只读：定时任务半夜没人审批，
// 名单误伤的只读巡检命令（grep 模式里的 kill、stat /etc/shadow 的时间戳）由它放行。
// 只认得出就放行，认不出一律当成非只读交给人：命令替换、sh -c、eval、xargs、find -exec、
// awk 的 system()、写文件的重定向、不在清单里的程序都不放行；提到密钥文件时只许看元数据。
func ReadOnly(cmd string) bool {
	return readOnly(cmd, false)
}

// readOnly nested 表示 cmd 是命令替换里的命令：外层给变量赋的值看不到，没赋值的变量不能当空串
func readOnly(cmd string, nested bool) bool {
	segments, ok := split(cmd)
	if !ok || len(segments) == 0 {
		return false
	}
	vars := collectVars(cmd, segments, nested)
	// 密钥路径或敏感文件名出现在 for 列表、变量赋值或输入重定向里，可能经变量或标准输入传给别的段：整条命令都只许看元数据
	strict := false
	for _, seg := range segments {
		if program, _, _ := command(seg.words); (program == "" || seg.input) && segmentMentionsSecret(seg, true) {
			strict = true
		}
	}
	for _, seg := range segments {
		program, args, ok := command(seg.words)
		if !ok {
			return false
		}
		if program == "" {
			continue
		}
		if !metadataOnly[program] && (strict || segmentMentionsSecret(seg, false) || segmentUnsafeDynamicSecret(program, seg, vars)) {
			return false
		}
		// 容器里执行的命令按同一份清单判定；shell 会展开的段，判定看到的和容器里真跑的可能不是一回事
		if inner, ok := containerExec(program, args); ok {
			if seg.dynamic || !argvReadOnly(inner) {
				return false
			}
			continue
		}
		check, known := readOnlyPrograms[program]
		if !known {
			return false
		}
		if check != nil {
			argMetas := seg.wordMetas[len(seg.words)-len(args):]
			if !checkArgsWithVars(program, check, args, argMetas, vars) {
				return false
			}
		}
	}
	return true
}

// containerExec 仅拆出 pct exec <ID> -- 命令。
func containerExec(program string, args []string) ([]string, bool) {
	switch {
	case program == "pct" && len(args) >= 4 && args[0] == "exec" && vmid.MatchString(args[1]) && args[2] == "--":
		return args[3:], true
	}
	return nil, false
}

var vmid = regexp.MustCompile(`^[0-9]+$`)

// argvReadOnly 不经 shell 直接执行的参数表：sh -c 只认恰好一个脚本参数，脚本按 shell 命令递归判定
func argvReadOnly(words []string) bool {
	if len(words) == 3 && (words[0] == "sh" || words[0] == "bash" || words[0] == "/bin/sh" || words[0] == "/bin/bash") && words[1] == "-c" {
		return ReadOnly(words[2])
	}
	program, args, ok := command(words)
	if !ok || program == "" {
		return false
	}
	if !metadataOnly[program] {
		for _, w := range args {
			if matchesSecretPath(w) {
				return false
			}
		}
	}
	if inner, ok := containerExec(program, args); ok {
		return argvReadOnly(inner)
	}
	check, known := readOnlyPrograms[program]
	return known && (check == nil || check(args))
}

// wordMeta 记录段内每个词的动态展开属性（与 segment.words 一一对应）。
type wordMeta struct {
	dynamic         bool // 词内包含未转义的变量展开（$...）或命令替换（$(...)）
	unquotedDynamic bool // 动态展开出现在双引号之外，shell 会对展开结果做分词
}

// segment 一个命令段：去掉引号后的词、输入重定向目标、含未转义变量展开的词、引号外含通配符的词、
// 原文（密钥路径按原文找，含重定向目标）、是否有输入重定向、
// 单引号外是否出现 $ 或反斜杠（shell 会展开或转义，去引号后的词和真正传给程序的参数可能不同）
type segment struct {
	words     []string
	wordMetas []wordMeta
	inputs    []string
	varWords  []string
	globWords []string
	raw       string
	input     bool
	dynamic   bool
}

// secretPath 与默认名单的读密钥条目同一范围，宽一点无妨：命中后只许 ls / stat 这类看元数据的命令
var (
	secretPath    = regexp.MustCompile(`/(?:etc|var/backups)/g?shadow|\bid_(?:rsa|dsa|ecdsa|ed25519)|ssh_host_\w*key`)
	secretKeyword = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])(?:g?shadow|id_(?:rsa|dsa|ecdsa|ed25519)|ssh_host_\w*key)(?:$|[^a-z0-9_])`)
)

// fileReaders 会直接读文件内容输出到标准输出的程序：不许经动态变量传未知路径绕过密钥路径检查
var fileReaders = map[string]bool{
	"cat": true, "tac": true, "head": true, "tail": true, "grep": true, "egrep": true, "fgrep": true,
	"zgrep": true, "zcat": true, "wc": true, "cut": true, "tr": true, "column": true, "nl": true,
	"comm": true, "paste": true, "rev": true, "strings": true, "cmp": true, "diff": true,
	"md5sum": true, "sha1sum": true, "sha256sum": true, "jq": true, "awk": true, "gawk": true,
	"mawk": true, "sed": true, "sort": true, "uniq": true, "file": true,
}

func matchesSecretPath(w string) bool {
	check := func(s string) bool {
		if secretPath.MatchString(s) {
			return true
		}
		// agent 的 cwd 是 /：etc/shadow、../etc/shadow 都是 /etc/shadow
		return strings.Contains(s, "/") && secretPath.MatchString(path.Join("/", s))
	}
	if check(w) {
		return true
	}
	if _, rhs, ok := strings.Cut(w, "="); ok && rhs != "" {
		return check(rhs)
	}
	return false
}

func segmentMentionsSecret(seg segment, includeKeywords bool) bool {
	if secretPath.MatchString(seg.raw) {
		return true
	}
	for _, w := range seg.words {
		if matchesSecretPath(w) || (includeKeywords && secretKeyword.MatchString(w)) {
			return true
		}
	}
	for _, w := range seg.inputs {
		if matchesSecretPath(w) || (includeKeywords && secretKeyword.MatchString(w)) {
			return true
		}
	}
	return false
}

func looksLikeSensitiveDynamic(w string) bool {
	lower := strings.ToLower(w)
	if strings.Contains(lower, "/etc") || strings.Contains(lower, ".ssh") ||
		strings.Contains(lower, "shadow") || strings.Contains(lower, "ssh_host") ||
		strings.Contains(lower, "id_") {
		return true
	}
	// 根目录通配如 /*/shadow 或 /e*/shadow
	return strings.HasPrefix(lower, "/*") || strings.HasPrefix(lower, "/?") || strings.HasPrefix(lower, "/[")
}

// segmentUnsafeDynamicSecret 变量与通配展开后可能读到密钥。读内容的程序按展开结果精确判定：恰好是一个变量的词
// 按它可能的取值判定，认不出取值的变量不收，通配词按 globMayReadSecret；其余程序（du、find 只看元数据或名字）沿用按字面猜
func segmentUnsafeDynamicSecret(program string, seg segment, vars shellVars) bool {
	if !fileReaders[program] {
		return slices.ContainsFunc(seg.varWords, looksLikeSensitiveDynamic) || slices.ContainsFunc(seg.globWords, looksLikeSensitiveDynamic)
	}
	for _, w := range seg.varWords {
		values, ok := vars.lookup(w)
		if !ok || slices.ContainsFunc(values, valueMayReadSecret) {
			return true
		}
	}
	return slices.ContainsFunc(seg.globWords, globMayReadSecret)
}

// secretSuffixes 密钥文件路径的末几级，空串表示任意名字：.ssh 目录下的任何文件都算。
// 只比末几级，/proc/1/root/etc/shadow、容器 rootfs 里的 etc/shadow 一样认得出
var secretSuffixes = [][]string{
	{"etc", "shadow"}, {"etc", "shadow-"}, {"etc", "gshadow"}, {"etc", "gshadow-"},
	{"backups", "shadow.bak"}, {"backups", "gshadow.bak"},
	{"id_rsa"}, {"id_dsa"}, {"id_ecdsa"}, {"id_ed25519"},
	{"ssh_host_rsa_key"}, {"ssh_host_dsa_key"}, {"ssh_host_ecdsa_key"}, {"ssh_host_ed25519_key"},
	{".ssh", ""},
}

// globMayReadSecret 通配词展开后可能命中密钥文件：按 cwd=/ 补成绝对路径，逐个比对 secretSuffixes。
// 判定标准是“展开结果里可能有密钥文件就不放行”：/etc/*.conf、/var/log/*.log 放行，/etc/*、/tmp/* 可能展开出 shadow、id_rsa，不放行。
// 花括号展开（sh 是 bash 时生效）和 ~ 不做比对，一律当成可能命中
func globMayReadSecret(w string) bool {
	if strings.ContainsAny(w, "{~") {
		return true
	}
	parts := strings.Split(path.Join("/", w), "/")
	return slices.ContainsFunc(secretSuffixes, func(suffix []string) bool {
		if len(parts) < len(suffix) {
			return false
		}
		tail := parts[len(parts)-len(suffix):]
		for i, name := range suffix {
			// 模式写错的也当成可能命中
			if ok, err := path.Match(tail[i], name); name != "" && !ok && err == nil {
				return false
			}
		}
		return true
	})
}

// valueMayReadSecret 变量的一个取值：不加引号展开时按空白切开，每一段再当路径或通配词判定
func valueMayReadSecret(v string) bool {
	return matchesSecretPath(v) || slices.ContainsFunc(strings.Fields(v), func(f string) bool {
		return matchesSecretPath(f) || globMayReadSecret(f)
	})
}

// shellVars 命令里给变量赋过的值：for 列表、静态赋值。取值来自 read、printf -v、命令替换或别的变量的，记为认不出
type shellVars struct {
	values  map[string][]string
	unknown map[string]bool
	nested  bool
	off     bool
}

var (
	simpleVar   = regexp.MustCompile(`^\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})$`)
	simpleBrace = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`)
	localName   = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
)

func collectVars(cmd string, segments []segment, nested bool) shellVars {
	vars := shellVars{values: map[string][]string{}, unknown: map[string]bool{}, nested: nested}
	// ${f:=/etc/shadow} 这类带赋值、带替换的参数展开不去理解，整条命令都不认变量取值
	vars.off = strings.Count(cmd, "${") != len(simpleBrace.FindAllString(cmd, -1))
	for _, seg := range segments {
		vars.collect(seg.words)
	}
	// 修改 IFS 会改变未加引号变量展开的分词规则，整条命令不再信任静态变量展开
	if _, ok := vars.values["IFS"]; ok || vars.unknown["IFS"] {
		vars.off = true
	}
	return vars
}

func (v *shellVars) collect(words []string) {
	for len(words) > 0 {
		switch w := words[0]; {
		case slices.Contains([]string{"!", "if", "then", "else", "elif", "do", "while", "until", "time"}, w):
			words = words[1:]
		case w == "for":
			if len(words) >= 3 && words[2] == "in" {
				v.assign(words[1], words[3:])
			} else if len(words) >= 2 {
				v.unknown[words[1]] = true // 不带 in 的 for 遍历位置参数
			}
			return
		case assignment.MatchString(w):
			name, value, _ := strings.Cut(w, "=")
			v.assign(name, []string{value})
			words = words[1:]
		case w == "read":
			v.unknown["REPLY"] = true
			for _, a := range words[1:] {
				v.unknown[a] = true
			}
			return
		default:
			// printf -v 给变量赋值，不去理解它赋了什么
			v.off = v.off || (w == "printf" && slices.ContainsFunc(words[1:], func(a string) bool { return strings.HasPrefix(a, "-v") }))
			return
		}
	}
}

func (v *shellVars) assign(name string, values []string) {
	for _, value := range values {
		if strings.Contains(value, "$") {
			v.unknown[name] = true
		}
	}
	v.values[name] = append(v.values[name], values...)
}

// lookup 词恰好是一个变量时给出它可能的取值。sh -c 起的新 shell 里，小写变量没在命令里赋值就是空串
// （环境变量按惯例大写）；大写变量、位置参数和命令替换里没赋值的变量都认不出
func (v shellVars) lookup(w string) ([]string, bool) {
	m := simpleVar.FindStringSubmatch(w)
	if m == nil || v.off {
		return nil, false
	}
	name := m[1] + m[2]
	if v.unknown[name] {
		return nil, false
	}
	if values, ok := v.values[name]; ok {
		return values, true
	}
	return []string{""}, !v.nested && localName.MatchString(name)
}

// maxExpandedCombos 变量笛卡尔展开的组合数上限，超过一律拒绝（交给人审批）。
const maxExpandedCombos = 64

// checkArgsWithVars 在把参数交给目标程序只读检查器之前，展开所有动态参数并逐组合校验：
//  1. 已知取值的单变量引用按全部可能取值展开（未加引号的按空白分词），任一组合不通过即拒绝；
//  2. 无法经 vars.lookup 解析的动态词（未知环境变量、复合展开如 $a$b、命令替换等），
//     除极少数已严格证明处于安全数据位置的形态外一律拒绝，防止展开为危险选项或写子命令。
func checkArgsWithVars(program string, check func([]string) bool, args []string, metas []wordMeta, vars shellVars) bool {
	if len(args) != len(metas) {
		return false
	}
	hasDynamic := false
	for _, m := range metas {
		if m.dynamic {
			hasDynamic = true
			break
		}
	}
	if !hasDynamic {
		return check(args)
	}
	choices := make([][][]string, len(args))
	total := 1
	for i, a := range args {
		if !metas[i].dynamic {
			choices[i] = [][]string{{a}}
			continue
		}
		values, ok := vars.lookup(a)
		if !ok {
			if !safeUnknownDynamicArg(program, args, metas, i, vars.nested) {
				return false
			}
			choices[i] = [][]string{{"__safe_dynamic_arg__"}}
			continue
		}
		expanded := expandVarChoices(values, metas[i].unquotedDynamic)
		choices[i] = expanded
		if len(expanded) > 1 {
			if total > maxExpandedCombos/len(expanded) {
				return false
			}
			total *= len(expanded)
		}
	}
	var walk func(idx int, cur []string) bool
	walk = func(idx int, cur []string) bool {
		if idx == len(choices) {
			return check(cur)
		}
		for _, piece := range choices[idx] {
			if !walk(idx+1, append(cur, piece...)) {
				return false
			}
		}
		return true
	}
	return walk(0, make([]string, 0, len(args)))
}

// expandVarChoices 将变量的所有已知取值转为展开后的参数切片列表并去重。
func expandVarChoices(values []string, unquoted bool) [][]string {
	var out [][]string
	for _, v := range values {
		var parts []string
		if unquoted {
			parts = strings.Fields(v)
		} else {
			parts = []string{v}
		}
		dup := false
		for _, prev := range out {
			if slices.Equal(prev, parts) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, parts)
		}
	}
	if len(out) == 0 {
		return [][]string{{}}
	}
	return out
}

// safeUnknownDynamicArg 判定无法静态解析的动态参数是否位于严格安全的数据位置：
// - chage -l "$user"：仅含 -l 与一个双引号单变量，即使展开为 -d0 也因缺少用户名无法修改任何账户；
// - crontab -u "$u" -l（或命令替换内小写循环变量 crontab -u $u -l）：紧跟 -u 后的用户名参数。
func safeUnknownDynamicArg(program string, args []string, metas []wordMeta, idx int, nested bool) bool {
	m := simpleVar.FindStringSubmatch(args[idx])
	if m == nil {
		return false
	}
	name := m[1] + m[2]
	switch program {
	case "chage":
		return len(args) == 2 && idx == 1 && args[0] == "-l" && !metas[idx].unquotedDynamic
	case "crontab":
		return idx > 0 && args[idx-1] == "-u" && (!metas[idx].unquotedDynamic || (nested && localName.MatchString(name)))
	default:
		return false
	}
}

var metadataOnly = map[string]bool{"ls": true, "stat": true, "test": true, "[": true, "echo": true, "printf": true, "true": true, "false": true}

// split 按 shell 规则切成命令段，每段是去掉引号后的词。遇到命令替换、进程替换、heredoc、
// 后台运行、子 shell 括号，或写到 /dev/null 以外的重定向，直接判为非只读。
func split(cmd string) ([]segment, bool) {
	var segments []segment
	var words, inputs, varWords, globWords []string
	var wordMetas []wordMeta
	start, redirected, dynamic := 0, false, false
	var word strings.Builder
	inWord, input, wordVar, wordGlob, wordDynamic, wordUnquotedDynamic := false, false, false, false, false, false
	flushWord := func() {
		if inWord {
			w := word.String()
			// 输入重定向的文件名不算命令参数，但保留在 inputs 里供密钥路径检查
			if input {
				inputs = append(inputs, w)
			} else {
				words = append(words, w)
				wordMetas = append(wordMetas, wordMeta{dynamic: wordDynamic, unquotedDynamic: wordUnquotedDynamic})
			}
			if wordVar {
				varWords = append(varWords, w)
			}
			if wordGlob {
				globWords = append(globWords, w)
			}
			input, wordVar, wordGlob, wordDynamic, wordUnquotedDynamic = false, false, false, false, false
		}
		word.Reset()
		inWord = false
	}
	flushSegment := func(end int) {
		flushWord()
		if len(words) > 0 || len(inputs) > 0 {
			segments = append(segments, segment{
				words: words, wordMetas: wordMetas, inputs: inputs, varWords: varWords, globWords: globWords,
				raw: cmd[start:end], input: redirected, dynamic: dynamic,
			})
		}
		words, wordMetas, inputs, varWords, globWords = nil, nil, nil, nil, nil
		redirected, dynamic = false, false
		start = end + 1
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case c == '\'':
			end := strings.IndexByte(cmd[i+1:], '\'')
			if end < 0 {
				return nil, false
			}
			word.WriteString(cmd[i+1 : i+1+end])
			inWord = true
			i += end + 1
		case c == '"':
			j := i + 1
			for ; j < len(cmd) && cmd[j] != '"'; j++ {
				switch cmd[j] {
				case '`':
					return nil, false
				case '$':
					dynamic = true
					wordDynamic = true
					if j+1 < len(cmd) && cmd[j+1] == '(' {
						end, ok := substitution(cmd, j)
						if !ok {
							return nil, false
						}
						word.WriteString(cmd[j : end+1])
						j = end
					} else {
						wordVar = true
						word.WriteByte('$')
					}
				case '\\':
					dynamic = true
					if j+1 < len(cmd) {
						next := cmd[j+1]
						if next == '$' || next == '"' || next == '\\' || next == '`' {
							word.WriteByte(next)
						} else {
							word.WriteByte('\\')
							word.WriteByte(next)
						}
						j++
					} else {
						return nil, false
					}
				default:
					word.WriteByte(cmd[j])
				}
			}
			if j >= len(cmd) {
				return nil, false
			}
			inWord = true
			i = j
		case c == '\\':
			dynamic = true
			if i+1 < len(cmd) {
				word.WriteByte(cmd[i+1])
				inWord = true
				i++
			}
		case c == '`', c == '(', c == ')', c == '{' && !inWord, c == '}' && !inWord:
			return nil, false
		case c == '$' && i+1 < len(cmd) && cmd[i+1] == '\'':
			return nil, false
		case c == '$' && i+1 < len(cmd) && cmd[i+1] == '(':
			// 命令替换：里面的命令同样要只读，整段原样留在词里（拿它当程序名照样不认）
			end, ok := substitution(cmd, i)
			if !ok {
				return nil, false
			}
			dynamic = true
			wordDynamic = true
			wordUnquotedDynamic = true
			word.WriteString(cmd[i : end+1])
			inWord = true
			i = end
		case c == ' ' || c == '\t':
			flushWord()
		case c == ';' || c == '\n':
			flushSegment(i)
		case c == '|':
			if i+1 < len(cmd) && cmd[i+1] == '&' {
				return nil, false
			}
			end := i
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				i++
			}
			flushSegment(end)
		case c == '&':
			switch {
			case i+1 < len(cmd) && cmd[i+1] == '&':
				i++
				flushSegment(i - 1)
			case i+1 < len(cmd) && cmd[i+1] == '>':
				// &>/dev/null
				flushWord()
				n, ok := redirect(cmd, i+1)
				if !ok {
					return nil, false
				}
				i = n
			default:
				return nil, false // 后台运行
			}
		case c == '>':
			// 2>/dev/null 里的 2 是文件描述符，不是参数
			if inWord && strings.Trim(word.String(), "0123456789") == "" {
				word.Reset()
				inWord = false
			}
			flushWord()
			n, ok := redirect(cmd, i)
			if !ok {
				return nil, false
			}
			i = n
		case c == '<':
			if i+1 < len(cmd) && (cmd[i+1] == '<' || cmd[i+1] == '(') {
				return nil, false
			}
			flushWord()
			input, redirected = true, true // 输入重定向只是读文件；文件名留在 inputs 与段原文里，提到密钥路径照样拦
		default:
			if c == '$' {
				dynamic = true
				wordVar = true
				wordDynamic = true
				wordUnquotedDynamic = true
			}
			// 词中间的 { 在 sh 是 bash 时会做花括号展开（/e{tc,}/shadow），${f} 的花括号不算
			if c == '*' || c == '?' || c == '[' || c == '{' && cmd[i-1] != '$' {
				wordGlob = true
			}
			word.WriteByte(c)
			inWord = true
		}
	}
	flushSegment(len(cmd))
	return segments, true
}

// substitution 找到从 cmd[i]（'$('）开始的命令替换的右括号，里面的命令递归判定只读；$(( 算术展开不认
func substitution(cmd string, i int) (int, bool) {
	depth := 0
	for j := i + 1; j < len(cmd); j++ {
		switch cmd[j] {
		case '\'':
			end := strings.IndexByte(cmd[j+1:], '\'')
			if end < 0 {
				return 0, false
			}
			j += end + 1
		case '"':
			for j++; j < len(cmd) && cmd[j] != '"'; j++ {
				if cmd[j] == '\\' {
					j++
				}
			}
		case '\\':
			j++
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				inner := cmd[i+2 : j]
				return j, !strings.HasPrefix(inner, "(") && readOnly(inner, true)
			}
		}
	}
	return 0, false
}

// redirect 解析从 cmd[i]（'>'）开始的输出重定向，只放行丢弃输出与合并描述符；返回目标结束的位置
func redirect(cmd string, i int) (int, bool) {
	i++
	if i < len(cmd) && cmd[i] == '>' {
		i++
	}
	if i < len(cmd) && cmd[i] == '&' {
		i++
		j := i
		for j < len(cmd) && cmd[j] >= '0' && cmd[j] <= '9' {
			j++
		}
		return j - 1, j > i
	}
	for i < len(cmd) && (cmd[i] == ' ' || cmd[i] == '\t') {
		i++
	}
	const devNull = "/dev/null"
	if !strings.HasPrefix(cmd[i:], devNull) {
		return 0, false
	}
	end := i + len(devNull)
	if end < len(cmd) && !strings.ContainsRune(" \t;|&\n", rune(cmd[end])) {
		return 0, false
	}
	return end - 1, true
}

// command 去掉段首的 shell 关键字与变量赋值，返回程序名与参数；程序名为空表示这段没有命令（for 头、done、赋值）
func command(words []string) (string, []string, bool) {
	for len(words) > 0 {
		switch words[0] {
		case "!", "if", "then", "else", "elif", "do", "while", "until", "time":
			words = words[1:]
			continue
		case "done", "fi":
			return "", nil, len(words) == 1
		case "for":
			// for 变量 in 列表：列表只是数据
			return "", nil, len(words) >= 2 && assignable.MatchString(words[1]) && (len(words) == 2 || words[2] == "in")
		}
		if assignment.MatchString(words[0]) {
			words = words[1:]
			continue
		}
		break
	}
	if len(words) == 0 {
		return "", nil, true
	}
	program := words[0]
	for _, dir := range []string{"/usr/local/sbin/", "/usr/local/bin/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/"} {
		if strings.HasPrefix(program, dir) {
			program = strings.TrimPrefix(program, dir)
			break
		}
	}
	// 变量当程序名、相对路径或别的目录下的同名程序，都不知道真正跑的是什么
	if program == "" || strings.ContainsAny(program, "/$*?") {
		return "", nil, false
	}
	return program, words[1:], true
}

var (
	assignable = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

// readOnlyPrograms 只读程序清单；值为参数检查，nil 表示任何参数都只读。不在清单里的程序一律交给人。
var readOnlyPrograms = map[string]func(args []string) bool{
	"echo": nil, "printf": nil, "true": nil, "false": nil, "test": nil, "[": nil, "read": nil, "sleep": nil, "seq": nil,
	"cat": nil, "tac": nil, "head": nil, "tail": nil, "grep": grepRead, "egrep": grepRead, "fgrep": grepRead, "zgrep": grepRead, "zcat": nil,
	"wc": nil, "cut": nil, "tr": nil, "column": nil, "nl": nil, "comm": nil, "paste": nil, "rev": nil, "strings": nil,
	"cmp": nil, "diff": diffRead, "md5sum": nil, "sha1sum": nil, "sha256sum": nil, "jq": nil, "basename": nil, "dirname": nil,
	"readlink": nil, "realpath": nil, "ls": nil, "stat": nil, "file": nil, "du": nil, "df": nil, "free": nil,
	"uptime": nil, "uname": nil, "nproc": nil, "id": nil, "whoami": nil, "who": nil, "w": nil, "groups": nil,
	"last": nil, "lastb": nil, "lastlog": nil, "getent": nil, "ps": nil, "pgrep": nil, "pidof": nil, "pstree": nil,
	"ss": ssRead, "netstat": nil, "lsof": nil, "lsblk": nil, "findmnt": nil, "lscpu": nil, "lspci": nil, "lsusb": nil,
	"lsmod": nil, "modinfo": nil, "vmstat": nil, "iostat": nil, "mpstat": nil, "getfacl": nil, "lsattr": nil,
	"pveversion": nil, "printenv": nil, "locale": nil, "getconf": nil, "atq": nil, "ipcs": nil, "lsns": nil, "which": nil,
	"hostid": nil, "arch": nil, "systemd-detect-virt": nil, "lslogins": nil,
	"curl":             curlProbe,
	"find":             noArg("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"),
	"sort":             noArgPrefix("-o", "--output", "--compress-program", "--files0-from"),
	"uniq":             atMostOneFile, // uniq 输入 输出：第二个文件名会被写
	"date":             noArgPrefix("-s", "-f", "--set", "--file"),
	"dmesg":            noArgPrefix("-c", "-C", "-D", "-E", "-n", "--clear", "--read-clear", "--console-level", "--console-off", "--console-on"),
	"journalctl":       noArgPrefix("--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush", "--sync", "--relinquish-var", "--smart-relinquish-var", "--setup-keys", "--update-catalog"),
	"sysctl":           sysctlRead,
	"hostname":         flagsOnly,
	"crontab":          crontabList,
	"chage":            onlyFlag("-l"),
	"top":              requireFlag("-b"),
	"awk":              awkRead,
	"gawk":             awkRead,
	"mawk":             awkRead,
	"ip":               ipReadOnly,
	"systemctl":        subcommand(true, systemctlPreFlags, "status", "show", "cat", "list-units", "list-unit-files", "list-timers", "list-sockets", "list-jobs", "list-paths", "list-dependencies", "is-active", "is-enabled", "is-failed", "is-system-running"),
	"timedatectl":      subcommand(true, []string{"--no-pager"}, "status", "show", "timesync-status", "show-timesync"),
	"hostnamectl":      subcommand(true, []string{"--no-pager"}, "status"),
	"docker":           dockerReadOnly,
	"iptables":         firewallReadOnly,
	"ip6tables":        firewallReadOnly,
	"iptables-legacy":  firewallReadOnly,
	"ip6tables-legacy": firewallReadOnly,
	"iptables-nft":     firewallReadOnly,
	"ip6tables-nft":    firewallReadOnly,
	"nft":              nftReadOnly,
	"dpkg":             onlyFlagPrefix("-l", "-L", "-s", "-S", "--list", "--listfiles", "--status", "--search", "--print-architecture"),
	"dpkg-query":       nil,
	"rpm":              rpmQuery,
	"apt":              subcommand(false, []string{"-q", "-qq", "--quiet"}, "list", "show", "policy", "search"),
	"apt-cache":        subcommand(false, nil, "policy", "show", "showpkg", "search", "depends", "rdepends", "madison", "pkgnames"),
	"qm":               subcommand(false, nil, "list", "status", "config", "pending", "listsnapshot"),
	"pct":              subcommand(false, nil, "list", "status", "config", "pending", "listsnapshot"),
	"pvecm":            subcommand(false, nil, "status", "nodes"),
	"zpool":            subcommand(false, nil, "status", "list", "iostat"),
	"zfs":              subcommand(false, nil, "list", "get"),
	"chronyc":          subcommand(false, nil, "tracking", "sources", "sourcestats", "activity"),
	"sshd":             sshdTest,
	"visudo":           onlyFlag("-c"),
	"vtysh":            vtyshShow,
	"sed":              sedRead,
	"smartctl":         smartctlRead,
	"storcli":          raidShow,
	"storcli64":        raidShow,
	"perccli":          raidShow,
	// megactl 包：只读出控制器、电池与阵列状态；-T 会让磁盘做自检，不放行
	"megasasctl": noArgPrefix("-T"),
	"megactl":    noArgPrefix("-T"),
	"perccli64":  raidShow,
	"arcconf":    arcconfGet,
	"swapon":     swaponShow,
	"command":    onlyFlagPrefix("-v", "-V"), // command 不带 -v 就是执行后面的命令
	"loginctl":   subcommand(true, []string{"--no-pager", "--no-legend", "--all", "-a", "--full", "-l"}, "list-sessions", "list-users", "list-seats", "show-session", "show-user", "session-status", "user-status"),
}

// systemctlPreFlags systemctl 在子命令前允许出现的无参全局选项，拒绝 -H/--host/-M/--root 等带值或远程选项
var systemctlPreFlags = []string{
	"--no-pager", "--no-legend", "--failed", "--all", "-a", "--full", "-l",
	"--plain", "--quiet", "-q", "--system", "--user", "--utc",
}

// sshdTest sshd -T / -t 只打印或校验配置；不带它们就是起一个守护进程
func sshdTest(args []string) bool {
	test := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-T", "-t":
			test = true
		case "-C", "-f":
			i++ // 连接参数、配置文件路径
		default:
			return false
		}
	}
	return test
}

// vtyshShow vtysh 只认成对的单行 -c 'show …'，配置模式、内嵌换行和别的选项一律不认
func vtyshShow(args []string) bool {
	if len(args) == 0 || len(args)%2 != 0 {
		return false
	}
	for i := 0; i < len(args); i += 2 {
		if args[i] != "-c" || strings.ContainsAny(args[i+1], "\r\n") || !strings.HasPrefix(strings.TrimSpace(args[i+1]), "show ") {
			return false
		}
	}
	return true
}

func noArg(banned ...string) func([]string) bool {
	return func(args []string) bool {
		for _, a := range args {
			for _, b := range banned {
				if a == b {
					return false
				}
			}
		}
		return true
	}
}

// noArgPrefix 参数命中这些短选项或长选项（含 getopt_long 唯一前缀缩写）就不放行：
// -o 会写文件，-s 会改时间。短选项可能并在一起（-no 也含 -o 的效果），一并拦
func noArgPrefix(banned ...string) func([]string) bool {
	return func(args []string) bool {
		for _, a := range args {
			if strings.HasPrefix(a, "--") {
				name, _, _ := strings.Cut(a, "=")
				for _, b := range banned {
					if strings.HasPrefix(b, "--") && (strings.HasPrefix(name, b) || longAbbrev(name, b)) {
						return false
					}
				}
				continue
			}
			for _, b := range banned {
				if strings.HasPrefix(b, "--") {
					continue
				}
				if strings.HasPrefix(a, b) {
					return false
				}
				if len(b) == 2 && b[0] == '-' && strings.HasPrefix(a, "-") && strings.ContainsRune(a[1:], rune(b[1])) {
					return false
				}
			}
		}
		return true
	}
}

// ssRead ss -K / --kill 会强制关闭套接字。getopt 接受长选项的唯一前缀，ss 里 --k 开头的只有 --kill，--k、--ki 都是它
func ssRead(args []string) bool {
	for _, a := range args {
		if name, _, _ := strings.Cut(a, "="); len(name) > 2 && strings.HasPrefix("--kill", name) {
			return false
		}
	}
	return noArgPrefix("-K")(args)
}

// longAbbrev name 是这些长选项之一的缩写（getopt 接受的唯一前缀；有歧义时 getopt 报错，按命中算更稳）
func longAbbrev(name string, long ...string) bool {
	return len(name) > 2 && slices.ContainsFunc(long, func(l string) bool { return strings.HasPrefix(l, name) })
}

// recursiveRisky 递归读取不放行的位置：放 shadow、主机与用户私钥的地方，以及它们的上级目录（/、/etc、/home/<user> 都算）；
// /proc（/proc/self/root 指回根目录）、/dev（设备文件）同样不放行
var recursiveRisky = [][]string{{"etc", "shadow"}, {"etc", "gshadow"}, {"etc", "ssh"}, {"var", "backups"}, {"root"}, {"home", "*", ".ssh"}, {"proc"}, {"dev"}}

// recursiveTargetSafe 递归读取的目录得是写死的路径（按 cwd=/ 解析），且和 recursiveRisky 的位置互不包含
func recursiveTargetSafe(w string) bool {
	clean := path.Join("/", w)
	if w == "" || strings.ContainsAny(w, "$*?[{~") || clean == "/" {
		return false
	}
	parts := strings.Split(clean[1:], "/")
	return !slices.ContainsFunc(recursiveRisky, func(risky []string) bool {
		for i := 0; i < len(parts) && i < len(risky); i++ {
			if ok, _ := path.Match(risky[i], parts[i]); !ok {
				return false
			}
		}
		return true
	})
}

// grep 的选项表，递归时按它拆出模式与文件
var (
	grepValuedLong = []string{"--regexp", "--file", "--max-count", "--after-context", "--before-context", "--context", "--directories",
		"--devices", "--exclude", "--include", "--exclude-dir", "--exclude-from", "--label", "--binary-files"}
	grepPlainLong = []string{"--recursive", "--ignore-case", "--no-ignore-case", "--invert-match", "--word-regexp", "--line-regexp",
		"--count", "--files-with-matches", "--files-without-match", "--only-matching", "--quiet", "--silent", "--no-messages",
		"--byte-offset", "--line-number", "--with-filename", "--no-filename", "--null", "--null-data", "--text", "--extended-regexp",
		"--fixed-strings", "--basic-regexp", "--perl-regexp", "--initial-tab", "--color", "--colour", "--line-buffered", "--no-group-separator"}
)

// grepRead 不递归的 grep 只读命令行上的文件（密钥路径由 ReadOnly 统一拦），照旧放行。
// 递归（-r、-d recurse 及长选项缩写）时按选项表拆出模式与文件：没给文件就读 cwd（agent 是 /），
// 每个文件都得过 recursiveTargetSafe；-R 会跟着目录里的符号链接走（/usr/lib/ssl/private 指向 /etc），认不出的选项一律不放行
func grepRead(args []string) bool {
	if !slices.ContainsFunc(args, func(a string) bool {
		name, _, _ := strings.Cut(a, "=")
		if strings.HasPrefix(name, "--") {
			return longAbbrev(name, "--recursive", "--dereference-recursive", "--directories")
		}
		return strings.HasPrefix(a, "-") && strings.ContainsAny(a, "rRd")
	}) {
		return true
	}
	var operands []string
	explicit := false // 模式由 -e / -f 给出，位置参数全是文件
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, _, joined := strings.Cut(a, "=")
		switch {
		case a == "--":
			operands = append(operands, args[i+1:]...)
			i = len(args)
		case slices.Contains(grepValuedLong, name):
			explicit = explicit || name == "--regexp" || name == "--file"
			if !joined {
				i++
			}
		case strings.HasPrefix(a, "--"):
			if !slices.Contains(grepPlainLong, name) || joined && name != "--color" && name != "--colour" {
				return false
			}
		case strings.HasPrefix(a, "-") && a != "-":
			pattern, next, ok := grepShort(a[1:])
			if !ok {
				return false
			}
			explicit = explicit || pattern
			if next {
				i++
			}
		default:
			operands = append(operands, a)
		}
	}
	if !explicit && len(operands) > 0 {
		operands = operands[1:]
	}
	return len(operands) > 0 && !slices.ContainsFunc(operands, func(w string) bool { return !recursiveTargetSafe(w) })
}

// grepShort 拆一组短选项：pattern 表示带了 -e / -f，next 表示下一个参数是选项值；遇到认不出的字母（含 -R）ok 为 false
func grepShort(cluster string) (pattern, next, ok bool) {
	for j, c := range cluster {
		if strings.ContainsRune("efmABCdD", c) {
			return c == 'e' || c == 'f', j == len(cluster)-1, true
		}
		if !strings.ContainsRune("rivwxclLoqsbnHhZzaEFGPTUIy0123456789", c) {
			return false, false, false
		}
	}
	return false, false, true
}

// diffRead diff -r 把两棵目录树里不同的文件内容打出来（-N 连只在一边的文件也整个打出）：
// 递归时每个路径参数（含 --from-file= / --to-file= 的值）都得过 recursiveTargetSafe。选项值被当成路径只会多拒，不会漏
func diffRead(args []string) bool {
	if !slices.ContainsFunc(args, func(a string) bool {
		name, _, _ := strings.Cut(a, "=")
		if strings.HasPrefix(name, "--") {
			return longAbbrev(name, "--recursive")
		}
		return strings.HasPrefix(a, "-") && strings.ContainsRune(a, 'r')
	}) {
		return true
	}
	for _, a := range args {
		name, value, joined := strings.Cut(a, "=")
		switch {
		case joined && longAbbrev(name, "--from-file", "--to-file"):
			a = value
		case strings.HasPrefix(a, "-") && a != "-":
			continue
		}
		if !recursiveTargetSafe(a) {
			return false
		}
	}
	return true
}

func atMostOneFile(args []string) bool {
	files := 0
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			files++
		}
	}
	return files <= 1
}

// curlProbe 只取不存的 GET / HEAD 探测：不带请求体、不上传、不读配置文件，响应只许丢到 /dev/null 或标准输出。
// 连通性与状态码探针不改主机状态，判成写操作会让它之前取的结案证据全部作废
func curlProbe(args []string) bool {
	plain := map[string]bool{"-s": true, "-S": true, "-k": true, "-I": true, "-L": true, "-f": true, "-v": true, "-4": true, "-6": true, "-i": true,
		"--silent": true, "--show-error": true, "--insecure": true, "--head": true, "--location": true, "--fail": true, "--verbose": true, "--include": true, "--compressed": true}
	// 带值的选项；值有限制的给出许可值，nil 表示任意
	valued := map[string][]string{"-m": nil, "--max-time": nil, "--connect-timeout": nil, "-w": nil, "--write-out": nil, "-H": nil, "--header": nil,
		"-A": nil, "--user-agent": nil, "--resolve": nil, "-x": nil, "--proxy": nil, "--noproxy": nil, "--retry": nil,
		"-o": {"/dev/null"}, "--output": {"/dev/null"}, "-D": {"-", "/dev/null"}, "--dump-header": {"-", "/dev/null"}, "-X": {"GET", "HEAD"}, "--request": {"GET", "HEAD"}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			// 只认 http(s)：file:// 读本机文件（%73hadow 这类编码、{} [] 通配 curl 自己会展开），gopher:// 之类能发任意字节
			if lower := strings.ToLower(a); !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
				return false
			}
			continue
		}
		if plain[a] {
			continue
		}
		name, value, joined := strings.Cut(a, "=")
		allowed, ok := valued[name]
		if !ok && !strings.HasPrefix(a, "--") && len(a) > 2 {
			// -sS、-sk 这类合并的短选项；合并里带值的（-so /dev/null）不认，分开写
			for _, c := range a[1:] {
				if !plain["-"+string(c)] {
					return false
				}
			}
			continue
		}
		if !ok {
			return false
		}
		if !joined {
			if i++; i >= len(args) {
				return false
			}
			value = args[i]
		}
		// -H @file、-w @file 从文件读取内容
		if strings.HasPrefix(value, "@") || allowed != nil && !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

func flagsOnly(args []string) bool {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return false
		}
	}
	return true
}

func onlyFlag(flag string) func([]string) bool {
	return func(args []string) bool {
		seen := false
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				if a != flag {
					return false
				}
				seen = true
			}
		}
		return seen
	}
}

func requireFlag(flag string) func([]string) bool {
	return func(args []string) bool {
		for _, a := range args {
			if a == flag || (strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsRune(a[1:], rune(flag[1]))) {
				return true
			}
		}
		return false
	}
}

func onlyFlagPrefix(allowed ...string) func([]string) bool {
	return func(args []string) bool {
		flags := 0
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				continue
			}
			flags++
			ok := false
			for _, p := range allowed {
				if a == p || (strings.HasPrefix(p, "--") && strings.HasPrefix(a, p+"=")) {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
		return flags > 0
	}
}

// rpmQuery rpm 只允许纯查询参数，拒绝 --eval/-E/--define/-D/--pipe/--rcfile/--macros 等可执行或改配置选项。
func rpmQuery(args []string) bool {
	if len(args) == 0 {
		return false
	}
	queryMode := false
	longPlain := map[string]bool{
		"--query": true, "--all": true, "--info": true, "--list": true,
		"--file": true, "--package": true, "--whatprovides": true, "--whatrequires": true,
		"--requires": true, "--provides": true, "--changelog": true, "--last": true,
		"--filesbypkg": true, "--configfiles": true, "--docfiles": true, "--state": true,
		"--dump": true, "--nosignature": true, "--nodigest": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		if a == "--qf" || a == "--queryformat" {
			if i++; i >= len(args) || strings.Contains(args[i], "%(") {
				return false
			}
			continue
		}
		if fmtVal, ok := strings.CutPrefix(a, "--qf="); ok {
			if strings.Contains(fmtVal, "%(") {
				return false
			}
			continue
		}
		if fmtVal, ok := strings.CutPrefix(a, "--queryformat="); ok {
			if strings.Contains(fmtVal, "%(") {
				return false
			}
			continue
		}
		if strings.HasPrefix(a, "--") {
			if !longPlain[a] {
				return false
			}
			if a == "--query" {
				queryMode = true
			}
			continue
		}
		// 短选项组合：仅放行纯查询字母，且必须显式带有 -q（避免 -i 被当成安装）
		if len(a) < 2 {
			return false
		}
		hasQ := strings.ContainsRune(a[1:], 'q')
		if hasQ {
			queryMode = true
		}
		for _, r := range a[1:] {
			switch r {
			case 'q', 'a', 'l', 'f', 'p', 'c', 'd', 's', 'R', 'v', 'g', 'L':
			case 'i':
				// -i 只有在 -q 组合或已经进入查询模式后才是 --info，否则是安装软件包
				if !queryMode {
					return false
				}
			default:
				return false
			}
		}
	}
	return queryMode
}

// subcommand 仅跳过显式声明的无参前置选项；遇到未知选项直接拒绝，防止带值全局选项把值伪装成子命令。
// bare 为 true 时允许不带子命令（如 systemctl --failed --no-pager 默认 list-units）。
func subcommand(bare bool, preFlags []string, allowed ...string) func([]string) bool {
	return func(args []string) bool {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				if !slices.Contains(preFlags, a) {
					return false
				}
				continue
			}
			return slices.Contains(allowed, a)
		}
		return bare
	}
}

// ipReadOnly 仅放行已知无参输出选项 + 明确只读网络对象与 show/list/get 动作，拒绝 -b/-batch/缩写写动词等绕过。
func ipReadOnly(args []string) bool {
	preFlags := map[string]bool{
		"-4": true, "-6": true, "-br": true, "-brief": true, "--brief": true,
		"-c": true, "-color": true, "--color": true, "-d": true, "-details": true, "--details": true,
		"-h": true, "-human": true, "-human-readable": true, "--human-readable": true,
		"-j": true, "-json": true, "--json": true, "-o": true, "-oneline": true, "--oneline": true,
		"-p": true, "-pretty": true, "--pretty": true, "-r": true, "-resolve": true, "--resolve": true,
		"-s": true, "-stats": true, "-statistics": true, "--statistics": true,
		"-t": true, "-timestamp": true, "-ts": true, "-tshort": true, "-V": true, "-Version": true,
	}
	objects := map[string]bool{
		"a": true, "addr": true, "address": true,
		"l": true, "link": true,
		"r": true, "ro": true, "route": true,
		"n": true, "neigh": true, "neighbour": true,
		"ru": true, "rule": true,
		"maddr": true, "maddress": true, "mroute": true,
		"tunnel": true, "netns": true, "vrf": true,
	}
	addressObjects := map[string]bool{"a": true, "addr": true, "address": true}
	readActions := map[string]bool{
		"show": true, "list": true, "lst": true, "ls": true, "get": true,
	}
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		if !preFlags[args[i]] {
			return false
		}
		i++
	}
	if i >= len(args) || !objects[args[i]] {
		return false
	}
	i++
	if i >= len(args) {
		return true
	}
	// 对象后第一个词若存在，必须明确是只读动作（拒绝缩写写动作如 ip l s eth0 down / ip netns exec）
	// ip address 的动词按 add、change、replace、delete、show 的顺序认缩写，s、sh、sho 都是 show；ip link 的 s 是 set，别的对象不认缩写
	if !readActions[args[i]] && !(addressObjects[args[i-1]] && args[i] != "" && strings.HasPrefix("show", args[i])) {
		return false
	}
	// 动作之后不再允许出现写动词或批处理选项
	for _, a := range args[i+1:] {
		switch a {
		case "set", "add", "del", "delete", "flush", "change", "replace", "append", "prepend", "exec", "save", "restore":
			return false
		}
	}
	return true
}

func crontabList(args []string) bool {
	list := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-l":
			list = true
		case "-u":
			i++
		default:
			return false
		}
	}
	return list
}

func sysctlRead(args []string) bool {
	for _, a := range args {
		if strings.Contains(a, "=") || a == "-w" || a == "-p" || strings.HasPrefix(a, "--write") || strings.HasPrefix(a, "--load") || a == "--system" {
			return false
		}
	}
	return true
}

// awkUnsafe 剥离字符串字面量与注释后再匹配，避免 print "}" > "/tmp/x" 因字符串里的 } 提前中断正则
var (
	awkUnsafeCore = regexp.MustCompile(`\b(?:system|getline|fflush)\b|\bclose\s*\(|\|&|>>`)
	awkPrintRedir = regexp.MustCompile(`\bprintf?\b[^;}]*>`)
)

// stripAwkStringsAndComments 去掉双引号字符串、正则字面量的内容、# 注释与反斜杠续行；未闭合返回 false。
// 正则里的引号不能当字符串开头，否则 /"/{system("x")}/"/ 会把中间的 system 当字符串剥掉
func stripAwkStringsAndComments(script string) (string, bool) {
	// 先合并反斜杠续行，避免 print "a" \ 换行 > "/tmp/x" 绕过单行匹配
	script = strings.ReplaceAll(script, "\\\n", " ")
	var b strings.Builder
	b.Grow(len(script))
	for i := 0; i < len(script); i++ {
		switch script[i] {
		case '/':
			if !awkRegexStart(b.String()) {
				b.WriteByte('/')
				continue
			}
			end, ok := awkRegexEnd(script, i+1)
			if !ok {
				return "", false
			}
			b.WriteString("//")
			i = end
		case '"':
			b.WriteString(`""`)
			i++
			closed := false
			for ; i < len(script); i++ {
				if script[i] == '\\' {
					i++
					continue
				}
				if script[i] == '"' {
					closed = true
					break
				}
			}
			if !closed {
				return "", false
			}
		case '#':
			for i < len(script) && script[i] != '\n' {
				i++
			}
			if i < len(script) {
				b.WriteByte('\n')
			}
		default:
			b.WriteByte(script[i])
		}
	}
	return b.String(), true
}

var awkRegexKeywords = map[string]bool{
	"print": true, "printf": true, "return": true, "exit": true,
	"in": true, "do": true, "else": true, "delete": true, "getline": true, "case": true,
}

func isAwkIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

// awkRegexStart 前面没有操作数（开头、运算符、括号、分隔符或关键字之后）时 / 是正则开头，否则是除号
func awkRegexStart(prev string) bool {
	prev = strings.TrimRight(prev, " \t")
	if prev == "" {
		return true
	}
	if strings.ContainsRune("(,{};!~&|?:=<>+-*%^\n", rune(prev[len(prev)-1])) {
		return true
	}
	j := len(prev)
	for j > 0 && isAwkIdentChar(prev[j-1]) {
		j--
	}
	return j < len(prev) && awkRegexKeywords[prev[j:]]
}

// awkRegexEnd 从 start 起找正则字面量的结束 /，跳过转义、字符类（含首字符 ] 与 POSIX 子类）里的 /
func awkRegexEnd(script string, start int) (int, bool) {
	inClass := false
	classStart := -1
	for i := start; i < len(script); i++ {
		switch c := script[i]; {
		case c == '\\':
			if i+1 < len(script) && script[i+1] == '\n' {
				return 0, false
			}
			i++
		case c == '\n':
			return 0, false
		case c == '[' && !inClass:
			inClass = true
			classStart = i + 1
			if i+1 < len(script) && script[i+1] == '^' {
				i++
				classStart = i + 1
			}
		case c == '[' && inClass:
			// 方括号内的 POSIX 字符类/等价类/排序符号（[:alpha:]、[=a=]、[.ch.]）不能提前结束外层字符类
			if i+1 < len(script) && (script[i+1] == ':' || script[i+1] == '=' || script[i+1] == '.') {
				delim := script[i+1]
				for j := i + 2; j+1 < len(script) && script[j] != '\n'; j++ {
					if script[j] == delim && script[j+1] == ']' {
						i = j + 1
						break
					}
				}
			}
		case c == ']' && inClass && i > classStart:
			inClass = false
		case c == '/' && !inClass:
			return i, true
		}
	}
	return 0, false
}

func hasSinglePipe(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			if i+1 < len(s) && s[i+1] == '|' {
				i++
				continue
			}
			return true
		}
	}
	return false
}

func awkScriptSafe(script string) bool {
	stripped, ok := stripAwkStringsAndComments(script)
	if !ok {
		return false
	}
	if awkUnsafeCore.MatchString(stripped) || hasSinglePipe(stripped) || awkPrintRedir.MatchString(stripped) {
		return false
	}
	return true
}

func awkRead(args []string) bool {
	script := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-F" || a == "-v":
			if i++; i >= len(args) {
				return false
			}
		case strings.HasPrefix(a, "-F") || strings.HasPrefix(a, "-v"):
		case strings.HasPrefix(a, "-"):
			return false // -f 读脚本文件、-i 原地改写、--load 加载扩展，都不认
		case !script:
			if !awkScriptSafe(a) {
				return false
			}
			script = true
		}
	}
	return script
}

// swaponShow swapon 只认 --show / -s 这类查看；带设备名或 -a 就是启用交换分区
func swaponShow(args []string) bool {
	show := false
	for _, a := range args {
		switch {
		case a == "--show" || strings.HasPrefix(a, "--show=") || a == "-s" || a == "--summary":
			show = true
		case a == "--noheadings" || a == "--bytes" || a == "--raw":
		default:
			return false
		}
	}
	return show
}

// sedRead 只认替换（s///，标志限 g p i I m 和数字）与打印、删除、退出这类不碰文件的命令；
// -i 原地改写、-f 读脚本、w 写文件、e 执行命令一律不认，解析不了的也不认
func sedRead(args []string) bool {
	var scripts []string
	explicit := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-n" || a == "--quiet" || a == "--silent" || a == "-E" || a == "-r" || a == "--regexp-extended" || a == "-u" || a == "-z":
		case a == "-e":
			if i++; i >= len(args) {
				return false
			}
			scripts, explicit = append(scripts, args[i]), true
		case strings.HasPrefix(a, "--expression="):
			scripts, explicit = append(scripts, strings.TrimPrefix(a, "--expression=")), true
		case strings.HasPrefix(a, "-"):
			return false
		case !explicit && len(scripts) == 0:
			scripts = append(scripts, a)
		}
	}
	if len(scripts) == 0 {
		return false
	}
	for _, script := range scripts {
		for _, cmd := range strings.FieldsFunc(script, func(r rune) bool { return r == ';' || r == '\n' }) {
			if !sedCommand(strings.TrimSpace(cmd)) {
				return false
			}
		}
	}
	return true
}

var sedAddress = regexp.MustCompile(`^(?:\d+|\$|/(?:[^/\\]|\\.)*/)(?:,(?:\d+|\$|/(?:[^/\\]|\\.)*/))?`)

func sedCommand(c string) bool {
	c = strings.TrimSpace(sedAddress.ReplaceAllString(c, ""))
	switch {
	case c == "p" || c == "d" || c == "q" || c == "=" || c == "!d" || c == "!p":
		return true
	case len(c) < 2 || c[0] != 's':
		return false
	}
	delim := c[1]
	if delim == '\\' || delim == '\n' || (delim >= 'a' && delim <= 'z') || (delim >= 'A' && delim <= 'Z') || (delim >= '0' && delim <= '9') {
		return false
	}
	parts, i := 0, 2
	for ; i < len(c) && parts < 2; i++ {
		switch c[i] {
		case '\\':
			i++
		case delim:
			parts++
		}
	}
	return parts == 2 && strings.Trim(c[i:], "gpiIm0123456789") == ""
}

// smartctl 只认查看：-s/-t/-X/-o/-S 会开关 SMART、启动或中止自检，一律不认
func smartctlRead(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-a" || a == "--all" || a == "-x" || a == "--xall" || a == "-i" || a == "--info" || a == "-H" || a == "--health" ||
			a == "-A" || a == "--attributes" || a == "-c" || a == "--capabilities" || a == "--scan" || a == "--scan-open" || a == "-j" || a == "--json":
		case a == "-l" || a == "--log" || a == "-d" || a == "--device":
			i++ // 日志类型、设备类型是数据
		case strings.HasPrefix(a, "--log=") || strings.HasPrefix(a, "--device=") || strings.HasPrefix(a, "-d"):
		case strings.HasPrefix(a, "-"):
			return false
		}
	}
	return true
}

// raidShow storcli / perccli 的查看都带 show；带设置、删除、启动这类动词的一律不认
var raidVerbs = map[string]bool{"set": true, "add": true, "del": true, "delete": true, "start": true, "stop": true, "pause": true, "resume": true,
	"suspend": true, "flash": true, "download": true, "erase": true, "import": true, "reset": true, "clear": true, "restart": true,
	"expand": true, "migrate": true, "compress": true, "secureerase": true, "insert": true, "offline": true, "online": true, "spinup": true, "spindown": true}

func raidShow(args []string) bool {
	show := false
	for _, a := range args {
		w := strings.ToLower(a)
		if raidVerbs[w] {
			return false
		}
		show = show || w == "show"
	}
	return show
}

// arcconfGet arcconf 只认 GET 开头的查询子命令
func arcconfGet(args []string) bool {
	return len(args) > 0 && strings.HasPrefix(strings.ToUpper(args[0]), "GET")
}

// dockerReadOnly 只接受查询子命令；拒绝任何前置全局选项（避免 -l info rm -f x 等带值选项绕过），stats 必须明确关闭持续采样。
func dockerReadOnly(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "system":
		return len(args) == 2 && args[1] == "df"
	case "stats":
		return len(args) == 2 && (args[1] == "--no-stream" || args[1] == "--no-stream=true")
	case "ps", "images", "inspect", "logs", "version", "info", "top", "port", "diff":
		return true
	default:
		return false
	}
}
