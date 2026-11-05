package commandgate

import (
	"regexp"
	"strings"
)

// ReadOnly 判断一条经 sh -c 执行的 Linux 命令是否只读：定时任务半夜没人审批，
// 名单误伤的只读巡检命令（grep 模式里的 kill、stat /etc/shadow 的时间戳）由它放行。
// 只认得出就放行，认不出一律当成非只读交给人：命令替换、sh -c、eval、xargs、find -exec、
// awk 的 system()、写文件的重定向、不在清单里的程序都不放行；提到密钥文件时只许看元数据。
func ReadOnly(cmd string) bool {
	segments, ok := split(cmd)
	if !ok || len(segments) == 0 {
		return false
	}
	// 密钥路径出现在 for 列表、变量赋值或输入重定向里，可能经变量或标准输入传给别的段：整条命令都只许看元数据
	strict := false
	for _, seg := range segments {
		if program, _, _ := command(seg.words); secretPath.MatchString(seg.raw) && (program == "" || seg.input) {
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
		if (strict || secretPath.MatchString(seg.raw)) && !metadataOnly[program] {
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
		if !known || (check != nil && !check(args)) {
			return false
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
	if inner, ok := containerExec(program, args); ok {
		return argvReadOnly(inner)
	}
	check, known := readOnlyPrograms[program]
	return known && (check == nil || check(args))
}

// segment 一个命令段：去掉引号后的词、原文（密钥路径按原文找，含重定向目标）、是否有输入重定向、
// 单引号外是否出现 $ 或反斜杠（shell 会展开或转义，去引号后的词和真正传给程序的参数可能不同）
type segment struct {
	words   []string
	raw     string
	input   bool
	dynamic bool
}

// secretPath 与默认名单的读密钥条目同一范围，宽一点无妨：命中后只许 ls / stat 这类看元数据的命令
var secretPath = regexp.MustCompile(`/etc/g?shadow|\bid_(?:rsa|dsa|ecdsa|ed25519)|ssh_host_\w*key`)

var metadataOnly = map[string]bool{"ls": true, "stat": true, "test": true, "[": true, "echo": true, "printf": true, "true": true, "false": true}

// split 按 shell 规则切成命令段，每段是去掉引号后的词。遇到命令替换、进程替换、heredoc、
// 后台运行、子 shell 括号，或写到 /dev/null 以外的重定向，直接判为非只读。
func split(cmd string) ([]segment, bool) {
	var segments []segment
	var words []string
	start, redirected, dynamic := 0, false, false
	var word strings.Builder
	inWord, input := false, false
	flushWord := func() {
		// 输入重定向的文件名不算参数：done < /etc/passwd 里的 done 后面不该多出一个词
		if inWord && !input {
			words = append(words, word.String())
		}
		if inWord {
			input = false
		}
		word.Reset()
		inWord = false
	}
	flushSegment := func(end int) {
		flushWord()
		if len(words) > 0 {
			segments = append(segments, segment{words, cmd[start:end], redirected, dynamic})
		}
		words, redirected, dynamic = nil, false, false
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
					if j+1 < len(cmd) && cmd[j+1] == '(' {
						end, ok := substitution(cmd, j)
						if !ok {
							return nil, false
						}
						j = end
					}
				case '\\':
					j++
				}
			}
			if j >= len(cmd) {
				return nil, false
			}
			dynamic = dynamic || strings.ContainsAny(cmd[i+1:j], "$\\")
			word.WriteString(cmd[i+1 : j])
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
			input, redirected = true, true // 输入重定向只是读文件；文件名留在段原文里，提到密钥路径照样拦
		default:
			dynamic = dynamic || c == '$'
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
				return j, !strings.HasPrefix(inner, "(") && ReadOnly(inner)
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
	"cat": nil, "tac": nil, "head": nil, "tail": nil, "grep": nil, "egrep": nil, "fgrep": nil, "zgrep": nil, "zcat": nil,
	"wc": nil, "cut": nil, "tr": nil, "column": nil, "nl": nil, "comm": nil, "paste": nil, "rev": nil, "strings": nil,
	"cmp": nil, "diff": nil, "md5sum": nil, "sha1sum": nil, "sha256sum": nil, "jq": nil, "basename": nil, "dirname": nil,
	"readlink": nil, "realpath": nil, "ls": nil, "stat": nil, "file": nil, "du": nil, "df": nil, "free": nil,
	"uptime": nil, "uname": nil, "nproc": nil, "id": nil, "whoami": nil, "who": nil, "w": nil, "groups": nil,
	"last": nil, "lastb": nil, "lastlog": nil, "getent": nil, "ps": nil, "pgrep": nil, "pidof": nil, "pstree": nil,
	"ss": nil, "netstat": nil, "lsof": nil, "lsblk": nil, "findmnt": nil, "lscpu": nil, "lspci": nil, "lsusb": nil,
	"lsmod": nil, "modinfo": nil, "vmstat": nil, "iostat": nil, "mpstat": nil, "getfacl": nil, "lsattr": nil,
	"pveversion": nil, "printenv": nil, "locale": nil, "getconf": nil, "atq": nil, "ipcs": nil, "lsns": nil, "which": nil,
	"hostid": nil, "arch": nil, "systemd-detect-virt": nil, "lslogins": nil,
	"find":        noArg("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"),
	"sort":        noArgPrefix("-o", "--output"),
	"uniq":        atMostOneFile, // uniq 输入 输出：第二个文件名会被写
	"date":        noArgPrefix("-s", "--set"),
	"dmesg":       noArgPrefix("-c", "-C", "-D", "-E", "-n", "--clear", "--read-clear", "--console"),
	"journalctl":  noArgPrefix("--vacuum", "--rotate", "--flush", "--sync", "--relinquish", "--smart-relinquish", "--setup-keys", "--update-catalog"),
	"sysctl":      sysctlRead,
	"hostname":    flagsOnly,
	"crontab":     crontabList,
	"chage":       onlyFlag("-l"),
	"top":         requireFlag("-b"),
	"awk":         awkRead,
	"gawk":        awkRead,
	"mawk":        awkRead,
	"ip":          noWord("set", "add", "del", "delete", "flush", "change", "replace", "append", "prepend", "exec", "-batch", "-b", "-force"),
	"systemctl":   subcommand(true, "status", "show", "cat", "list-units", "list-unit-files", "list-timers", "list-sockets", "list-jobs", "list-paths", "list-dependencies", "is-active", "is-enabled", "is-failed", "is-system-running"),
	"timedatectl": subcommand(true, "status", "show", "timesync-status", "show-timesync"),
	"hostnamectl": subcommand(true, "status"),
	"docker":      dockerReadOnly,
	"dpkg":        onlyFlagPrefix("-l", "-L", "-s", "-S", "--list", "--listfiles", "--status", "--search", "--print-architecture"),
	"dpkg-query":  nil,
	"rpm":         firstFlagPrefix("-q"),
	"apt":         subcommand(false, "list", "show", "policy", "search"),
	"apt-cache":   subcommand(false, "policy", "show", "showpkg", "search", "depends", "rdepends", "madison", "pkgnames"),
	"qm":          subcommand(false, "list", "status", "config", "pending", "listsnapshot"),
	"pct":         subcommand(false, "list", "status", "config", "pending", "listsnapshot"),
	"pvecm":       subcommand(false, "status", "nodes"),
	"zpool":       subcommand(false, "status", "list", "iostat"),
	"zfs":         subcommand(false, "list", "get"),
	"chronyc":     subcommand(false, "tracking", "sources", "sourcestats", "activity"),
	"sshd":        sshdTest,
	"visudo":      onlyFlag("-c"),
	"vtysh":       vtyshShow,
	"sed":         sedRead,
	"smartctl":    smartctlRead,
	"storcli":     raidShow,
	"storcli64":   raidShow,
	"perccli":     raidShow,
	// megactl 包：只读出控制器、电池与阵列状态；-T 会让磁盘做自检，不放行
	"megasasctl": noArgPrefix("-T"),
	"megactl":    noArgPrefix("-T"),
	"perccli64":  raidShow,
	"arcconf":    arcconfGet,
	"swapon":     swaponShow,
	"command":    onlyFlagPrefix("-v", "-V"), // command 不带 -v 就是执行后面的命令
	"loginctl":   subcommand(true, "list-sessions", "list-users", "list-seats", "show-session", "show-user", "session-status", "user-status"),
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

// vtyshShow vtysh 只认成对的 -c 'show …'，配置模式和别的选项一律不认
func vtyshShow(args []string) bool {
	if len(args) == 0 || len(args)%2 != 0 {
		return false
	}
	for i := 0; i < len(args); i += 2 {
		if args[i] != "-c" || !strings.HasPrefix(strings.TrimSpace(args[i+1]), "show ") {
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

// noArgPrefix 参数以这些前缀开头就不放行：-o 会写文件，-s 会改时间。短选项可能并在一起（-no 也含 -o 的效果），一并拦
func noArgPrefix(banned ...string) func([]string) bool {
	return func(args []string) bool {
		for _, a := range args {
			for _, b := range banned {
				if strings.HasPrefix(a, b) {
					return false
				}
				if len(b) == 2 && b[0] == '-' && strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsRune(a[1:], rune(b[1])) {
					return false
				}
			}
		}
		return true
	}
}

func noWord(banned ...string) func([]string) bool { return noArg(banned...) }

func atMostOneFile(args []string) bool {
	files := 0
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			files++
		}
	}
	return files <= 1
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

func firstFlagPrefix(prefix string) func([]string) bool {
	return func(args []string) bool {
		return len(args) > 0 && strings.HasPrefix(args[0], prefix)
	}
}

// subcommand 第一个非选项参数必须是只读子命令；bare 为 true 时允许不带子命令（systemctl 默认 list-units）
func subcommand(bare bool, allowed ...string) func([]string) bool {
	return func(args []string) bool {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			for _, s := range allowed {
				if a == s {
					return true
				}
			}
			return false
		}
		return bare
	}
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

// awkScript 能执行命令、读命令输出或写文件的 awk 写法：system()、getline、协进程、print/printf 后接重定向或管道
var awkUnsafe = regexp.MustCompile(`system|getline|\|&|print[^;}]*[>|]|fflush|close\s*\(`)

func awkRead(args []string) bool {
	script := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-F" || a == "-v":
			i++ // 分隔符、变量赋值是数据
		case strings.HasPrefix(a, "-F") || strings.HasPrefix(a, "-v"):
		case strings.HasPrefix(a, "-"):
			return false // -f 读脚本文件、-i 原地改写、--load 加载扩展，都不认
		case !script:
			if awkUnsafe.MatchString(a) {
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

// dockerReadOnly 只接受查询子命令；stats 必须明确关闭持续采样。
func dockerReadOnly(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "system":
		return len(args) == 2 && args[1] == "df"
	case "stats":
		return len(args) == 2 && (args[1] == "--no-stream" || args[1] == "--no-stream=true")
	default:
		return subcommand(false, "ps", "images", "inspect", "logs", "version", "info", "top", "port", "diff")(args)
	}
}
