package commandgate

// firewallReadOnly 只接受规则列表和输出格式参数；不根据「没看到写参数」推断只读。
func firewallReadOnly(args []string) bool {
	listed := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t", "--table":
			i++
			if i == len(args) || !firewallName(args[i]) {
				return false
			}
		case "-L", "--list", "-S", "--list-rules":
			if listed {
				return false
			}
			listed = true
			if i+1 < len(args) && firewallName(args[i+1]) {
				i++
			}
		case "-n", "--numeric", "-v", "--verbose", "-x", "--exact", "--line-numbers", "-nvL", "-vnL":
			if args[i] == "-nvL" || args[i] == "-vnL" {
				if listed {
					return false
				}
				listed = true
			}
		default:
			return false
		}
	}
	return listed
}

func firewallName(s string) bool {
	if s == "" || s[0] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// nftReadOnly 不接受文件输入、交互模式或任意追加语句。
func nftReadOnly(args []string) bool {
	for len(args) > 0 && (args[0] == "-a" || args[0] == "-n" || args[0] == "-nn") {
		args = args[1:]
	}
	if len(args) == 2 {
		return args[0] == "list" && (args[1] == "ruleset" || args[1] == "tables")
	}
	if len(args) < 3 || args[0] != "list" {
		return false
	}
	switch args[2] {
	case "ip", "ip6", "inet", "arp", "bridge", "netdev":
	default:
		return false
	}
	want := 0
	switch args[1] {
	case "table":
		want = 4
	case "chain", "set":
		want = 5
	default:
		return false
	}
	if len(args) != want {
		return false
	}
	for _, name := range args[3:] {
		if !firewallName(name) {
			return false
		}
	}
	return true
}
