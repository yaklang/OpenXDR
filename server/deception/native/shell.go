package native

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Shell 是有限状态的虚拟终端，无 os/exec、宿主文件读取、管道或网络能力。
// 可作为专用诱饵账号的 forced-command；绝不能替换真实用户 Shell。
func Shell(in io.Reader, out io.Writer, m Manifest, record func(string) error) error {
	if m.Kind != "shell" {
		return fmt.Errorf("载体不是模拟终端")
	}
	text, err := Text(m.Kind, m.Profile, m.Marker)
	if err != nil {
		return err
	}
	if err = record("shell_started"); err != nil {
		return err
	}
	if _, err = fmt.Fprintln(out, "维护终端。输入 help 查看命令。"); err != nil {
		return err
	}
	scanner := bufio.NewScanner(io.LimitReader(in, 64*1024))
	scanner.Buffer(make([]byte, 1024), 1024)
	verified := false
	for n := 0; n < 32 && scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		response := "未知命令。输入 help。"
		event := "shell_action"
		switch line {
		case "exit", "quit":
			return nil
		case "help":
			response = "help | pwd | ls | cat README.md | verify <marker> | exit"
		case "pwd":
			response = "/maintenance"
		case "ls":
			response = "README.md  archive  status"
		case "cat README.md":
			response = text
		default:
			if m.Profile == "decoy" && !verified && line == "verify "+m.Marker {
				response = "核实已记录；不授予访问权限。"
				event = "marker_used"
				verified = true
			}
		}
		if err = record(event); err != nil {
			return err
		}
		if _, err = fmt.Fprintln(out, response); err != nil {
			return err
		}
	}
	return scanner.Err()
}
