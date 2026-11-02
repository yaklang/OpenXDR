package decoy

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallScriptBoundaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux 安装脚本的权限及符号链接验收")
	}
	dir := t.TempDir()
	data := make([]byte, 64)
	copy(data, []byte{127, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], 2)
	binary.LittleEndian.PutUint16(data[18:], 62)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint16(data[52:], 64)
	path := filepath.Join(dir, "decoyhost-linux-amd64")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	script, err := InstallScript(dir, "amd64", "https://aidr.internal", "11111111-1111-4111-8111-111111111111", "http", "127.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script syntax: %v %s", err, out)
	}
	fileScript, err := InstallScript(dir, "amd64", "https://aidr.internal", "11111111-1111-4111-8111-111111111111", "file", "127.0.0.1", "/srv/share")
	if err != nil || !strings.Contains(fileScript, "/srv/share/archive-11111111-1111-4111-8111-111111111111") || strings.Contains(fileScript, "%!") {
		t.Fatal("file root guard missing", err)
	}
	cmd = exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(fileScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("file script syntax: %v %s", err, out)
	}

	// 单独运行真实目录校验函数，所有路径都在临时目录内；模拟 root 所有权。
	checkDir := script[strings.Index(script, "safe_dir() {"):strings.Index(script, "[ -d /opt ]")]
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := target + "-link"
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	unsafe := target + "-unsafe"
	if err := os.Mkdir(unsafe, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0777); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		ok   bool
	}{{target, true}, {link, false}, {unsafe, false}} {
		guard := exec.Command("sh", "-c", "set -eu\nstat() { if [ \"$2\" = %u ]; then printf 0; else command stat \"$@\"; fi; }\n"+checkDir+"\nsafe_dir \"$TARGET\"\n")
		guard.Env = append(os.Environ(), "TARGET="+tc.path)
		if out, err := guard.CombinedOutput(); (err == nil) != tc.ok {
			t.Fatalf("directory guard %s: %v %s", tc.path, err, out)
		}
	}
	for _, want := range []string{"sha256sum -c", `printf '%s' "$2"`, "systemd-analyze verify", `[ ! -e "$unit" ] && [ ! -L "$unit" ] || exit 1`} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if _, err = InstallScript(dir, "../../etc/passwd", "https://aidr.internal", "11111111-1111-4111-8111-111111111111", "http", "127.0.0.1", ""); err == nil {
		t.Fatal("invalid arch accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "decoyhost-linux-arm64"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = InstallScript(dir, "arm64", "https://aidr.internal", "11111111-1111-4111-8111-111111111111", "http", "127.0.0.1", ""); err == nil {
		t.Fatal("wrong ELF machine accepted")
	}
	if err := os.WriteFile(path, []byte("not ELF"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = InstallScript(dir, "amd64", "https://aidr.internal", "11111111-1111-4111-8111-111111111111", "http", "127.0.0.1", ""); err == nil {
		t.Fatal("invalid ELF accepted")
	}
}
