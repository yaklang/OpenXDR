package sdk

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadTokenFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	path := filepath.Join(t.TempDir(), "token")
	token := strings.Repeat("a", 64)
	if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadTokenFile(path); err != nil || got != token {
		t.Fatalf("valid file: %v", err)
	}
	for _, mode := range []os.FileMode{0644, 0700} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadTokenFile(path); err == nil {
			t.Fatalf("accepted %o", mode)
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenFile(link); err == nil {
		t.Fatal("accepted symlink")
	}
	for _, body := range []string{"invalid", strings.Repeat("a", 257)} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadTokenFile(path); err == nil || strings.Contains(err.Error(), body) {
			t.Fatal("invalid token accepted or exposed")
		}
	}
}
func TestReadTokenFileSystemdCredential(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)), 0440); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenFile(path); err == nil {
		t.Fatal("凭据目录外接受了 0440")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if _, err := ReadTokenFile(path); err != nil {
		t.Fatal("systemd 凭据 0440 被拒", err)
	}
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTokenFile(path); err == nil {
		t.Fatal("凭据目录接受了其他用户可读")
	}
}

func TestReadTokenFileSearchOnlyDirectory(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		t.Skip("需要非 root Linux 用户验证目录权限")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	token := strings.Repeat("b", 64)
	if err := os.WriteFile(path, []byte(token), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0100); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	// systemd 可以只授予遍历权限：已知文件可读，但目录不能列举。
	if _, err := os.ReadDir(dir); err == nil {
		t.Fatal("测试目录仍可列举")
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Fatal("已知凭据应可读", err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if got, err := ReadTokenFile(path); err != nil || got != token {
		t.Fatalf("只可遍历目录读取失败: %v", err)
	}
}
