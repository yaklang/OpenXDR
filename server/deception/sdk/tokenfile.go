package sdk

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ReadTokenFile 避免令牌进入命令行与执行审计；拒绝符号链接、其他用户可读或非 root/本用户所有的文件。
func ReadTokenFile(path string) (string, error) {
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("Windows 尚未校验凭据文件 ACL，请使用受控环境变量")
	}
	file, err := openTokenFile(path)
	if err != nil {
		return "", fmt.Errorf("无法打开令牌文件")
	}
	defer file.Close()
	// systemd 新版本把凭据放在私有只读 tmpfs，用 ACL 授权动态用户，文件显示为 0440；
	// 仅对 $CREDENTIALS_DIRECTORY 内的文件放宽属组只读，其他位置仍要求 0600。
	forbidden := os.FileMode(0177)
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" && filepath.Clean(dir) == filepath.Dir(filepath.Clean(path)) {
		forbidden = 0137
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&forbidden != 0 || !trustedOwner(info) {
		return "", fmt.Errorf("令牌文件类型或权限无效")
	}
	data, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil || len(data) > 256 {
		return "", fmt.Errorf("令牌文件格式无效")
	}
	token := strings.TrimSpace(string(data))
	if len(token) != 64 || strings.Trim(token, "0123456789abcdef") != "" {
		return "", fmt.Errorf("令牌文件格式无效")
	}
	return token, nil
}
