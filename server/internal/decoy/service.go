package decoy

import (
	"fmt"
	"net"
	"net/url"
	"openxdr/server/deception/sdk"
	"path"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// ServiceUnit 仅生成可审查的配置，不读取凭据、不安装或启动服务。
// fileRoot 只用于文件载体：管理员选定、业务用户会浏览的现有目录。
func ServiceUnit(platform, deployment, kind, listenHost, fileRoot string) (string, error) {
	id, err := uuid.Parse(deployment)
	if err != nil || id == uuid.Nil || id.String() != deployment {
		return "", fmt.Errorf("登记 ID 必须为规范 UUID")
	}
	u, err := url.Parse(platform)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || !regexp.MustCompile(`^[a-zA-Z0-9.:[\]-]+$`).MatchString(u.Host) {
		return "", fmt.Errorf("服务配置要求 HTTPS origin，不接受参数、凭据或转义字符")
	}
	if net.ParseIP(listenHost) == nil {
		return "", fmt.Errorf("监听地址必须为 IP")
	}
	if _, err = sdk.NewClient(strings.TrimSuffix(platform, "/"), deployment, strings.Repeat("0", 64)); err != nil {
		return "", err
	}
	base := "/etc/aidr-decoy/" + deployment
	sandbox := "DynamicUser=yes\nStateDirectory=aidr-decoy-" + deployment + "\nStateDirectoryMode=0700\nUMask=0077\nProtectHome=yes\n"
	args := "-expected-kind " + kind + " -platform " + strings.TrimSuffix(platform, "/") + " -deployment " + deployment + " -token-file %d/token"
	credential := "LoadCredential=token:" + base + "/token\n"
	switch kind {
	case "http":
		args += " -listen-host " + listenHost
	case "ssh":
		args += " -listen-host " + listenHost + " -host-key %d/host-key"
		credential += "LoadCredential=host-key:" + base + "/host-key\n"
	case "file":
		if err = ValidFileRoot(fileRoot); err != nil {
			return "", err
		}
		args += " -file-root " + fileRoot
		// 动态用户的状态目录在 /var/lib/private（0700）下，除 root 外谁都看不到诱饵；
		// 文件载体改以无任何 capability 的 root 运行，只能写选定目录，产物 root 所有、他人只读。
		sandbox = "ReadWritePaths=" + fileRoot + "\nUMask=0022\nProtectHome=read-only\n"
	default:
		return "", fmt.Errorf("常驻服务仅支持 ssh、http、file；模拟 Shell 保持交互运行")
	}
	return fmt.Sprintf(`[Unit]
Description=AIDR 专用诱饵 %s
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
%s%sExecStart=/usr/local/libexec/aidr-decoyhost %s
Restart=no
TimeoutStopSec=20
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
MemoryMax=128M
TasksMax=64
LimitNOFILE=256

[Install]
WantedBy=multi-user.target
`, deployment, sandbox, credential, args), nil
}

// ValidFileRoot 只接受规范绝对路径且不含 systemd 说明符、空白或引号；系统目录与运行端自身目录拒绝。
func ValidFileRoot(root string) error {
	if !regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`).MatchString(root) || path.Clean(root) != root || root == "/" {
		return fmt.Errorf("文件诱饵父目录须为规范绝对路径")
	}
	for _, system := range []string{"/proc", "/sys", "/dev", "/run", "/boot", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/opt/aidr-decoy", "/var/lib/private"} {
		if root == system || strings.HasPrefix(root, system+"/") {
			return fmt.Errorf("文件诱饵不放在系统目录")
		}
	}
	return nil
}
