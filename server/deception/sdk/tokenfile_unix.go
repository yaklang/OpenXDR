//go:build unix

package sdk

import (
	"os"
	"syscall"
)

// trustedOwner 只认 root 或运行端自己：别的用户放进来的 0600 文件同样不可信。
// systemd 凭据为 root 所有，经 ACL 授权给动态用户。
func trustedOwner(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && (st.Uid == 0 || int(st.Uid) == os.Geteuid())
}
