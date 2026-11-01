package sdk

import "os"

// Windows 在 ReadTokenFile 入口已拒绝，ACL 校验未实现前不认任何属主。
func trustedOwner(os.FileInfo) bool { return false }
