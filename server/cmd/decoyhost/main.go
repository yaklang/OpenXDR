// decoyhost 通过独立引擎运行已授权载体。
package main

import (
	"fmt"
	"openxdr/server/deception/runner"
	"openxdr/server/deception/sdk"
	"os"
)

// exitUnreachable 平台暂时连不上或返回 5xx（维护重启、主节点切换、网络抖动）时的退出码（EX_TEMPFAIL）：
// systemd 单元据此稍后重启；被撤销、令牌失效等平台明确拒绝仍以 1 退出，不再拉起
const exitUnreachable = 75

func main() {
	if err := runner.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if sdk.Transient(err) {
			os.Exit(exitUnreachable)
		}
		os.Exit(1)
	}
}
