// decoyhost 通过独立引擎运行已授权载体。
package main

import (
	"fmt"
	"openxdr/server/deception/runner"
	"os"
)

func main() {
	if err := runner.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
