package main

import (
	"fmt"
	"openxdr/server/deception/runner"
	"os"
)

func main() {
	if err := runner.SSHRun(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
