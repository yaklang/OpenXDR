//go:build !linux

package native

import (
	"context"
	"fmt"
)

func WatchFile(_ context.Context, _ string, _ func(string) error) error {
	return fmt.Errorf("本平台尚不支持文件打开监视")
}
