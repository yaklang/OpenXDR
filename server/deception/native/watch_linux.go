//go:build linux

package native

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"time"
)

// WatchFile 仅记录打开，不声称内容已读取。IN_OPEN 不能识别平台进程，调用方必须说明覆盖限制。
func WatchFile(ctx context.Context, path string, record func(string) error) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, err = unix.InotifyAddWatch(fd, path, unix.IN_OPEN|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_MODIFY)
	if err != nil {
		return err
	}
	if err = record("file_installed"); err != nil {
		return err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return err
		}
		for offset := 0; offset+unix.SizeofInotifyEvent <= n; {
			mask := binary.NativeEndian.Uint32(buf[offset+4:])
			length := int(binary.NativeEndian.Uint32(buf[offset+12:]))
			offset += unix.SizeofInotifyEvent + length
			if mask&(unix.IN_Q_OVERFLOW|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_IGNORED|unix.IN_MODIFY) != 0 {
				return fmt.Errorf("文件监视丢失或文件被移动，停止布放")
			}
			if mask&unix.IN_OPEN != 0 {
				if err = record("file_opened"); err != nil {
					return err
				}
			}
		}
	}
}
