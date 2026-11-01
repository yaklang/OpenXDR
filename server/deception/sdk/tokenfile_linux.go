package sdk

import (
	"os"

	"golang.org/x/sys/unix"
)

func openTokenFile(path string) (*os.File, error) {
	// 直接打开已知文件，不要求凭据父目录可列举；NOFOLLOW 原子拒绝末级符号链接。
	// NONBLOCK 防止误配 FIFO 卡住启动，调用方在读取前用同一 fd 校验普通文件与权限。
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
