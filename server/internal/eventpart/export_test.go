package eventpart

import "time"

// SetParentLockWait 测试用：缩短退役拿父表排他锁的尝试时长，返回还原函数。
func SetParentLockWait(d time.Duration) func() {
	old := parentLockWait
	parentLockWait = d
	return func() { parentLockWait = old }
}
