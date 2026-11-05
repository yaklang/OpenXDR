package agentchat

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTaskLeaseConfirmationOnlyAdvancesAcknowledgedExpiry(t *testing.T) {
	now := time.Now()
	original := now.Add(taskLeaseTTL)
	c := taskLeaseConfirmation{expires: original}
	if !c.accept(now.Add(time.Hour), context.DeadlineExceeded, now.Add(taskHeartbeat+taskRenewTimeout), now.Add(2*taskHeartbeat)) {
		t.Fatal("已确认有效期限足够下一拍时应容忍一次timeout")
	}
	if !c.expires.Equal(original) {
		t.Fatal("未知提交扩展了本地确认租约")
	}
	ack := now.Add(4 * time.Minute)
	if !c.accept(ack, nil, now.Add(2*time.Minute), now.Add(3*time.Minute)) || !c.expires.Equal(ack) {
		t.Fatal("下一拍确认成功后未推进精确ack期限")
	}
}

func TestTaskLeaseConfirmationRejectsLostCancelledExpiredAndUnknownExtension(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name                 string
		err                  error
		expires, time, retry time.Time
	}{
		{"lost", errTaskLeaseLost, now.Add(time.Hour), now, now.Add(time.Minute)},
		{"wrapped_lost", errors.Join(errors.New("db"), errTaskLeaseLost), now.Add(time.Hour), now, now.Add(time.Minute)},
		{"cancelled", context.Canceled, now.Add(time.Hour), now, now.Add(time.Minute)},
		{"permanent", errors.New("permission denied"), now.Add(time.Hour), now, now.Add(time.Minute)},
		{"expired", context.DeadlineExceeded, now.Add(-time.Second), now, now.Add(time.Minute)},
		{"late_success_cannot_resurrect", nil, now.Add(taskLeaseReserve), now, now.Add(time.Minute)},
		{"no_next_attempt_budget", context.DeadlineExceeded, now.Add(time.Minute + taskRenewTimeout + taskLeaseReserve), now, now.Add(time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := taskLeaseConfirmation{expires: tc.expires}
			if c.accept(now.Add(24*time.Hour), tc.err, tc.time, tc.retry) {
				t.Fatal("无权继续却容忍错误")
			}
			if !c.expires.Equal(tc.expires) {
				t.Fatal("失败修改了确认期限")
			}
		})
	}
	c := taskLeaseConfirmation{expires: now.Add(time.Hour)}
	if c.accept(now.Add(taskLeaseReserve), nil, now, now.Add(time.Minute)) {
		t.Fatal("晚到或安全余量不足的ack不能继续")
	}
}
