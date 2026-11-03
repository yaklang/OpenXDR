//go:build integration

package feishuapproval

import (
	"context"
	"errors"
	"testing"
)

func TestApprovalNotificationRoutesDynamically(t *testing.T) {
	f := setup(t)
	calls := 0
	wrapped := ApprovalNotifier(f.s.DB, func(_ context.Context, title, body, path string) error {
		calls++
		if title != "approval" || body != "command" || path != "/approvals" {
			t.Fatal("旧通知内容改变")
		}
		return nil
	})
	// 未绑定且无长连接，也不能将已选择私聊的命令泄露到 Webhook。
	if err := wrapped(f.ctx, "approval", "command", "/approvals"); err != nil || calls != 0 {
		t.Fatalf("应用启用后仍发群通知: %d %v", calls, err)
	}
	for _, body := range []string{`{"enabled":false}`, `{"enabled":true}`, `{"enabled":"invalid"}`} {
		f.s.DB.Setting.UpdateOneID(configKey).SetValue([]byte(body)).SaveX(f.ctx)
		calls = 0
		err := wrapped(f.ctx, "approval", "command", "/approvals")
		switch body {
		case `{"enabled":false}`:
			if err != nil || calls != 1 {
				t.Fatal("关闭应用后未恢复原通知")
			}
		case `{"enabled":true}`:
			if err != nil || calls != 0 {
				t.Fatal("启用不完整应用配置时不应回退群聊")
			}
		default:
			if err == nil || calls != 0 {
				t.Fatal("配置损坏时不应回退群聊")
			}
		}
	}
	f.s.DB.Setting.DeleteOneID(configKey).ExecX(f.ctx)
	calls = 0
	if err := wrapped(f.ctx, "approval", "command", "/approvals"); err != nil || calls != 1 {
		t.Fatal("未配置应用时应沿用原通知")
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	calls = 0
	if err := wrapped(ctx, "approval", "command", "/approvals"); err == nil || calls != 0 {
		t.Fatal("读取失败不能导致回退群聊")
	}
	want := errors.New("webhook failed")
	failing := ApprovalNotifier(f.s.DB, func(context.Context, string, string, string) error { return want })
	if !errors.Is(failing(f.ctx, "approval", "command", "/approvals"), want) {
		t.Fatal("旧通知器错误未透传")
	}
}
