//go:build integration

package feishuapproval

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"openxdr/server/ent/approval"
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
	// 飞书配置完整时先等私聊投递，是否回退由 Service.fallback 按送达结果决定。
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
			if err != nil || calls != 1 {
				t.Fatal("飞书配置不完整时应沿用原通知")
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

// 卡片没送到任何有权审批人时回退原通知器，每条申请只回退一次；已送达则不回退。
func TestFallbackWhenCardNotDelivered(t *testing.T) {
	f := setup(t)
	var titles []string
	f.s.Fallback = func(_ context.Context, title, body, path string) error {
		if path != "/approvals" || !strings.Contains(body, "test-host") {
			t.Fatalf("回退通知内容不符: %s %s", body, path)
		}
		titles = append(titles, title)
		return nil
	}
	age := func(table string) {
		if _, err := f.s.SQL.ExecContext(f.ctx, `UPDATE `+table+` SET created_at=now()-interval '1 minute'`); err != nil {
			t.Fatal(err)
		}
	}
	run := func() {
		if err := f.s.enqueue(f.ctx, f.c); err != nil {
			t.Fatal(err)
		}
		if err := f.s.fallback(f.ctx, f.c); err != nil {
			t.Fatal(err)
		}
	}
	// 无人绑定：新申请先等投递窗口，过了窗口回退一次。
	lonely := pendingApproval(t, f)
	run()
	if len(titles) != 0 {
		t.Fatal("投递窗口内不应回退")
	}
	age("approvals")
	run()
	run()
	if len(titles) != 1 {
		t.Fatalf("未绑定时应恰好回退一次: %d", len(titles))
	}
	f.s.DB.Approval.UpdateOneID(lonely.ID).SetStatus(approval.StatusRejected).ExecX(f.ctx)

	// 已送达有权审批人：不回退。
	bindUser(t, f, f.u, "open-1")
	a := pendingApproval(t, f)
	delivered(t, f, a)
	age("approvals")
	age("feishu_approval_deliveries")
	run()
	if len(titles) != 1 {
		t.Fatal("已送达仍回退")
	}

	// 配置重存：旧卡片作废，未决申请在新版本下重新投递；新版本迟迟送不到才回退。
	f.c.Revision = uuid.NewString()
	b, _ := json.Marshal(f.c)
	f.s.DB.Setting.UpdateOneID(configKey).SetValue(b).SaveX(f.ctx)
	run()
	var revision, messageID string
	if err := f.s.SQL.QueryRowContext(f.ctx, `SELECT revision,message_id FROM feishu_approval_deliveries WHERE approval_id=$1`, a.ID).Scan(&revision, &messageID); err != nil {
		t.Fatal(err)
	}
	if revision != f.c.Revision || messageID != "" {
		t.Fatal("配置重存后未重新投递待审批申请")
	}
	if len(titles) != 1 {
		t.Fatal("重新投递窗口内不应回退")
	}
	age("feishu_approval_deliveries")
	run()
	if len(titles) != 2 {
		t.Fatal("新版本未送达时应回退")
	}
}
