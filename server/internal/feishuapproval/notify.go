package feishuapproval

import (
	"context"
	"encoding/json"
	"errors"

	"openxdr/server/ent"
)

// ApprovalNotifier 只用于命令审批通知。启用应用机器人时，由持久投递队列发送私聊卡片，
// 不再向旧 Webhook 发送命令，也不因未绑定、离线或发送失败自动回退到群聊。
// 普通告警和报告继续直接使用原通知器。每次读取配置，控制台启停即时生效。
func ApprovalNotifier(db *ent.Client, fallback func(context.Context, string, string, string) error) func(context.Context, string, string, string) error {
	return func(ctx context.Context, title, body, path string) error {
		row, err := db.Setting.Get(ctx, configKey)
		if err != nil && !ent.IsNotFound(err) {
			return errors.New("无法读取审批通知渠道配置，本次未向 Webhook 发送")
		}
		if row != nil {
			var config Config
			if json.Unmarshal(row.Value, &config) != nil {
				return errors.New("审批通知渠道配置无效，本次未向 Webhook 发送")
			}
			if config.Enabled {
				return nil
			}
		}
		if fallback != nil {
			return fallback(ctx, title, body, path)
		}
		return nil
	}
}
