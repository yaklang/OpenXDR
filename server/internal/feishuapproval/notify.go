package feishuapproval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/approval"
)

// fallbackAfter 内没有任何有权审批人收到卡片，就改走原 Webhook，审批通知不能静默丢失。
const fallbackAfter = 30 * time.Second

// ApprovalNotifier 只用于命令审批通知。飞书配置完整启用时，由持久投递队列发送私聊卡片，
// 未在 fallbackAfter 内送达任何有权审批人的申请由 Service.fallback 回退到原通知器；
// 未启用或配置不完整时直接走原通知器。普通告警和报告继续直接使用原通知器。每次读取配置，控制台启停即时生效。
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
			if validConfig(config) {
				return nil
			}
		}
		if fallback != nil {
			return fallback(ctx, title, body, path)
		}
		return nil
	}
}

// fallback 把超时仍未送达任何有权审批人的待审批申请改发原通知器；每条申请只回退一次。
// 覆盖长连接或凭据故障、无人绑定、绑定人无组权限、卡片发送失败、配置重存后未重新送达等情况。
func (s *Service) fallback(ctx context.Context, c Config) error {
	if s.Fallback == nil {
		return nil
	}
	rows, err := s.SQL.QueryContext(ctx, `SELECT a.id FROM approvals a WHERE a.status='pending' AND a.expires_at>now() AND a.created_at<now()-make_interval(secs=>$3)
 AND NOT EXISTS(SELECT 1 FROM feishu_approval_deliveries d WHERE d.approval_id=a.id AND d.app_id=$1 AND d.revision=$2 AND (d.message_id<>'' OR d.created_at>now()-make_interval(secs=>$3)))
 AND NOT EXISTS(SELECT 1 FROM feishu_approval_fallbacks f WHERE f.approval_id=a.id)
 ORDER BY a.created_at LIMIT 50`, c.AppID, c.Revision, fallbackAfter.Seconds())
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		// 先占位再发送：发送失败只记日志，不每轮重复刷屏。
		res, err := s.SQL.ExecContext(ctx, `INSERT INTO feishu_approval_fallbacks(approval_id) VALUES($1) ON CONFLICT DO NOTHING`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			continue
		}
		a, err := s.DB.Approval.Get(ctx, id)
		if err != nil {
			return err
		}
		title, text := s.fallbackMessage(ctx, a)
		slog.Warn("飞书审批卡片未送达任何有权审批人，审批通知回退到 Webhook", "approval", id)
		sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = s.Fallback(sendCtx, title, text, "/approvals")
		cancel()
		if err != nil {
			slog.Error("审批通知回退发送失败", "approval", id, "err", err)
		}
	}
	return nil
}

// fallbackMessage 与命令闸门的原审批通知同一格式。
func (s *Service) fallbackMessage(ctx context.Context, a *ent.Approval) (string, string) {
	group, host := a.GroupID.String(), a.AssetID.String()
	if v, err := s.DB.Group.Get(ctx, a.GroupID); err == nil {
		group = v.Name
	}
	if v, err := s.DB.Asset.Get(ctx, a.AssetID); err == nil {
		host = v.Hostname
	}
	cmd := []rune(a.Cmd)
	if len(cmd) > 300 {
		cmd = append(cmd[:300], []rune("…")...)
	}
	title := "待批准：人工请求执行高风险命令"
	if a.Origin == approval.OriginAi {
		title = "待批准：AI 请求执行高风险命令"
	}
	return title, fmt.Sprintf("组：%s\n主机：%s\n发起：%s\n命令：%s\n（飞书私聊卡片未送达有权审批人，改由本渠道通知）", group, host, a.RequestedBy, string(cmd))
}
