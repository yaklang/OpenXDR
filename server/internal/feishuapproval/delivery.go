package feishuapproval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/approval"
	"openxdr/server/internal/auth"
)

type delivery struct {
	Nonce                     string
	ApprovalID                *uuid.UUID
	UserID                    uuid.UUID
	Tenant, OpenID, MessageID string
	Expires                   time.Time
}

// 固定飞书官方域名；不接受任意 API 地址或跳转，避免密钥被重定向到其他服务。
func (s *Service) api(ctx context.Context, path, token string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://open.feishu.cn/open-apis"+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("飞书网络请求失败")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("飞书 HTTP 状态 %d", resp.StatusCode)
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(out); err != nil {
		return errors.New("飞书响应格式无效")
	}
	return nil
}

func (s *Service) accessToken(ctx context.Context, c Config) (string, error) {
	s.mu.RLock()
	token, rev, until := s.token, s.tokenRevision, s.tokenUntil
	s.mu.RUnlock()
	if rev == c.Revision && time.Now().Before(until) {
		return token, nil
	}
	if s.Vault == nil {
		return "", errors.New("应用凭据不可用")
	}
	secret, err := s.Vault.Open(c.Sealed, "feishu-approval:"+c.AppID)
	if err != nil {
		return "", errors.New("应用凭据不可用")
	}
	var result struct {
		Code   int    `json:"code"`
		Token  string `json:"tenant_access_token"`
		Expire int    `json:"expire"`
	}
	err = s.api(ctx, "/auth/v3/tenant_access_token/internal", "", map[string]string{"app_id": c.AppID, "app_secret": secret.Password}, &result)
	if err != nil {
		return "", err
	}
	if result.Code != 0 || result.Token == "" {
		return "", fmt.Errorf("飞书鉴权代码 %d", result.Code)
	}
	s.mu.Lock()
	s.token = result.Token
	s.tokenRevision = c.Revision
	s.tokenUntil = time.Now().Add(time.Duration(max(0, result.Expire-120)) * time.Second)
	s.mu.Unlock()
	return result.Token, nil
}

func (s *Service) send(ctx context.Context, c Config, d delivery, card map[string]any) (string, error) {
	token, err := s.accessToken(ctx, c)
	if err != nil {
		return "", err
	}
	content, _ := json.Marshal(card)
	var result struct {
		Code int `json:"code"`
		Data struct {
			MessageID string `json:"message_id"`
		} `json:"data"`
	}
	err = s.api(ctx, "/im/v1/messages?receive_id_type=open_id", token, map[string]string{"receive_id": d.OpenID, "msg_type": "interactive", "content": string(content), "uuid": d.Nonce}, &result)
	if err != nil {
		return "", err
	}
	if result.Code != 0 || result.Data.MessageID == "" {
		return "", fmt.Errorf("飞书发送代码 %d", result.Code)
	}
	return result.Data.MessageID, nil
}

func plain(content string) map[string]any {
	return map[string]any{"tag": "plain_text", "content": content}
}
func paragraph(content string) map[string]any {
	return map[string]any{"tag": "div", "text": plain(content)}
}
func button(label, action, nonce, style string) map[string]any {
	return map[string]any{"tag": "button", "text": plain(label), "type": style, "value": map[string]string{"action": action, "nonce": nonce}}
}
func cardBody(title string, elements []any) map[string]any {
	return map[string]any{"config": map[string]any{"wide_screen_mode": true, "enable_forward": false}, "header": map[string]any{"title": plain(title), "template": "orange"}, "elements": elements}
}
func statusCard(text string) map[string]any {
	return cardBody("OpenXDR 审批状态", []any{paragraph(text)})
}

func directCommand(cmd string) bool {
	if !utf8.ValidString(cmd) || utf8.RuneCountInString(cmd) > 4000 {
		return false
	}
	for _, r := range cmd {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return cmd != ""
}

func (s *Service) card(ctx context.Context, d delivery, a *ent.Approval) map[string]any {
	if a == nil {
		return cardBody("OpenXDR 私聊连接测试", []any{paragraph("此卡片仅验证本人身份和按钮回调，不执行任何主机命令。请点击下方按钮。"), map[string]any{"tag": "action", "actions": []any{button("验证私聊回调", "test", d.Nonce, "primary")}}})
	}
	host, group := a.AssetID.String(), a.GroupID.String()
	if v, err := s.DB.Asset.Get(ctx, a.AssetID); err == nil {
		host = v.Hostname
	}
	if v, err := s.DB.Group.Get(ctx, a.GroupID); err == nil {
		group = v.Name
	}
	fields := fmt.Sprintf("组：%s\n主机：%s\n发起人：%s\n审批 ID：%s\n到期：%s", group, host, a.RequestedBy, a.ID, a.ExpiresAt.UTC().Format(time.RFC3339))
	elements := []any{paragraph(fields)}
	if !directCommand(a.Cmd) {
		return cardBody("OpenXDR 待审批", append(elements, paragraph("命令过长或含不可见控制字符，不能安全完整展示。请进入 OpenXDR 审批中心核对原始命令后处理；本卡片不提供批准按钮。")))
	}
	elements = append(elements, paragraph("完整命令（以下为命令内容，不是审批说明）：\n"+a.Cmd), paragraph("批准只授权此条命令；实际执行结果以平台回执为准。"), map[string]any{"tag": "action", "actions": []any{button("批准执行", "approve", d.Nonce, "primary"), button("拒绝", "reject", d.Nonce, "danger")}})
	return cardBody("OpenXDR 命令待审批", elements)
}

// 单活轮询持久审批队列，避免修改原有执行链，也覆盖其他 Server 创建的申请。
func (s *Service) enqueue(ctx context.Context, c Config) error {
	approvals, err := s.DB.Approval.Query().Where(approval.StatusEQ(approval.StatusPending), approval.ExpiresAtGT(time.Now())).Order(ent.Asc(approval.FieldCreatedAt)).Limit(200).All(ctx)
	if err != nil {
		return err
	}
	rows, err := s.SQL.QueryContext(ctx, `SELECT user_id,tenant,open_id FROM feishu_approval_bindings WHERE app_id=$1`, c.AppID)
	if err != nil {
		return err
	}
	var recipients []delivery
	for rows.Next() {
		var d delivery
		if err = rows.Scan(&d.UserID, &d.Tenant, &d.OpenID); err != nil {
			rows.Close()
			return err
		}
		recipients = append(recipients, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, d := range recipients {
		u, err := s.DB.User.Get(ctx, d.UserID)
		if err != nil {
			continue
		}
		for _, a := range approvals {
			if !auth.Allowed(auth.GroupRole(ctx, s.DB, u, a.GroupID), "admin") {
				continue
			}
			_, err = s.SQL.ExecContext(ctx, `INSERT INTO feishu_approval_deliveries(nonce,approval_id,user_id,app_id,revision,tenant,open_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(approval_id,user_id) DO NOTHING`, uuid.NewString(), a.ID, d.UserID, c.AppID, c.Revision, d.Tenant, d.OpenID, a.ExpiresAt)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) deliver(ctx context.Context, c Config) error {
	rows, err := s.SQL.QueryContext(ctx, `SELECT nonce,approval_id,user_id,tenant,open_id,expires_at FROM feishu_approval_deliveries WHERE app_id=$1 AND revision=$2 AND message_id='' AND expires_at>now() AND attempts<3 AND next_attempt<=now() ORDER BY created_at LIMIT 20`, c.AppID, c.Revision)
	if err != nil {
		return err
	}
	var pending []delivery
	for rows.Next() {
		var d delivery
		if err = rows.Scan(&d.Nonce, &d.ApprovalID, &d.UserID, &d.Tenant, &d.OpenID, &d.Expires); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, d := range pending {
		current, err := readConfig(ctx, s.SQL, false)
		if err != nil || !validConfig(current) || current.Revision != c.Revision {
			return errors.New("配置已变化")
		}
		var bound bool
		err = s.SQL.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM feishu_approval_bindings WHERE app_id=$1 AND user_id=$2 AND tenant=$3 AND open_id=$4)`, c.AppID, d.UserID, d.Tenant, d.OpenID).Scan(&bound)
		if err != nil {
			return err
		}
		if !bound {
			continue
		}
		var a *ent.Approval
		if d.ApprovalID != nil {
			a, err = s.DB.Approval.Get(ctx, *d.ApprovalID)
			if err != nil || a.Status != approval.StatusPending || !time.Now().Before(a.ExpiresAt) {
				continue
			}
			u, e := s.DB.User.Get(ctx, d.UserID)
			if e != nil || !auth.Allowed(auth.GroupRole(ctx, s.DB, u, a.GroupID), "admin") {
				continue
			}
		}
		// 先记尝试再调用；uuid 在超时重试时不变，由飞书去重。不无限重发。
		_, err = s.SQL.ExecContext(ctx, `UPDATE feishu_approval_deliveries SET attempts=attempts+1,next_attempt=now()+interval '30 seconds' WHERE nonce=$1`, d.Nonce)
		if err != nil {
			return err
		}
		id, err := s.send(ctx, c, d, s.card(ctx, d, a))
		if err != nil {
			s.setState(err.Error())
			continue
		}
		_, err = s.SQL.ExecContext(ctx, `UPDATE feishu_approval_deliveries SET message_id=$2 WHERE nonce=$1`, d.Nonce, id)
		if err != nil {
			return err
		}
	}
	return nil
}
