package feishuapproval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/larksuite/oapi-sdk-go/v3/event"
	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher"
	"github.com/larksuite/oapi-sdk-go/v3/event/dispatcher/callback"
	larkim "github.com/larksuite/oapi-sdk-go/v3/service/im/v1"
	larkws "github.com/larksuite/oapi-sdk-go/v3/ws"
	"openxdr/server/internal/commandgate"
)

// 官方 SDK 的默认日志包含事件内容和长连接 URL；这里禁止输出这些凭据与命令。
type quietLogger struct{ service *Service }

func (l quietLogger) Debug(_ context.Context, args ...interface{}) {
	if l.service == nil {
		return
	}
	text := fmt.Sprint(args...)
	if !strings.Contains(text, "receive message, message_type:") {
		return
	}
	kind := "other"
	for _, k := range []string{"event", "card"} {
		if strings.Contains(text, "message_type: "+k+",") {
			kind = k
		}
	}
	l.service.recordDiagnostic(map[string]any{"last_frame_type": kind, "last_frame_at": time.Now().UTC()})
}
func (quietLogger) Info(context.Context, ...interface{}) {}
func (quietLogger) Warn(context.Context, ...interface{}) {}
func (l quietLogger) Error(context.Context, ...interface{}) {
	if l.service != nil {
		l.service.recordDiagnostic(map[string]any{"last_sdk_error_at": time.Now().UTC()})
	}
}

func freshHeader(base *larkevent.EventV2Base, c Config, kind string) bool {
	if base == nil || base.Header == nil {
		return false
	}
	h := base.Header
	if h.AppID != c.AppID || h.TenantKey == "" || h.EventType != kind {
		return false
	}
	stamp, err := strconv.ParseInt(h.CreateTime, 10, 64)
	if err != nil {
		return false
	}
	// 私聊消息与卡片回调的时间精度不同：分别可能使用毫秒和微秒。
	// 只接受明确的两种精度，再执行同一时效窗口校验，不能通过单位转换放宽重放限制。
	var at time.Time
	switch len(h.CreateTime) {
	case 13:
		at = time.UnixMilli(stamp)
	case 16:
		at = time.UnixMicro(stamp)
	default:
		return false
	}
	age := time.Since(at)
	return age >= -time.Minute && age < 10*time.Minute
}
func str(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func (s *Service) message(ctx context.Context, c Config, e *larkim.P2MessageReceiveV1) error {
	if e == nil || !freshHeader(e.EventV2Base, c, "im.message.receive_v1") || e.Event == nil || e.Event.Sender == nil || e.Event.Message == nil {
		return nil
	}
	sender, msg := e.Event.Sender, e.Event.Message
	if sender.SenderId == nil || str(sender.SenderType) != "user" || str(msg.ChatType) != "p2p" || str(msg.MessageType) != "text" || str(sender.TenantKey) != e.EventV2Base.Header.TenantKey {
		return nil
	}
	var body struct {
		Text string `json:"text"`
	}
	if len(str(msg.Content)) > 2048 || json.Unmarshal([]byte(str(msg.Content)), &body) != nil {
		return nil
	}
	code := strings.TrimSpace(body.Text)
	if !strings.HasPrefix(code, "OXB-") {
		return nil
	}
	// 只有一次性码绑定成功才改变状态；不向未知私聊或群聊发送响应。
	if err := s.bind(ctx, c, e.EventV2Base.Header.TenantKey, str(sender.SenderId.OpenId), code); err != nil {
		s.setState("binding_rejected")
		return nil
	}
	s.setState("bound")
	return nil
}

func (s *Service) action(ctx context.Context, c Config, e *callback.CardActionTriggerEvent) (*callback.CardActionTriggerResponse, error) {
	diagnostic := map[string]any{"last_callback_at": time.Now().UTC(), "callback_stage": "received"}
	if e != nil && e.EventV2Base != nil && e.EventV2Base.Header != nil {
		h := e.EventV2Base.Header
		diagnostic["app_matches"] = h.AppID == c.AppID
		diagnostic["tenant_present"] = h.TenantKey != ""
		diagnostic["event_type_matches"] = h.EventType == "card.action.trigger"
		diagnostic["event_timestamp"] = h.CreateTime
	}
	if e != nil && e.Event != nil {
		diagnostic["host_matches"] = e.Event.Host == "im_message"
		if e.Event.Operator != nil {
			diagnostic["operator_present"] = e.Event.Operator.OpenID != ""
			diagnostic["operator_tenant_present"] = str(e.Event.Operator.TenantKey) != ""
		}
		if e.Event.Context != nil {
			diagnostic["message_present"] = e.Event.Context.OpenMessageID != ""
		}
	}
	s.recordDiagnostic(diagnostic)
	fail := func(message string) (*callback.CardActionTriggerResponse, error) {
		s.recordDiagnostic(map[string]any{"callback_stage": message})
		return &callback.CardActionTriggerResponse{Toast: &callback.Toast{Type: "error", Content: message}}, nil
	}
	if e == nil || !freshHeader(e.EventV2Base, c, "card.action.trigger") || e.Event == nil || e.Event.Operator == nil || e.Event.Action == nil || e.Event.Context == nil {
		return fail("无法验证审批来源，请进入平台处理")
	}
	req := e.Event
	if req.Host != "im_message" || req.Operator.OpenID == "" || str(req.Operator.TenantKey) != e.EventV2Base.Header.TenantKey || req.Context.OpenMessageID == "" {
		return fail("审批身份不匹配")
	}
	nonce, ok := req.Action.Value["nonce"].(string)
	if !ok || len(nonce) != 36 {
		return fail("审批标识无效")
	}
	action, ok := req.Action.Value["action"].(string)
	if !ok || (action != "approve" && action != "reject" && action != "test") {
		return fail("审批操作无效")
	}
	result, err := s.decide(ctx, c, e.EventV2Base.Header.TenantKey, req.Operator.OpenID, req.Context.OpenMessageID, nonce, action)
	if err != nil {
		return fail("未确认审批结果：卡片可能已失效、已处理或账号无权限，请在平台核对；不要重复申请命令。")
	}
	s.recordDiagnostic(map[string]any{"callback_stage": "verified"})
	return &callback.CardActionTriggerResponse{Toast: &callback.Toast{Type: "success", Content: result}, Card: &callback.Card{Type: "raw", Data: statusCard(result)}}, nil
}

func (s *Service) decide(ctx context.Context, c Config, tenant, openID, messageID, nonce, action string) (string, error) {
	if tenant == "" || openID == "" || messageID == "" || (action != "approve" && action != "reject" && action != "test") {
		return "", errors.New("无效回调")
	}
	tx, err := s.SQL.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	// 持有配置和绑定共享锁直至 Gate.Decide 完成，禁用/解绑不能与决定交错。
	current, err := readConfig(ctx, tx, true)
	if err != nil || !validConfig(current) || current.Revision != c.Revision {
		return "", errors.New("配置已失效")
	}
	var d delivery
	err = tx.QueryRowContext(ctx, `SELECT nonce,approval_id,user_id,expires_at FROM feishu_approval_deliveries WHERE nonce=$1 AND app_id=$2 AND revision=$3 AND tenant=$4 AND open_id=$5 AND message_id=$6 AND expires_at>now() FOR UPDATE`, nonce, c.AppID, c.Revision, tenant, openID, messageID).Scan(&d.Nonce, &d.ApprovalID, &d.UserID, &d.Expires)
	if err != nil {
		return "", errors.New("卡片已失效")
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT open_id FROM feishu_approval_bindings WHERE app_id=$1 AND user_id=$2 AND tenant=$3 AND open_id=$4 FOR SHARE`, c.AppID, d.UserID, tenant, openID).Scan(&existing)
	if err != nil {
		return "", errors.New("绑定已失效")
	}
	u, err := s.DB.User.Get(ctx, d.UserID)
	if err != nil {
		return "", err
	}
	result := ""
	if d.ApprovalID == nil {
		if action != "test" {
			return "", errors.New("连接测试不能批准命令")
		}
		result = "私聊身份及按钮回调验证成功，没有执行主机命令。"
		var outcome string
		if err = tx.QueryRowContext(ctx, `SELECT outcome FROM feishu_approval_deliveries WHERE nonce=$1`, nonce).Scan(&outcome); err != nil {
			return "", err
		}
		if outcome == "test" {
			return result, nil
		}
		if err = sqlAudit(ctx, tx, u.Username, "feishu_private_test_verified", nonce); err != nil {
			return "", err
		}
	} else {
		if action == "test" {
			return "", errors.New("操作不匹配")
		}
		a, err := s.DB.Approval.Get(ctx, *d.ApprovalID)
		if err != nil || !directCommand(a.Cmd) {
			return "", errors.New("请在平台查看完整命令")
		}
		// 唯一有权改变审批状态的入口；内部事务含组权限、有效期、状态 CAS 和审计。
		if err = s.Gate.Decide(commandgate.ViaChannel(ctx, "feishu"), a.ID, u, action == "approve"); err != nil {
			return "", err
		}
		result = "已拒绝，命令不会因本次申请执行。"
		if action == "approve" {
			result = "已批准；是否实际执行成功，请以 OpenXDR 的命令回执为准。"
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE feishu_approval_deliveries SET outcome=$2 WHERE nonce=$1`, nonce, action)
	if err == nil {
		err = tx.Commit()
	}
	// 命令决定已在 Gate 的独立事务内提交并审计；投递状态回写失败不否认已批准的事实。
	if d.ApprovalID != nil {
		return result, nil
	}
	return result, err
}

// 长连接退出（如凭据错误这类不可重试的失败）后按指数退避重连，连上过则从头计时。
const (
	minBackoff = 3 * time.Second
	maxBackoff = 5 * time.Minute
)

// Run 由集群租约驱动。配置改变时关闭旧长连接，并取消其在途回调。
func (s *Service) Run(ctx context.Context) {
	var active string
	var cancel context.CancelFunc
	var done chan struct{}
	var ready *atomic.Bool
	var backoff time.Duration
	var retryAt time.Time
	stop := func() {
		if cancel != nil {
			cancel()
			<-done
			cancel = nil
		}
	}
	defer stop()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		c, err := readConfig(ctx, s.SQL, false)
		if err != nil {
			s.setState("configuration_unavailable")
		} else {
			if c.Revision != active || !validConfig(c) {
				// 配置变了从头计退避，改好的凭据立即生效。
				backoff, retryAt = 0, time.Time{}
				stop()
				active = ""
				s.setState("disabled")
			}
			if validConfig(c) && cancel == nil && s.Vault != nil && time.Now().After(retryAt) {
				secret, e := s.Vault.Open(c.Sealed, "feishu-approval:"+c.AppID)
				if e != nil {
					s.setState("credential_unavailable")
				} else {
					runCtx, stopFn := context.WithCancel(ctx)
					cancel = stopFn
					done = make(chan struct{})
					ready = new(atomic.Bool)
					active = c.Revision
					connected := func() { ready.Store(true); s.setState("connected") }
					handler := dispatcher.NewEventDispatcher("", "").OnP2MessageReceiveV1(func(evtCtx context.Context, e *larkim.P2MessageReceiveV1) error { return s.message(runCtx, c, e) }).OnP2CardActionTrigger(func(evtCtx context.Context, e *callback.CardActionTriggerEvent) (*callback.CardActionTriggerResponse, error) {
						callbackCtx, stop := context.WithTimeout(runCtx, 2500*time.Millisecond)
						defer stop()
						return s.action(callbackCtx, c, e)
					})
					handler.Config.Logger = quietLogger{service: s}
					client := larkws.NewClient(c.AppID, secret.Password, larkws.WithEventHandler(handler), larkws.WithLogger(quietLogger{service: s}), larkws.WithHttpClient(&httpClient), larkws.WithOnReady(connected), larkws.WithOnReconnected(connected), larkws.WithOnError(func(error) { s.setState("connection_error") }), larkws.WithOnReconnecting(func() { s.setState("reconnecting") }), larkws.WithOnDisconnected(func() { s.setState("disconnected") }))
					s.setState("connecting")
					go func(done chan struct{}) { defer close(done); _ = client.Start(runCtx) }(done)
				}
			}
			if validConfig(c) {
				cycle, stopCycle := context.WithTimeout(ctx, 20*time.Second)
				if e := s.enqueue(cycle, c); e == nil {
					_ = s.deliver(cycle, c)
				}
				if e := s.fallback(cycle, c); e != nil {
					slog.Error("审批通知回退检查失败", "err", e)
				}
				stopCycle()
			}
		}
		_, _ = s.SQL.ExecContext(ctx, `DELETE FROM feishu_approval_codes WHERE expires_at<now(); DELETE FROM feishu_approval_deliveries WHERE expires_at<now()-interval '30 days'; DELETE FROM feishu_approval_fallbacks WHERE created_at<now()-interval '30 days'`)
		if done != nil && cancel != nil {
			select {
			case <-done:
				stop()
				if ready.Load() {
					backoff = 0
				}
				backoff = min(max(2*backoff, minBackoff), maxBackoff)
				retryAt = time.Now().Add(backoff)
				s.setState("reconnect_wait")
				slog.Warn("飞书长连接已退出，稍后重连", "after", backoff)
			default:
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// 长连接建连请求也受超时和禁止重定向限制。
var httpClient = http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
