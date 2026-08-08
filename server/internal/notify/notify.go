// Package notify 告警通知：把研判后的 incident 推到 webhook。
// "一万条进三个出"——那三个出来了得有人知道，不能指望有人一直盯着屏幕。
//
// 投递语义：
//   - AI 启用时等研判完成再推，避免推完 AI 又改口；未启用则事件一出就推
//   - benign 判定静默跳过：AI 说是噪声的不打扰人
//   - 通知器启动前的历史事件不补发，防止首次启用时轰炸群
//   - 发送失败不落投递标记，下个周期自动重试
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
)

type Notifier struct {
	DB *ent.Client
	// 目标 webhook，空则整个通知器不启用
	URL string
	// generic / dingtalk / feishu / wecom
	Format   string
	Interval time.Duration
	// AI 启用时为 true：等 verdict 出来再推
	WaitTriage bool
	// 拼进消息的控制台链接前缀，如 https://xdr.example.com
	LinkBase string
	// 低于该级别的事件不推送，0 表示全推。降噪的最后一道闸
	MinSeverity int16
	Client      *http.Client

	start time.Time
}

func (n *Notifier) Run(ctx context.Context) {
	if n.URL == "" {
		slog.Warn("告警通知未启用：未配置 WEBHOOK_URL")
		return
	}
	if n.Client == nil {
		n.Client = &http.Client{Timeout: 10 * time.Second}
	}
	n.start = time.Now()
	ticker := time.NewTicker(n.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := n.sweep(ctx); err != nil {
				slog.Error("通知批次失败", "err", err)
			}
		}
	}
}

// verdict 只取通知需要的三个字段，其余留给界面
type verdict struct {
	Verdict    string `json:"verdict"`
	Confidence int    `json:"confidence"`
	Summary    string `json:"summary"`
}

func (n *Notifier) sweep(ctx context.Context) error {
	incidents, err := n.DB.Incident.Query().
		Where(incident.NotifiedAtIsNil()).
		Order(ent.Asc(incident.FieldCreatedAt)).
		Limit(20).
		All(ctx)
	if err != nil {
		return err
	}

	for _, inc := range incidents {
		send, why := n.decide(inc)
		if !send {
			if why == "wait" {
				continue // 等研判，先不落标记
			}
			if err := n.markNotified(ctx, inc); err != nil {
				return err
			}
			continue
		}
		msg, err := n.message(ctx, inc)
		if err != nil {
			return err
		}
		if msg.Severity < n.MinSeverity {
			if err := n.markNotified(ctx, inc); err != nil {
				return err
			}
			continue
		}
		if err := n.post(ctx, msg); err != nil {
			slog.Error("webhook 推送失败，下周期重试", "incident", inc.ID, "err", err)
			continue
		}
		if err := n.markNotified(ctx, inc); err != nil {
			return err
		}
		slog.Info("incident 已推送", "id", inc.ID)
	}
	return nil
}

// decide 是否推送。返回 (false, "wait") 表示暂缓，(false, 其他) 表示静默跳过。
func (n *Notifier) decide(inc *ent.Incident) (bool, string) {
	if inc.CreatedAt.Before(n.start) {
		return false, "历史事件不补发"
	}
	// 分析师已经处理过的不用再喊人
	if inc.Status == "closed" || inc.Status == "false_positive" {
		return false, "已人工处理"
	}
	if len(inc.AiVerdict) == 0 {
		if n.WaitTriage {
			return false, "wait"
		}
		return true, "" // AI 未启用，事件即推
	}
	var v verdict
	_ = json.Unmarshal(inc.AiVerdict, &v)
	if v.Verdict == "benign" {
		return false, "AI 判定良性"
	}
	return true, ""
}

func (n *Notifier) markNotified(ctx context.Context, inc *ent.Incident) error {
	return n.DB.Incident.UpdateOneID(inc.ID).SetNotifiedAt(time.Now()).Exec(ctx)
}

// Message 通知内容，也是 generic 格式的推送体。
type Message struct {
	IncidentID string    `json:"incidentId"`
	CreatedAt  time.Time `json:"createdAt"`
	Title      string    `json:"title"`
	Verdict    string    `json:"verdict,omitempty"`
	Confidence int       `json:"confidence,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	AlertCount int       `json:"alertCount"`
	Severity   int16     `json:"maxSeverity"`
	Link       string    `json:"link,omitempty"`
}

func (n *Notifier) message(ctx context.Context, inc *ent.Incident) (Message, error) {
	alerts, err := n.DB.Alert.Query().
		Where(alert.IncidentIDEQ(inc.ID)).
		All(ctx)
	if err != nil {
		return Message{}, err
	}
	m := Message{IncidentID: inc.ID.String(), CreatedAt: inc.CreatedAt, AlertCount: len(alerts)}
	for _, a := range alerts {
		if a.Severity > m.Severity {
			m.Severity = a.Severity
		}
	}
	if inc.Title != nil {
		m.Title = *inc.Title
	}
	if len(inc.AiVerdict) > 0 {
		var v verdict
		_ = json.Unmarshal(inc.AiVerdict, &v)
		m.Verdict, m.Confidence, m.Summary = v.Verdict, v.Confidence, v.Summary
	}
	if n.LinkBase != "" {
		m.Link = n.LinkBase + "/?incident=" + m.IncidentID
	}
	return m, nil
}

var severityText = []string{"-", "信息", "低危", "中危", "高危", "严重"}

var verdictText = map[string]string{"malicious": "恶意", "suspicious": "可疑"}

// text 各家 IM 共用的正文。
func text(m Message) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "【OpenXDR】%s\n", m.Title)
	if m.Verdict != "" {
		label := verdictText[m.Verdict]
		if label == "" {
			label = m.Verdict
		}
		fmt.Fprintf(&b, "AI 判定: %s（置信度 %d）\n", label, m.Confidence)
	}
	sev := fmt.Sprint(m.Severity)
	if int(m.Severity) < len(severityText) && m.Severity > 0 {
		sev = severityText[m.Severity]
	}
	fmt.Fprintf(&b, "告警 %d 条，最高级别: %s\n", m.AlertCount, sev)
	if m.Summary != "" {
		fmt.Fprintf(&b, "%s\n", m.Summary)
	}
	if m.Link != "" {
		fmt.Fprintf(&b, "%s\n", m.Link)
	}
	return b.String()
}

// payload 按目标平台包装消息体。未知格式按 generic 处理。
func payload(format string, m Message) []byte {
	var v any
	switch format {
	case "dingtalk":
		v = map[string]any{"msgtype": "text", "text": map[string]string{"content": text(m)}}
	case "feishu":
		v = map[string]any{"msg_type": "text", "content": map[string]string{"text": text(m)}}
	case "wecom":
		v = map[string]any{"msgtype": "text", "text": map[string]string{"content": text(m)}}
	default:
		v = m
	}
	b, _ := json.Marshal(v)
	return b
}

func (n *Notifier) post(ctx context.Context, m Message) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL,
		bytes.NewReader(payload(n.Format, m)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook 返回 %d", resp.StatusCode)
	}
	return nil
}
