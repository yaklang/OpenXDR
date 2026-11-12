package notify

// 通知渠道看门狗：推送目标被清空或连续发送失败时，该推的事件会一直积着没人知道。
// 发送结果存在 settings 表里而不是推送 leader 的内存：控制台与 /metrics 可能落在任一节点，
// 换 leader 后也不丢历史。多节点同时写（任务报告、审批回退走 Webhook.Send）可能丢一次计数，
// 连续失败数是近似值，不影响"正在失败"的判断。

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"openxdr/server/ent/setting"
	"openxdr/server/internal/review"
)

const healthKey = "notify.health"

// PendingAfter 事件创建超过这么久仍没推送才算积压，给研判与推送周期留出余量
const PendingAfter = 15 * time.Minute

// FailingAfter 连续失败这么多次才算渠道故障，偶发超时不报
const FailingAfter = 3

// WarnEvery 渠道异常且有积压时，日志告警的最小间隔
const WarnEvery = 10 * time.Minute

// sendState 最近的发送结果
type sendState struct {
	LastSuccessAt       *time.Time `json:"lastSuccessAt,omitempty"`
	LastFailureAt       *time.Time `json:"lastFailureAt,omitempty"`
	LastError           string     `json:"lastError,omitempty"`
	ConsecutiveFailures int        `json:"consecutiveFailures"`
}

// Health 通知渠道健康：ok / unconfigured（没配推送目标）/ failing（连续失败）。
type Health struct {
	Status string `json:"status"`
	// PendingIncidents 需人工处理、该推却超过 PendingAfter 还没推的事件数
	PendingIncidents int `json:"pendingIncidents"`
	sendState
}

// Delivering 渠道正常；不正常且有积压时才需要喊人
func (h Health) Delivering() bool { return h.Status == "ok" }

// Pending 该推却还没推的事件，与 sweep 同一口径：没落投递标记、不是纯诱饵观察、需人工处理（review.Needed）且不走每日汇总（review.SevereBenign）、
// 最高级别达到推送门槛，且创建早于 before。没配目标期间这些事件不会落标记，配上后启用前的不补发，
// 所以这里数到的就是"本该有人收到却没收到"的
func Pending(t Target, before time.Time) predicate.Incident {
	ps := []predicate.Incident{incident.NotifiedAtIsNil(), incident.Not(review.DecoyOnly()), review.Needed(), incident.Not(review.SevereBenign()), incident.CreatedAtLT(before)}
	if t.MinSeverity > 0 {
		ps = append(ps, incident.HasAlertsWith(alert.SeverityGTE(t.MinSeverity)))
	}
	return incident.And(ps...)
}

// Health 当前渠道健康。scope 限定计数范围（控制台按用户可见范围），指标与日志不传
func (s *Settings) Health(ctx context.Context, scope ...predicate.Incident) (Health, error) {
	t := s.Load(ctx)
	h := Health{Status: "ok", sendState: s.state(ctx)}
	switch {
	case t.URL == "":
		h.Status = "unconfigured"
	case h.ConsecutiveFailures >= FailingAfter:
		h.Status = "failing"
	}
	n, err := s.DB.Incident.Query().Where(Pending(t, time.Now().Add(-PendingAfter))).Where(scope...).Count(ctx)
	h.PendingIncidents = n
	return h, err
}

func (s *Settings) state(ctx context.Context) sendState {
	var st sendState
	row, err := s.DB.Setting.Get(ctx, healthKey)
	if err != nil {
		if !ent.IsNotFound(err) {
			slog.Warn("读取通知发送状态失败", "err", err)
		}
		return st
	}
	if err := json.Unmarshal(row.Value, &st); err != nil {
		slog.Warn("通知发送状态损坏，按空状态处理", "err", err)
	}
	return st
}

// Record 记一次真实推送（不含"发送测试"）的结果：成功清零连续失败，失败累加并留下原因
func (s *Settings) Record(ctx context.Context, sendErr error) {
	st := s.state(ctx)
	now := time.Now()
	if sendErr == nil {
		st.LastSuccessAt, st.ConsecutiveFailures = &now, 0
	} else {
		st.LastFailureAt, st.LastError = &now, reason(sendErr)
		st.ConsecutiveFailures++
	}
	s.saveState(ctx, st)
}

func (s *Settings) saveState(ctx context.Context, st sendState) {
	value, _ := json.Marshal(st)
	n, err := s.DB.Setting.Update().Where(setting.IDEQ(healthKey)).SetValue(value).Save(ctx)
	if err == nil && n == 0 {
		err = s.DB.Setting.Create().SetID(healthKey).SetValue(value).Exec(ctx)
	}
	if err != nil {
		slog.Warn("保存通知发送状态失败", "err", err)
	}
}

// redact 去掉错误里的请求地址：webhook 地址里常带 token，不能进日志、接口与指标。
// 只剥 url.Error 外壳，内层错误链（超时、取消）保留给调用方判断
func redact(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

// reason 存进健康状态的失败原因：去掉地址并截断
func reason(err error) string {
	r := []rune(redact(err).Error())
	if len(r) > 200 {
		r = append(r[:200], '…')
	}
	return string(r)
}

// watch 渠道异常且有积压时打 WARN，最多每 WarnEvery 一次。只在推送 leader 上跑，集群里不重复
func (n *Notifier) watch(ctx context.Context) {
	if time.Since(n.warned) < WarnEvery {
		return
	}
	h, err := n.Settings.Health(ctx)
	if err != nil {
		slog.Error("通知健康检查失败", "err", err)
		return
	}
	if h.Delivering() || h.PendingIncidents == 0 {
		return
	}
	n.warned = time.Now()
	why := "未配置推送目标"
	if h.Status == "failing" {
		why = h.LastError
	}
	slog.Warn("通知未送达：有需人工处理的事件没有推送", "pending", h.PendingIncidents, "status", h.Status,
		"consecutiveFailures", h.ConsecutiveFailures, "reason", why)
}

// healthCollector 抓取时现查数据库：推送只在 leader 上跑，现查让每个节点报的都是同一份
type healthCollector struct {
	s                                          *Settings
	configured, pending, failures, lastSuccess *prometheus.Desc
}

// NewHealthCollector 暴露 openxdr_notify_configured / _pending_incidents / _consecutive_failures /
// _last_success_timestamp_seconds
func NewHealthCollector(s *Settings) prometheus.Collector {
	return &healthCollector{s: s,
		configured:  prometheus.NewDesc("openxdr_notify_configured", "通知推送目标是否已配置（1 已配置，0 未配置）", nil, nil),
		pending:     prometheus.NewDesc("openxdr_notify_pending_incidents", "需人工处理、创建超过 15 分钟仍未推送的事件数", nil, nil),
		failures:    prometheus.NewDesc("openxdr_notify_consecutive_failures", "通知连续发送失败次数，成功一次清零", nil, nil),
		lastSuccess: prometheus.NewDesc("openxdr_notify_last_success_timestamp_seconds", "最近一次推送成功的 Unix 时间（0 表示从未成功）", nil, nil),
	}
}

func (c *healthCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.configured
	ch <- c.pending
	ch <- c.failures
	ch <- c.lastSuccess
}

func (c *healthCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h, err := c.s.Health(ctx)
	if err != nil {
		// 不让整个 /metrics 失败；指标缺失本身也应在 Grafana 里按 absent 告警
		slog.Warn("通知健康指标查询失败", "err", err)
		return
	}
	configured, last := 1.0, 0.0
	if h.Status == "unconfigured" {
		configured = 0
	}
	if h.LastSuccessAt != nil {
		last = float64(h.LastSuccessAt.Unix())
	}
	ch <- prometheus.MustNewConstMetric(c.configured, prometheus.GaugeValue, configured)
	ch <- prometheus.MustNewConstMetric(c.pending, prometheus.GaugeValue, float64(h.PendingIncidents))
	ch <- prometheus.MustNewConstMetric(c.failures, prometheus.GaugeValue, float64(h.ConsecutiveFailures))
	ch <- prometheus.MustNewConstMetric(c.lastSuccess, prometheus.GaugeValue, last)
}
