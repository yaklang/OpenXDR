// Package telemetry 暴露队列、处理链与服务健康度指标。
package telemetry

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	published  *prometheus.CounterVec
	processed  *prometheus.CounterVec
	failed     *prometheus.CounterVec
	alerts     *prometheus.CounterVec
	duration   *prometheus.HistogramVec
	queueDepth *prometheus.GaugeVec
}

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		published:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openxdr_events_published_total", Help: "发布到处理管线的事件数"}, []string{"source"}),
		processed:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openxdr_events_processed_total", Help: "处理完成的事件数"}, []string{"source", "duplicate"}),
		failed:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openxdr_pipeline_failures_total", Help: "处理管线失败数"}, []string{"stage"}),
		alerts:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openxdr_alerts_created_total", Help: "新建告警数"}, []string{"source"}),
		duration:   prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "openxdr_event_processing_seconds", Help: "单事件处理耗时", Buckets: prometheus.DefBuckets}, []string{"source"}),
		queueDepth: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "openxdr_queue_pending_messages", Help: "JetStream 分片待处理消息"}, []string{"shard"}),
	}
	reg.MustRegister(m.published, m.processed, m.failed, m.alerts, m.duration, m.queueDepth)
	return m
}

func (m *Metrics) Published(source string) { m.published.WithLabelValues(source).Inc() }
func (m *Metrics) PublishFailed()          { m.failed.WithLabelValues("publish").Inc() }
func (m *Metrics) Failed(stage string)     { m.failed.WithLabelValues(stage).Inc() }
func (m *Metrics) Processed(source string, duplicate bool, alerts int, elapsed time.Duration) {
	m.processed.WithLabelValues(source, strconv.FormatBool(duplicate)).Inc()
	m.alerts.WithLabelValues(source).Add(float64(alerts))
	m.duration.WithLabelValues(source).Observe(elapsed.Seconds())
}
func (m *Metrics) SetQueuePending(shard string, count uint64) {
	m.queueDepth.WithLabelValues(shard).Set(float64(count))
}

func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
