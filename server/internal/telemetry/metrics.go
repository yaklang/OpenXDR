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
	temporalSkipped *prometheus.CounterVec
	published       *prometheus.CounterVec
	processed       *prometheus.CounterVec
	failed          *prometheus.CounterVec
	alerts          *prometheus.CounterVec
	duration        *prometheus.HistogramVec
	batchDuration   prometheus.Histogram
	batchSize       prometheus.Histogram
	queueDepth      *prometheus.GaugeVec
	queueSampleTime *prometheus.GaugeVec
	queueUnhealthy  prometheus.Gauge
	archiveFailOpen *prometheus.CounterVec
}

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		temporalSkipped: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openxdr_temporal_skipped_total", Help: "时序检测未覆盖的事件数"}, []string{"reason"}),
		published:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openxdr_events_published_total", Help: "发布到处理管线的事件数"}, []string{"source"}),
		processed:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openxdr_events_processed_total", Help: "处理完成的事件数"}, []string{"source", "duplicate"}),
		failed:          prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openxdr_pipeline_failures_total", Help: "处理管线失败数"}, []string{"stage"}),
		alerts:          prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openxdr_alerts_created_total", Help: "新建告警数"}, []string{"source"}),
		duration:        prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "openxdr_event_processing_seconds", Help: "单事件处理耗时（不含等待同批其他事件与提交）", Buckets: prometheus.DefBuckets}, []string{"source"}),
		batchDuration:   prometheus.NewHistogram(prometheus.HistogramOpts{Name: "openxdr_event_batch_seconds", Help: "整批入库事务耗时（含取锁与提交）", Buckets: prometheus.DefBuckets}),
		batchSize:       prometheus.NewHistogram(prometheus.HistogramOpts{Name: "openxdr_event_batch_size", Help: "每批入库的事件数", Buckets: []float64{1, 2, 4, 8, 16, 32, 64, 128}}),
		queueDepth:      prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "openxdr_queue_pending_messages", Help: "JetStream 分片待处理消息"}, []string{"shard"}),
		queueSampleTime: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "openxdr_queue_sample_timestamp_seconds", Help: "JetStream 分片最近一次成功采样的 Unix 时间（0 表示尚未成功）"}, []string{"shard"}),
		queueUnhealthy:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "openxdr_queue_replicas_unhealthy", Help: "事件流不在同步状态的副本数（含流 leader 不可达）"}),
		archiveFailOpen: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openxdr_archive_dedup_failopen_total", Help: "冷归档重传判重拿不准而按未归档继续入库的事件数（阶段：boundary 边界查询、lookup 按 ID 定位）"}, []string{"stage"}),
	}
	reg.MustRegister(m.temporalSkipped, m.published, m.processed, m.failed, m.alerts, m.duration, m.batchDuration, m.batchSize, m.queueDepth, m.queueSampleTime, m.queueUnhealthy, m.archiveFailOpen)
	return m
}

func (m *Metrics) TemporalSkipped(reason string) { m.temporalSkipped.WithLabelValues(reason).Inc() }

// ArchiveFailOpen 冷归档判重 fail-open 的累计次数：这部分事件照常入库与检测，
// 运维据此判断「重传判重当前是否可靠」。
func (m *Metrics) ArchiveFailOpen(stage string) { m.archiveFailOpen.WithLabelValues(stage).Inc() }

func (m *Metrics) Published(source string) { m.published.WithLabelValues(source).Inc() }
func (m *Metrics) PublishFailed()          { m.failed.WithLabelValues("publish").Inc() }
func (m *Metrics) Failed(stage string)     { m.failed.WithLabelValues(stage).Inc() }
func (m *Metrics) Processed(source string, duplicate bool, alerts int, elapsed time.Duration) {
	m.processed.WithLabelValues(source, strconv.FormatBool(duplicate)).Inc()
	m.alerts.WithLabelValues(source).Add(float64(alerts))
	m.duration.WithLabelValues(source).Observe(elapsed.Seconds())
}
func (m *Metrics) Batch(events int, elapsed time.Duration) {
	m.batchSize.Observe(float64(events))
	m.batchDuration.Observe(elapsed.Seconds())
}
func (m *Metrics) SetQueuePending(shard string, count uint64) {
	m.queueDepth.WithLabelValues(shard).Set(float64(count))
}
func (m *Metrics) SetQueueSampleTimestamp(shard string, timestamp float64) {
	m.queueSampleTime.WithLabelValues(shard).Set(timestamp)
}
func (m *Metrics) SetQueueReplicasUnhealthy(count int) { m.queueUnhealthy.Set(float64(count)) }

func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
