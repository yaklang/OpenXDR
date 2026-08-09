package telemetry

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsLabelingAndCounters(t *testing.T) {
	m := New(prometheus.NewRegistry())

	m.Published("agent")
	m.Published("agent")
	m.Published("sensor")

	if got := testutil.ToFloat64(m.published.WithLabelValues("agent")); got != 2 {
		t.Errorf("published[agent] = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.published.WithLabelValues("sensor")); got != 1 {
		t.Errorf("published[sensor] = %v, want 1", got)
	}

	m.Failed("ingest")
	m.Failed("dedup")
	if got := testutil.ToFloat64(m.failed.WithLabelValues("ingest")); got != 1 {
		t.Errorf("failed[ingest] = %v, want 1", got)
	}

	m.PublishFailed()
	if got := testutil.ToFloat64(m.failed.WithLabelValues("publish")); got != 1 {
		t.Errorf("failed[publish] = %v, want 1", got)
	}
}

func TestProcessedAggregates(t *testing.T) {
	m := New(prometheus.NewRegistry())

	m.Processed("agent", true, 3, 250*time.Millisecond)
	m.Processed("agent", false, 1, 500*time.Millisecond)

	c := m.processed.WithLabelValues("agent", "true")
	if got := testutil.ToFloat64(c); got != 1 {
		t.Errorf("processed[agent,true] = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.processed.WithLabelValues("agent", "false")); got != 1 {
		t.Errorf("processed[agent,false] = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.alerts.WithLabelValues("agent")); got != 4 {
		t.Errorf("alerts[agent] = %v, want 4", got)
	}
}

func TestQueueDepth(t *testing.T) {
	m := New(prometheus.NewRegistry())
	m.SetQueuePending("shard-0", 42)
	if got := testutil.ToFloat64(m.queueDepth.WithLabelValues("shard-0")); got != 42 {
		t.Errorf("queueDepth[shard-0] = %v, want 42", got)
	}
}
