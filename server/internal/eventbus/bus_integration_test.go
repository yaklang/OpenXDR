//go:build integration

package eventbus

import (
	"context"
	"encoding/json"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"openxdr/server/internal/ingest"
)

type testProcessor struct {
	seen atomic.Int32
	done chan struct{}
}

func (p *testProcessor) Process(_ context.Context, _ ingest.Envelope) error {
	if p.seen.Add(1) == 1 {
		close(p.done)
	}
	return nil
}

type testMetrics struct{}

func (testMetrics) Published(string)               {}
func (testMetrics) PublishFailed()                 {}
func (testMetrics) Failed(string)                  {}
func (testMetrics) SetQueuePending(string, uint64) {}

func TestJetStreamPublishConsumeAndDeduplicate(t *testing.T) {
	url := os.Getenv("NATS_URL")
	if url == "" {
		t.Skip("NATS_URL 未配置")
	}
	p := &testProcessor{done: make(chan struct{})}
	bus, err := NewJetStream(url, "integration", 4, 1, 1<<30, time.Hour, p, testMetrics{})
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	e := ingest.Envelope{Version: ingest.EnvelopeVersion, ID: ingest.StableID(t.Name()), PartitionKey: "asset-a", Timestamp: time.Now(), ClassUID: 1007, Source: "agent", Raw: json.RawMessage(`{}`)}
	if err := bus.Publish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := bus.Publish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Fatal("队列消息未送达")
	}
	time.Sleep(250 * time.Millisecond)
	if got := p.seen.Load(); got != 1 {
		t.Fatalf("相同 Msg-Id 应只消费一次，实际 %d", got)
	}
}
