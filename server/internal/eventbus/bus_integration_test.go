//go:build integration

package eventbus

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"openxdr/server/internal/ingest"
	"openxdr/server/internal/natsretry"
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
func (testMetrics) SetQueueReplicasUnhealthy(int)  {}

// 流暂时没有 leader（这里用删流模拟选主空档）时 NATS 回 no responders：发布在服务端内部重试吸收，
// 流恢复后照常写入；一直不恢复则超限后原样报错。
func TestJetStreamPublishAbsorbsLeaderGap(t *testing.T) {
	url := isolatedNATS(t)
	bus, err := NewJetStream(url, "integration", 1, 1, 1<<30, 0, &testProcessor{done: make(chan struct{})}, testMetrics{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := bus.js.DeleteStream(streamName); err != nil {
		t.Fatal(err)
	}
	restored := make(chan error, 1)
	go func() {
		time.Sleep(1500 * time.Millisecond) // 长于 nats.go 自带的两次 250ms 重试
		_, err := bus.js.AddStream(&nats.StreamConfig{Name: streamName, Subjects: []string{subjectAll}, Storage: nats.FileStorage})
		restored <- err
	}()
	e := ingest.Envelope{Version: ingest.EnvelopeVersion, ID: ingest.StableID(t.Name()), PartitionKey: "asset-a", Timestamp: time.Now(), ClassUID: 1007, Source: "agent", Raw: json.RawMessage(`{}`)}
	if err := bus.Publish(context.Background(), e); err != nil {
		t.Fatalf("选主空档应被重试吸收: %v", err)
	}
	if err := <-restored; err != nil {
		t.Fatal(err)
	}
	if info, err := bus.js.StreamInfo(streamName); err != nil || info.State.Msgs != 1 {
		t.Fatalf("流恢复后应恰好写入一条: info=%+v err=%v", info, err)
	}

	if err := bus.js.DeleteStream(streamName); err != nil {
		t.Fatal(err)
	}
	bus.retry = natsretry.Policy{First: 50 * time.Millisecond, Max: 100 * time.Millisecond, Budget: 300 * time.Millisecond}
	start := time.Now()
	err = bus.Publish(context.Background(), e)
	if !errors.Is(err, nats.ErrNoStreamResponse) {
		t.Fatalf("超限后应原样报 no responders: %v", err)
	}
	if spent := time.Since(start); spent > 3*time.Second {
		t.Fatalf("重试没有上限: %v", spent)
	}
}

func TestJetStreamPublishConsumeAndDeduplicate(t *testing.T) {
	url := isolatedNATS(t)
	p := &testProcessor{done: make(chan struct{})}
	bus, err := NewJetStream(url, "integration", 4, 1, 1<<30, 0, p, testMetrics{}, 1)
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

func (m testMetrics) SetQueueSampleTimestamp(string, float64) {}

func TestJetStreamMonitorSample(t *testing.T) {
	nc, err := nats.Connect(isolatedNATS(t))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{Name: streamName, Subjects: []string{subjectAll}, Storage: nats.FileStorage}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddConsumer(streamName, &nats.ConsumerConfig{Durable: "ingest-00", FilterSubject: "openxdr.events.00", AckPolicy: nats.AckExplicitPolicy}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := js.Publish("openxdr.events.00", []byte("test")); err != nil {
			t.Fatal(err)
		}
	}
	m := &monitorMetrics{}
	b := &JetStream{js: js, shards: 1, replicas: 1, metrics: m, monitorEnd: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b.sampleQueue(ctx)
	if m.pending != 3 || m.unhealthy != 0 || m.sampled == 0 {
		t.Fatalf("真实 JetStream 采样错误: %+v", m)
	}
}
