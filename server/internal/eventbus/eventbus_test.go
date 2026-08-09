package eventbus

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"openxdr/server/internal/ingest"
)

type fakeProcessor struct {
	err error
	got []ingest.Envelope
}

func (p *fakeProcessor) Process(_ context.Context, e ingest.Envelope) error {
	p.got = append(p.got, e)
	return p.err
}

type fakeMetrics struct {
	published int
	failed    int
}

func (m *fakeMetrics) Published(string)               { m.published++ }
func (m *fakeMetrics) PublishFailed()                 { m.failed++ }
func (m *fakeMetrics) Failed(string)                  {}
func (m *fakeMetrics) SetQueuePending(string, uint64) {}

func env(source string) ingest.Envelope {
	return ingest.Envelope{
		ID:           uuid.New(),
		PartitionKey: "key",
		ClassUID:     1001,
		Source:       source,
	}
}

func TestDirectPublish(t *testing.T) {
	e := env("agent")
	proc := &fakeProcessor{}
	m := &fakeMetrics{}
	d := NewDirect(proc, m)

	if !d.Ready() {
		t.Error("Direct 应始终 Ready")
	}
	if err := d.Close(); err != nil {
		t.Errorf("Close() 应返回 nil，got %v", err)
	}

	if err := d.Publish(context.Background(), e); err != nil {
		t.Fatalf("正常发布不应失败: %v", err)
	}
	if len(proc.got) != 1 {
		t.Fatalf("处理器应收到 1 个事件，got %d", len(proc.got))
	}
	if m.published != 1 || m.failed != 0 {
		t.Errorf("成功时 metrics published=%d failed=%d, want 1/0", m.published, m.failed)
	}
}

func TestDirectPublishError(t *testing.T) {
	proc := &fakeProcessor{err: errors.New("boom")}
	m := &fakeMetrics{}
	d := NewDirect(proc, m)

	if err := d.Publish(context.Background(), env("sensor")); err == nil {
		t.Fatal("处理器失败时 Publish 应返回错误")
	}
	if m.failed != 1 || m.published != 0 {
		t.Errorf("失败时 metrics published=%d failed=%d, want 0/1", m.published, m.failed)
	}
}

func TestNewJetStreamParamValidation(t *testing.T) {
	// 这些校验发生在连 NATS 之前，可安全断言而不触发网络。
	bad := []struct {
		name     string
		shards   int
		replicas int
	}{
		{"shards 为 0", 0, 1},
		{"shards 超上限", 257, 1},
		{"replicas 为 0", 2, 0},
		{"replicas 超上限", 2, 6},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewJetStream("nats://127.0.0.1:1", "test", tc.shards, tc.replicas, 0, 0, nil, nil)
			if err == nil {
				t.Fatal("非法参数应返回错误")
			}
		})
	}
}

func TestInstanceName(t *testing.T) {
	if got := InstanceName("host-a", 1234); got != "host-a-1234" {
		t.Errorf("InstanceName() = %q, want \"host-a-1234\"", got)
	}
}
