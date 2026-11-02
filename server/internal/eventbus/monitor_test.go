package eventbus

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type monitorJS struct {
	nats.JetStreamContext
	stream   func(...nats.JSOpt) (*nats.StreamInfo, error)
	consumer func(string, ...nats.JSOpt) (*nats.ConsumerInfo, error)
}

func (j monitorJS) StreamInfo(_ string, opts ...nats.JSOpt) (*nats.StreamInfo, error) {
	return j.stream(opts...)
}
func (j monitorJS) ConsumerInfo(_, name string, opts ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	return j.consumer(name, opts...)
}

type monitorMetrics struct {
	fakeMetrics
	unhealthy int
	pending   uint64
	sampled   float64
}

func (m *monitorMetrics) SetQueueReplicasUnhealthy(n int)    { m.unhealthy = n }
func (m *monitorMetrics) SetQueuePending(_ string, n uint64) { m.pending = n }

func (m *monitorMetrics) SetQueueSampleTimestamp(_ string, ts float64) { m.sampled = ts }

func TestQueueSampleCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	m := &monitorMetrics{pending: 42, sampled: 123}
	calls := 0
	b := &JetStream{shards: 32, replicas: 3, metrics: m, monitorEnd: make(chan struct{})}
	b.js = monitorJS{
		stream: func(opts ...nats.JSOpt) (*nats.StreamInfo, error) {
			if len(opts) != 1 || opts[0].(nats.ContextOpt).Context != ctx {
				t.Fatal("流检查必须使用本轮截止时间")
			}
			return nil, errors.New("无 leader")
		},
		consumer: func(_ string, opts ...nats.JSOpt) (*nats.ConsumerInfo, error) {
			calls++
			if m.unhealthy != 3 {
				t.Fatal("分片阻塞前必须更新副本健康度")
			}
			if len(opts) != 1 || opts[0].(nats.ContextOpt).Context != ctx {
				t.Fatal("分片查询必须共用本轮截止时间")
			}
			cancel()
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	b.sampleQueue(ctx)
	if m.pending != 42 || m.sampled != 123 {
		t.Fatal("失败采样不得覆盖上次成功数据")
	}
	if b.monitorNext != 1 {
		t.Fatal("下一轮应从未采样分片继续")
	}
	if calls != 1 {
		t.Fatalf("截止后仍继续查询分片: %d", calls)
	}
}

func TestQueueSamplePending(t *testing.T) {
	m := &monitorMetrics{}
	b := &JetStream{shards: 1, replicas: 1, metrics: m, monitorEnd: make(chan struct{})}
	b.js = monitorJS{
		stream: func(...nats.JSOpt) (*nats.StreamInfo, error) { return &nats.StreamInfo{}, nil },
		consumer: func(string, ...nats.JSOpt) (*nats.ConsumerInfo, error) {
			return &nats.ConsumerInfo{NumPending: 7, NumAckPending: 2}, nil
		},
	}
	b.sampleQueue(context.Background())
	if m.pending != 9 || m.unhealthy != 0 || m.sampled == 0 {
		t.Fatalf("采样错误: %+v", m)
	}
}

func TestQueueSampleResumesAfterTimeout(t *testing.T) {
	m := &monitorMetrics{}
	b := &JetStream{shards: 32, replicas: 1, metrics: m, monitorEnd: make(chan struct{})}
	var got []string
	var cancel context.CancelFunc
	b.js = monitorJS{
		stream: func(...nats.JSOpt) (*nats.StreamInfo, error) { return &nats.StreamInfo{}, nil },
	}
	// 每轮只容许一个分片完成，后面的分片仍须在后续轮次得到采样。
	b.js = monitorJS{stream: b.js.(monitorJS).stream, consumer: func(name string, _ ...nats.JSOpt) (*nats.ConsumerInfo, error) {
		got = append(got, name)
		cancel()
		return &nats.ConsumerInfo{}, nil
	}}
	for range 33 {
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		b.sampleQueue(ctx)
		cancel()
	}
	if len(got) != 33 || got[0] != "ingest-00" || got[31] != "ingest-1f" || got[32] != "ingest-00" {
		t.Fatalf("分片未公平轮询: %v", got)
	}
}
