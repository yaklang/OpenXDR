//go:build integration

package eventbus

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"openxdr/server/internal/ingest"
)

type batchRecorder struct{ batches chan []ingest.Envelope }

func (p *batchRecorder) Process(ctx context.Context, e ingest.Envelope) error {
	return p.ProcessBatch(ctx, []ingest.Envelope{e})
}
func (p *batchRecorder) ProcessBatch(_ context.Context, events []ingest.Envelope) error {
	p.batches <- events
	return nil
}

func TestBatchPublishConsumeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		size  int
		large bool
		want  []int
	}{
		{"批消息", 64, false, []int{64, 1}},
		{"兼容发布", 1, false, []int{1, 1}},
		{"字节上限", 64, true, []int{1, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &batchRecorder{make(chan []ingest.Envelope, 100)}
			bus, err := NewJetStream(isolatedNATS(t), "batch", 1, 1, 16<<20, 0, p, testMetrics{}, tc.size)
			if err != nil {
				t.Fatal(err)
			}
			defer bus.Close()
			n := 2
			if tc.name == "批消息" {
				n = 65
			}
			events := make([]ingest.Envelope, n)
			for i := range events {
				events[i] = batchEvent("host", i)
				if tc.large {
					events[i].Raw = json.RawMessage(`{"payload":"` + strings.Repeat("x", 140<<10) + `"}`)
				}
			}
			if err := bus.PublishBatch(context.Background(), events); err != nil {
				t.Fatal(err)
			}
			offset := 0
			for _, want := range tc.want {
				select {
				case got := <-p.batches:
					if len(got) != want {
						t.Fatalf("批大小 %d 期望 %d", len(got), want)
					}
					for _, e := range got {
						if e.ID != events[offset].ID {
							t.Fatal("批次事件顺序错误")
						}
						offset++
					}
				case <-time.After(5 * time.Second):
					t.Fatal("消费超时")
				}
			}
			if err := bus.PublishBatch(context.Background(), events); err != nil {
				t.Fatal(err)
			}
			select {
			case <-p.batches:
				t.Fatal("同批重投未在队列去重")
			case <-time.After(100 * time.Millisecond):
			}
			info, err := bus.js.ConsumerInfo(streamName, "ingest-00")
			if err != nil || info.Config.MaxAckPending != 1 {
				t.Fatalf("破坏分片串行消费: %v %v", info, err)
			}
		})
	}
}

type retryBatchRecorder struct {
	batchRecorder
	failed atomic.Bool
}

func (p *retryBatchRecorder) ProcessBatch(ctx context.Context, events []ingest.Envelope) error {
	if err := p.batchRecorder.ProcessBatch(ctx, events); err != nil {
		return err
	}
	if !p.failed.Swap(true) {
		return errors.New("模拟批事务回滚")
	}
	return nil
}

func TestBatchRetryAcrossConsumersPreservesOrder(t *testing.T) {
	url := isolatedNATS(t)
	p := &retryBatchRecorder{batchRecorder: batchRecorder{make(chan []ingest.Envelope, 10)}}
	for _, node := range []string{"one", "two"} {
		b, err := NewJetStream(url, node, 1, 1, 16<<20, 0, p, testMetrics{}, 64)
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		if node == "one" {
			continue
		}
		for batch := 0; batch < 2; batch++ {
			events := []ingest.Envelope{batchEvent("host", batch*2), batchEvent("host", batch*2+1)}
			if err := b.PublishBatch(context.Background(), events); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, index := range []int{0, 0, 2} {
		select {
		case got := <-p.batches:
			if len(got) != 2 || got[0].ID != batchEvent("host", index).ID {
				t.Fatalf("失败批次被后续批次越过: %+v", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("批消息重投超时")
		}
	}
}
