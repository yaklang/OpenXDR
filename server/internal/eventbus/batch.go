package eventbus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"openxdr/server/internal/ingest"
)

const MaxBatchSize = 64
const maxBatchBytes = 256 << 10

type batchProcessor interface {
	ProcessBatch(context.Context, []ingest.Envelope) error
}

type batchPublisher interface {
	BatchSize() int
	PublishBatch(context.Context, []ingest.Envelope) error
}

// BatchSize 仅对显式启用批消息的队列攒批，单机与旧消息发布保持原行为。
func BatchSize(bus Bus) int {
	if b, ok := bus.(batchPublisher); ok {
		return b.BatchSize()
	}
	return 1
}

func PublishBatch(ctx context.Context, bus Bus, events []ingest.Envelope) error {
	if b, ok := bus.(batchPublisher); ok {
		return b.PublishBatch(ctx, events)
	}
	for _, e := range events {
		if err := bus.Publish(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

func (b *JetStream) BatchSize() int { return b.batchSize }

// PublishBatch 只合并相邻的同资产事件，数量和编码后字节均有上限。
// 旧节点退出前必须保持 batchSize=1；消费端始终同时接受单事件与批消息。
func (b *JetStream) PublishBatch(ctx context.Context, events []ingest.Envelope) error {
	encoded := make([]json.RawMessage, len(events))
	for i, e := range events {
		if err := e.Validate(); err != nil {
			return err
		}
		raw, err := e.Marshal()
		if err != nil {
			return err
		}
		encoded[i] = raw
	}
	limit := min(maxBatchBytes, int(b.nc.MaxPayload())-512)
	for start := 0; start < len(events); {
		end, size := start+1, len(encoded[start])+2
		for end < len(events) && end-start < b.batchSize && events[end].PartitionKey == events[start].PartitionKey && size+len(encoded[end])+1 <= limit {
			size += len(encoded[end]) + 1
			end++
		}
		if end-start == 1 {
			if err := b.Publish(ctx, events[start]); err != nil {
				return err
			}
		} else {
			body, err := json.Marshal(encoded[start:end])
			if err != nil {
				return err
			}
			id := ingest.StableID("queue-batch-v1", string(body))
			if err := b.publishMessage(ctx, body, events[start].PartitionKey, id.String()); err != nil {
				return err
			}
			for _, e := range events[start:end] {
				b.metrics.Published(e.Source)
			}
		}
		start = end
	}
	return nil
}

func decodeMessage(body []byte) ([]ingest.Envelope, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '[' {
		e, err := ingest.Unmarshal(body)
		if err != nil {
			return nil, err
		}
		return []ingest.Envelope{e}, nil
	}
	var events []ingest.Envelope
	if err := json.Unmarshal(body, &events); err != nil {
		return nil, err
	}
	if len(events) == 0 || len(events) > MaxBatchSize {
		return nil, fmt.Errorf("批消息事件数必须在 1..64")
	}
	for _, e := range events {
		if err := e.Validate(); err != nil {
			return nil, err
		}
		if e.PartitionKey != events[0].PartitionKey {
			return nil, fmt.Errorf("批消息不能跨资产分区")
		}
	}
	return events, nil
}

func processMessage(ctx context.Context, processor Processor, events []ingest.Envelope) error {
	if len(events) == 1 {
		return processor.Process(ctx, events[0])
	}
	p, ok := processor.(batchProcessor)
	if !ok {
		return fmt.Errorf("事件处理器不支持批事务")
	}
	return p.ProcessBatch(ctx, events)
}
