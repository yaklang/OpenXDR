// Package eventbus 提供单机直连和 JetStream 集群两种事件传输。
package eventbus

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"

	"openxdr/server/internal/ingest"
)

const (
	streamName = "OPENXDR_EVENTS"
	subjectAll = "openxdr.events.*"
)

type Metrics interface {
	Published(source string)
	PublishFailed()
	Failed(stage string)
	SetQueuePending(shard string, count uint64)
}

type Processor interface {
	Process(context.Context, ingest.Envelope) error
}

type Bus interface {
	Publish(context.Context, ingest.Envelope) error
	Ready() bool
	Close() error
}

type Direct struct {
	processor Processor
	metrics   Metrics
}

func NewDirect(processor Processor, metrics Metrics) *Direct {
	return &Direct{processor: processor, metrics: metrics}
}

func (d *Direct) Publish(ctx context.Context, e ingest.Envelope) error {
	if err := d.processor.Process(ctx, e); err != nil {
		d.metrics.PublishFailed()
		return err
	}
	d.metrics.Published(e.Source)
	return nil
}
func (d *Direct) Ready() bool  { return true }
func (d *Direct) Close() error { return nil }

type JetStream struct {
	nc         *nats.Conn
	js         nats.JetStreamContext
	shards     int
	metrics    Metrics
	subs       []*nats.Subscription
	monitorEnd chan struct{}
}

func NewJetStream(url, instance string, shards, replicas int, maxBytes int64, maxAge time.Duration, processor Processor, metrics Metrics) (*JetStream, error) {
	if shards < 1 || shards > 256 {
		return nil, fmt.Errorf("QUEUE_SHARDS 必须在 1..256")
	}
	if replicas < 1 || replicas > 5 {
		return nil, fmt.Errorf("QUEUE_REPLICAS 必须在 1..5")
	}
	nc, err := nats.Connect(url,
		nats.Name("openxdr-"+instance),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) { slog.Warn("NATS 连接中断", "err", err) }),
		nats.ReconnectHandler(func(_ *nats.Conn) { slog.Info("NATS 已重连") }),
	)
	if err != nil {
		return nil, err
	}
	js, err := nc.JetStream(nats.PublishAsyncMaxPending(4096))
	if err != nil {
		nc.Close()
		return nil, err
	}
	config := &nats.StreamConfig{
		Name:        streamName,
		Description: fmt.Sprintf("OpenXDR events; shards=%d", shards),
		Subjects:    []string{subjectAll},
		Retention:   nats.WorkQueuePolicy,
		Storage:     nats.FileStorage,
		Replicas:    replicas,
		MaxBytes:    maxBytes,
		MaxAge:      maxAge,
		Discard:     nats.DiscardOld,
	}
	if info, infoErr := js.StreamInfo(streamName); infoErr != nil {
		if _, err = js.AddStream(config); err != nil {
			nc.Close()
			return nil, err
		}
	} else if info.Config.Description != "" && info.Config.Description != config.Description {
		nc.Close()
		return nil, fmt.Errorf("QUEUE_SHARDS 与现有 stream 不一致: %q", info.Config.Description)
	} else if _, err = js.UpdateStream(config); err != nil {
		nc.Close()
		return nil, err
	}
	b := &JetStream{nc: nc, js: js, shards: shards, metrics: metrics, monitorEnd: make(chan struct{})}
	for i := 0; i < shards; i++ {
		shard := fmt.Sprintf("%02x", i)
		subject := "openxdr.events." + shard
		durable := "ingest-" + shard
		sub, err := js.QueueSubscribe(subject, durable, func(msg *nats.Msg) {
			e, decodeErr := ingest.Unmarshal(msg.Data)
			if decodeErr != nil {
				metrics.Failed("decode")
				_ = msg.Term()
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := processor.Process(ctx, e)
			cancel()
			if err != nil {
				slog.Error("队列事件处理失败", "event", e.ID, "err", err)
				_ = msg.NakWithDelay(time.Second)
				return
			}
			_ = msg.Ack()
		}, nats.BindStream(streamName), nats.Durable(durable), nats.ManualAck(),
			nats.AckExplicit(), nats.MaxAckPending(1), nats.DeliverAll())
		if err != nil {
			b.Close()
			return nil, fmt.Errorf("创建分片消费者 %s: %w", shard, err)
		}
		b.subs = append(b.subs, sub)
	}
	go b.monitor()
	return b, nil
}

func (b *JetStream) Publish(ctx context.Context, e ingest.Envelope) error {
	body, err := e.Marshal()
	if err != nil {
		return err
	}
	shard := shardOf(e.PartitionKey, b.shards)
	msg := nats.NewMsg("openxdr.events." + fmt.Sprintf("%02x", shard))
	msg.Data = body
	msg.Header.Set(nats.MsgIdHdr, e.ID.String())
	if _, err = b.js.PublishMsg(msg, nats.Context(ctx)); err != nil {
		b.metrics.PublishFailed()
		return err
	}
	b.metrics.Published(e.Source)
	return nil
}

func (b *JetStream) Ready() bool {
	if !b.nc.IsConnected() || len(b.subs) != b.shards {
		return false
	}
	for _, sub := range b.subs {
		if !sub.IsValid() {
			return false
		}
	}
	return true
}

func (b *JetStream) Close() error {
	select {
	case <-b.monitorEnd:
	default:
		close(b.monitorEnd)
	}
	for _, sub := range b.subs {
		_ = sub.Drain()
	}
	b.nc.Drain()
	return nil
}

func (b *JetStream) monitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.monitorEnd:
			return
		case <-ticker.C:
			for i := 0; i < b.shards; i++ {
				shard := fmt.Sprintf("%02x", i)
				if info, err := b.js.ConsumerInfo(streamName, "ingest-"+shard); err == nil {
					b.metrics.SetQueuePending(shard, info.NumPending+uint64(info.NumAckPending))
				}
			}
		}
	}
}

func shardOf(key string, shards int) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % uint32(shards))
}

func InstanceName(hostname string, pid int) string { return hostname + "-" + strconv.Itoa(pid) }
