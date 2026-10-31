// Package eventbus 提供单机直连和 JetStream 集群两种事件传输。
package eventbus

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"

	"openxdr/server/internal/ingest"
	"openxdr/server/internal/natsretry"
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
	SetQueueReplicasUnhealthy(count int)
	SetQueueSampleTimestamp(shard string, timestamp float64)
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
	nc          *nats.Conn
	js          nats.JetStreamContext
	shards      int
	replicas    int
	metrics     Metrics
	subs        []*nats.Subscription
	monitorEnd  chan struct{}
	retry       natsretry.Policy
	batchSize   int
	monitorNext int
}

func NewJetStream(url, instance string, shards, replicas int, maxBytes int64, maxAge time.Duration, processor Processor, metrics Metrics, batchSize int) (*JetStream, error) {
	if batchSize < 1 || batchSize > MaxBatchSize {
		return nil, fmt.Errorf("QUEUE_BATCH_SIZE 必须在 1..64")
	}
	if shards < 1 || shards > 256 {
		return nil, fmt.Errorf("QUEUE_SHARDS 必须在 1..256")
	}
	if replicas < 1 || replicas > 5 {
		return nil, fmt.Errorf("QUEUE_REPLICAS 必须在 1..5")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("QUEUE_MAX_BYTES_GB 必须大于 0")
	}
	if maxAge != 0 {
		return nil, fmt.Errorf("QUEUE_MAX_AGE_HOURS 必须为 0：已确认但未处理的事件不能按时间过期")
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
		Discard:     nats.DiscardNew,
	}
	if info, infoErr := js.StreamInfo(streamName); infoErr != nil {
		if _, err = js.AddStream(config); err != nil {
			nc.Close()
			return nil, err
		}
	} else if info.Config.Description != "" && info.Config.Description != config.Description {
		nc.Close()
		return nil, fmt.Errorf("QUEUE_SHARDS 与现有 stream 不一致: %q", info.Config.Description)
	} else if (info.Config.MaxBytes <= 0 || maxBytes < info.Config.MaxBytes) || info.State.Bytes > uint64(maxBytes) {
		nc.Close()
		return nil, fmt.Errorf("拒绝在线缩小队列容量；请在停写维护窗口核对积压后调整")
	} else if _, err = js.UpdateStream(config); err != nil {
		nc.Close()
		return nil, err
	}
	b := &JetStream{nc: nc, js: js, shards: shards, replicas: replicas, metrics: metrics, monitorEnd: make(chan struct{}), retry: natsretry.Default, batchSize: batchSize}
	for i := 0; i < shards; i++ {
		shard := fmt.Sprintf("%02x", i)
		metrics.SetQueueSampleTimestamp(shard, 0)
		subject := "openxdr.events." + shard
		durable := "ingest-" + shard
		sub, err := js.QueueSubscribe(subject, durable, func(msg *nats.Msg) {
			events, decodeErr := decodeMessage(msg.Data)
			if decodeErr != nil {
				metrics.Failed("decode")
				_ = msg.Term()
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := processMessage(ctx, processor, events)
			cancel()
			if err != nil {
				slog.Error("队列事件处理失败", "event", events[0].ID, "batch_size", len(events), "err", err)
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
	if err := b.publishMessage(ctx, body, e.PartitionKey, e.ID.String()); err != nil {
		return err
	}
	b.metrics.Published(e.Source)
	return nil
}

func (b *JetStream) publishMessage(ctx context.Context, body []byte, partitionKey, id string) error {
	shard := shardOf(partitionKey, b.shards)
	msg := nats.NewMsg("openxdr.events." + fmt.Sprintf("%02x", shard))
	msg.Data = body
	msg.Header.Set(nats.MsgIdHdr, id)
	// 仅重试能证明未入队的错误；超时仍交给来源端重投，由事件 ID 保证幂等。
	err := b.retry.Do(ctx, func() error {
		_, err := b.js.PublishMsg(msg, nats.Context(ctx))
		return err
	}, notStored)
	if err != nil {
		b.metrics.PublishFailed()
	}
	return err
}

// jsClusterNotLeader nats-server 的 JSClusterNotLeaderErr（err_code 10009），nats.go 没有导出常量
const jsClusterNotLeader nats.ErrorCode = 10009

// notStored 能证明流没有收下这条消息的发布错误，重发安全：
//   - ErrNoStreamResponse / ErrNoResponders：流 leader 只在当选后订阅主题，选主空档里没人订阅，
//     NATS 直接回 no responders，消息根本没进任何副本（nats.go 自己已先重试两次）
//   - 503「raft: not leader」：旧 leader 收到消息时已卸任，raft 提案被拒、没有写入日志
//   - 10009 集群非 leader：在提案前就拒绝
//
// 超时等「可能已写入」的错误不在此列，按原样报错。即便误判，Nats-Msg-Id 去重窗口与
// 事件稳定 ID 的主键幂等也保证重发不会产生重复事件。
func notStored(err error) bool {
	if errors.Is(err, nats.ErrNoStreamResponse) || errors.Is(err, nats.ErrNoResponders) {
		return true
	}
	var api *nats.APIError
	if !errors.As(err, &api) {
		return false
	}
	return api.ErrorCode == jsClusterNotLeader || (api.Code == 503 && api.ErrorCode == 0 && api.Description == "raft: not leader")
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
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			b.sampleQueue(ctx)
			cancel()
		}
	}
}

// 全轮共用截止时间，避免分片逐个超时拖住副本健康度更新。
func (b *JetStream) sampleQueue(ctx context.Context) {
	info, err := b.js.StreamInfo(streamName, nats.Context(ctx))
	b.metrics.SetQueueReplicasUnhealthy(unhealthyReplicas(info, err, b.replicas))
	for i := 0; i < b.shards && ctx.Err() == nil; i++ {
		select {
		case <-b.monitorEnd:
			return
		default:
		}
		shard := fmt.Sprintf("%02x", b.monitorNext)
		b.monitorNext = (b.monitorNext + 1) % b.shards
		if info, err := b.js.ConsumerInfo(streamName, "ingest-"+shard, nats.Context(ctx)); err == nil {
			b.metrics.SetQueuePending(shard, info.NumPending+uint64(info.NumAckPending))
			b.metrics.SetQueueSampleTimestamp(shard, float64(time.Now().Unix()))
		}
	}
}

// unhealthyReplicas 不在同步状态的副本数。StreamInfo 由流 leader 应答，答得上来就算 leader 健康；
// 答不上来（没有 leader、失去多数）按全部副本不健康计——副本静默掉队正是需要告警的情形。
func unhealthyReplicas(info *nats.StreamInfo, err error, replicas int) int {
	if err != nil || info == nil {
		return replicas
	}
	healthy := 1
	if info.Cluster != nil {
		for _, peer := range info.Cluster.Replicas {
			if peer.Current && !peer.Offline {
				healthy++
			}
		}
	}
	return max(replicas-healthy, 0)
}

func shardOf(key string, shards int) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % uint32(shards))
}

func InstanceName(hostname string, pid int) string { return hostname + "-" + strconv.Itoa(pid) }
