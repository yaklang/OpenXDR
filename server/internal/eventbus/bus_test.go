package eventbus

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestNotStoredOnlyProvenRejections(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nats.ErrNoStreamResponse, true},
		{fmt.Errorf("包装: %w", nats.ErrNoResponders), true},
		{&nats.APIError{Code: 503, Description: "raft: not leader"}, true},
		{&nats.APIError{Code: 500, ErrorCode: 10009, Description: "JetStream cluster can not handle request"}, true},
		{nats.ErrTimeout, false},
		{context.DeadlineExceeded, false},
		{&nats.APIError{Code: 503, Description: "raft: write error"}, false},
		{&nats.APIError{Code: 503, ErrorCode: 10077, Description: "maximum messages exceeded"}, false},
		{nats.ErrInvalidJSAck, false},
	} {
		if got := notStored(tc.err); got != tc.want {
			t.Errorf("notStored(%v) = %t，期望 %t", tc.err, got, tc.want)
		}
	}
}

func TestShardStableAndBounded(t *testing.T) {
	for _, key := range []string{"asset-a", "asset-b", "10.0.0.1"} {
		a := shardOf(key, 32)
		b := shardOf(key, 32)
		if a != b || a < 0 || a >= 32 {
			t.Fatalf("分片异常 key=%q a=%d b=%d", key, a, b)
		}
	}
}

func TestQueueRejectsLossyLimits(t *testing.T) {
	for _, tc := range []struct {
		bytes int64
		age   time.Duration
		want  string
	}{{0, 0, "QUEUE_MAX_BYTES_GB"}, {-1, 0, "QUEUE_MAX_BYTES_GB"}, {1024, time.Hour, "QUEUE_MAX_AGE_HOURS"}, {1024, -time.Second, "QUEUE_MAX_AGE_HOURS"}} {
		_, err := NewJetStream("nats://127.0.0.1:1", "test", 1, 1, tc.bytes, tc.age, nil, nil, 1)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("未拒绝丢失配置: %v", err)
		}
	}
}
