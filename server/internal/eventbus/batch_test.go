package eventbus

import (
	"encoding/json"
	"testing"
	"time"

	"openxdr/server/internal/ingest"
)

func batchEvent(key string, index int) ingest.Envelope {
	return ingest.Envelope{Version: ingest.EnvelopeVersion, ID: ingest.StableID(key, time.Unix(int64(index), 0).String()), PartitionKey: key, Timestamp: time.Now().UTC(), ClassUID: 1007, Source: "agent", Raw: json.RawMessage(`{}`)}
}

func TestDecodeMessage(t *testing.T) {
	first, second := batchEvent("a", 0), batchEvent("a", 1)
	for _, value := range []any{first, []ingest.Envelope{first, second}} {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		events, err := decodeMessage(body)
		if err != nil || events[0].ID != first.ID {
			t.Fatalf("兼容解码失败: %v %v", events, err)
		}
	}
	invalid := second
	invalid.Version++
	foreign := second
	foreign.PartitionKey = "b"
	excessive := make([]ingest.Envelope, MaxBatchSize+1)
	for i := range excessive {
		excessive[i] = first
	}
	for _, value := range []any{[]ingest.Envelope{}, []ingest.Envelope{first, invalid}, []ingest.Envelope{first, foreign}, excessive} {
		body, _ := json.Marshal(value)
		if _, err := decodeMessage(body); err == nil {
			t.Fatal("接受了无效批消息")
		}
	}
}
