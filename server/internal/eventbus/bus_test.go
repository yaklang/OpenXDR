package eventbus

import "testing"

func TestShardStableAndBounded(t *testing.T) {
	for _, key := range []string{"asset-a", "asset-b", "10.0.0.1"} {
		a := shardOf(key, 32)
		b := shardOf(key, 32)
		if a != b || a < 0 || a >= 32 {
			t.Fatalf("分片异常 key=%q a=%d b=%d", key, a, b)
		}
	}
}
