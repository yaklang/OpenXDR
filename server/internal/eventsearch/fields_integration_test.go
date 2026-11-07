//go:build integration

package eventsearch

import (
	"encoding/json"
	"openxdr/server/internal/testdb"
	"testing"
	"time"
)

func TestStructuredFieldsPostgres(t *testing.T) {
	ctx, db := testdb.New(t)
	raw := json.RawMessage(`{"src_endpoint":{"ip":"192.0.2.1","port":12345},"dst_endpoint":{"ip":"198.51.100.2","port":443},"process":{"name":"curl","cmd_line":"curl 'https://example.test'"},"file":{"path":"/tmp/test's file"}}`)
	db.Event.Create().SetTs(time.Now()).SetClassUID(4001).SetSource("sensor").SetRaw(raw).SaveX(ctx)
	for _, fields := range []Fields{
		{"srcIp": "192.0.2.1"}, {"dstIp": "198.51.100.2"}, {"srcPort": "12345"}, {"dstPort": "443"},
		{"processName": "curl"}, {"commandLine": "curl 'https://example.test'"}, {"filePath": "/tmp/test's file"},
		{"srcIp": "192.0.2.1", "dstPort": "443"},
	} {
		count, err := db.Event.Query().Where(fields.Predicate()).Count(ctx)
		if err != nil || count != 1 {
			t.Fatalf("字段应匹配 %v: count=%d err=%v", fields, count, err)
		}
		if !fields.Match(raw) {
			t.Fatalf("冷热匹配口径不同: %v", fields)
		}
	}
	for _, fields := range []Fields{{"srcIp": "192.0.2"}, {"processName": "curl' OR TRUE --"}, {"dstPort": "444"}, {"srcIp": "192.0.2.1", "filePath": "missing"}} {
		count, err := db.Event.Query().Where(fields.Predicate()).Count(ctx)
		if err != nil || count != 0 {
			t.Fatalf("字段不应匹配 %v: count=%d err=%v", fields, count, err)
		}
	}
}
