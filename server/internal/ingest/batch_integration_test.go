//go:build integration

package ingest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProcessBatchAtomicReplay(t *testing.T) {
	p, client, db := testProcessor(t)
	defer client.Close()
	defer db.Close()
	ctx := context.Background()
	p.Temporal = temporalStoreFixture(t)
	asset := client.Asset.Create().SetHostname("batch").SetGroupID(uuid.New()).SaveX(ctx)
	first := Envelope{Version: EnvelopeVersion, ID: uuid.New(), PartitionKey: asset.ID.String(), Timestamp: time.Now().UTC().Truncate(time.Microsecond), ClassUID: 1007, Source: "agent", AssetID: &asset.ID, Raw: json.RawMessage(`{"marker":"yes"}`)}
	second := first
	second.ID = uuid.New()
	second.Timestamp = first.Timestamp.Add(time.Second)
	events := []Envelope{first, second, first}
	if _, err := db.Exec(`ALTER TABLE alerts ADD CONSTRAINT test_reject_batch CHECK (rule_id <> 'burst') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`ALTER TABLE alerts DROP CONSTRAINT IF EXISTS test_reject_batch`)
	if err := p.ProcessBatch(ctx, events); err == nil {
		t.Fatal("第二条派生告警失败必须使整批失败")
	}
	for _, table := range []string{"events", "alerts", "temporal_candidates", "temporal_detections", "temporal_evidence"} {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s 整批回滚失败: %d %v", table, n, err)
		}
	}
	if _, err := db.Exec(`ALTER TABLE alerts DROP CONSTRAINT test_reject_batch`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := p.ProcessBatch(ctx, events); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM events`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("重投重复落库: %d %v", n, err)
	}
	var anchor uuid.UUID
	var count int
	if err := db.QueryRow(`SELECT event_id,count FROM alerts WHERE rule_id='burst'`).Scan(&anchor, &count); err != nil {
		t.Fatal(err)
	}
	if anchor != second.ID || count != 1 {
		t.Fatalf("跨事件检测或重投计数错误: %s %d", anchor, count)
	}
}
