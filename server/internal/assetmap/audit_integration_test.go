//go:build integration

package assetmap

import (
	"encoding/json"
	"github.com/google/uuid"
	"openxdr/server/internal/ingest"
	"testing"
	"time"
)

func TestGraphAuditFindsGapsWithoutCountingPending(t *testing.T) {
	ctx, client, db, p, e, ev := queueFixture(t)
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE settings SET value='"legacy"' WHERE id='assetmap.delivery'`); err != nil {
		t.Fatal(err)
	}
	late := ev
	late.ID = uuid.New()
	late.Timestamp = ev.Timestamp.Add(-time.Minute)
	missing := late
	missing.ID = uuid.New()
	missing.Raw = json.RawMessage(`{"src_endpoint":{"ip":"10.0.0.1"},"dst_endpoint":{"ip":"9.9.9.9","port":443},"process":{"name":"missing"}}`)
	ignored := late
	ignored.ID = uuid.New()
	ignored.Raw = json.RawMessage(`{"src_endpoint":{"ip":"10.0.0.1"},"dst_endpoint":{"ip":"127.0.0.1","port":443}}`)
	if err := p.ProcessBatch(ctx, []ingest.Envelope{late, missing, ignored}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE settings SET value='"queue"' WHERE id='assetmap.delivery'`); err != nil {
		t.Fatal(err)
	}
	pending := missing
	pending.ID = uuid.New()
	if err := p.Process(ctx, pending); err != nil {
		t.Fatal(err)
	}
	since, until := ev.Timestamp.Add(-2*time.Hour), ev.Timestamp.Add(time.Hour)
	report, err := AuditGraph(ctx, db, since, until, 100, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Events != 5 || report.Pending != 1 || report.Contributing != 3 || report.ObservedLinks != 2 || report.MissingLinks != 1 || report.BelowObservedCount != 1 {
		t.Fatalf("核对口径错误: %+v", report)
	}
	if _, err := AuditGraph(ctx, db, since, until, 100, true); err == nil {
		t.Fatal("备库限定不能放行主库")
	}
	if client.AssetLink.Query().OnlyX(ctx).Count != 1 || pendingCount(t, db) != 1 {
		t.Fatal("只读核对修改了图谱或待办")
	}
	if _, err := AuditGraph(ctx, db, since, until, 2, false); err == nil {
		t.Fatal("超过事件上限不能报告完成")
	}
	if client.AssetLink.Query().OnlyX(ctx).Count != 1 || pendingCount(t, db) != 1 {
		t.Fatal("超限核对修改了数据")
	}
}
