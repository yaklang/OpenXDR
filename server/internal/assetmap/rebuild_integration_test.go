//go:build integration

package assetmap

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGraphRebuildRebasesWithoutDuplicates(t *testing.T) {
	ctx, client, db, p, e, ev := queueFixture(t)
	if _, err := db.Exec(`DROP TABLE IF EXISTS assetmap_rebuilds`); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	original := client.AssetLink.Query().OnlyX(ctx)
	if _, err := db.Exec(`UPDATE settings SET value='"legacy"' WHERE id='assetmap.delivery'`); err != nil {
		t.Fatal(err)
	}
	late := ev
	late.ID = uuid.New()
	late.Timestamp = ev.Timestamp.Add(-time.Minute)
	if err := p.Process(ctx, late); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE settings SET value='"queue"' WHERE id='assetmap.delivery'`); err != nil {
		t.Fatal(err)
	}
	pending := late
	pending.ID = uuid.New()
	pending.Raw = json.RawMessage(`{"src_endpoint":{"ip":"10.0.0.1"},"dst_endpoint":{"ip":"9.9.9.9","port":443},"process":{"name":"missing"}}`)
	if err := p.Process(ctx, pending); err != nil {
		t.Fatal(err)
	}
	since := ev.Timestamp.Add(-time.Hour)
	if _, err := RebuildGraph(ctx, db, since, 1); err == nil {
		t.Fatal("超限必须回滚")
	}
	if client.AssetLink.Query().OnlyX(ctx).Count != 1 || pendingCount(t, db) != 1 {
		t.Fatal("失败重建修改了图谱或队列")
	}
	report, err := RebuildGraph(ctx, db, since, 100)
	if err != nil {
		t.Fatal(err)
	}
	if report.Events != 3 || report.Links != 2 || report.Acknowledged != 1 {
		t.Fatalf("重建口径错误: %+v", report)
	}
	if pendingCount(t, db) != 0 {
		t.Fatal("快照内已重建待办没有清理")
	}
	restored := client.AssetLink.GetX(ctx, original.ID)
	if restored.Count != 2 || !restored.FirstSeen.Equal(late.Timestamp) {
		t.Fatalf("未保留 ID 或未补齐历史: %+v", restored)
	}
	var backupCount int
	if err := db.QueryRow(`SELECT (previous_links->0->>'count')::int FROM assetmap_rebuilds WHERE id=$1`, report.ID).Scan(&backupCount); err != nil || backupCount != 1 {
		t.Fatalf("原图备份: %d %v", backupCount, err)
	}
	again, err := RebuildGraph(ctx, db, since, 100)
	if err != nil || again.Acknowledged != 0 {
		t.Fatalf("重复重建: %+v %v", again, err)
	}
	if client.AssetLink.GetX(ctx, original.ID).Count != 2 {
		t.Fatal("重复重建累加了计数")
	}
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if client.AssetLink.GetX(ctx, original.ID).Count != 2 {
		t.Fatal("正常消费重复统计重建事件")
	}
	// 在应用阶段失败，必须同时回滚备份、图谱修改与待办确认。
	if _, err := db.Exec(`CREATE FUNCTION reject_graph_rebuild() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test rollback'; END $$;
 CREATE TRIGGER reject_graph_rebuild BEFORE UPDATE ON asset_links FOR EACH ROW EXECUTE FUNCTION reject_graph_rebuild()`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`DROP TRIGGER IF EXISTS reject_graph_rebuild ON asset_links; DROP FUNCTION IF EXISTS reject_graph_rebuild()`)
	extra := late
	extra.ID = uuid.New()
	if err := p.Process(ctx, extra); err != nil {
		t.Fatal(err)
	}
	failed, err := RebuildGraph(ctx, db, since, 100)
	if err == nil {
		t.Fatal("应用失败必须返回错误")
	}
	var backups int
	if err := db.QueryRow(`SELECT count(*) FROM assetmap_rebuilds WHERE id=$1`, failed.ID).Scan(&backups); err != nil {
		t.Fatal(err)
	}
	if backups != 0 || pendingCount(t, db) != 1 || client.AssetLink.GetX(ctx, original.ID).Count != 2 {
		t.Fatal("应用失败没有原子回滚")
	}
}

func TestGraphRebuildLeavesPostSnapshotArrivalQueued(t *testing.T) {
	ctx, client, db, p, e, ev := queueFixture(t)
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	since := ev.Timestamp.Add(-time.Hour)
	if _, err := RebuildGraph(ctx, db, since, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE FUNCTION pause_graph_rebuild() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN PERFORM pg_advisory_xact_lock(98743187::bigint); RETURN NEW; END $$;
 CREATE TRIGGER pause_graph_rebuild BEFORE INSERT ON assetmap_rebuilds FOR EACH ROW EXECUTE FUNCTION pause_graph_rebuild()`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`DROP TRIGGER IF EXISTS pause_graph_rebuild ON assetmap_rebuilds; DROP FUNCTION IF EXISTS pause_graph_rebuild()`)
	blocker, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	if _, err := blocker.ExecContext(ctx, `SELECT pg_advisory_lock(98743187::bigint)`); err != nil {
		t.Fatal(err)
	}
	defer blocker.ExecContext(ctx, `SELECT pg_advisory_unlock(98743187::bigint)`)
	type result struct {
		report GraphRebuild
		err    error
	}
	done := make(chan result, 1)
	go func() { r, err := RebuildGraph(ctx, db, since, 100); done <- result{r, err} }()
	deadline := time.Now().Add(4 * time.Second)
	for {
		var waiting bool
		if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=98743187 AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("重建未到达应用前暂停点")
		}
		time.Sleep(10 * time.Millisecond)
	}
	late := ev
	late.ID = uuid.New()
	late.Timestamp = ev.Timestamp.Add(-time.Minute)
	if err := p.Process(ctx, late); err != nil {
		t.Fatal(err)
	}
	if n, err := e.batch(ctx); err != nil || n != 0 {
		t.Fatalf("重建期间不能消费: %d %v", n, err)
	}
	if _, err := blocker.ExecContext(ctx, `SELECT pg_advisory_unlock(98743187::bigint)`); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.report.Events != 1 || got.report.Acknowledged != 0 {
			t.Fatalf("重建跨越了快照: %+v %v", got.report, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("重建没有完成")
	}
	if pendingCount(t, db) != 1 || client.AssetLink.Query().OnlyX(ctx).Count != 1 {
		t.Fatal("提前确认了快照后的迟到事件")
	}
	if n, err := e.batch(ctx); err != nil || n != 1 {
		t.Fatalf("迟到事件没有恢复消费: %d %v", n, err)
	}
	if pendingCount(t, db) != 0 || client.AssetLink.Query().OnlyX(ctx).Count != 2 {
		t.Fatal("快照后的事件丢失或重计")
	}
}
