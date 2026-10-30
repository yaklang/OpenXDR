//go:build integration

package assetmap

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/graphqueue"
	"openxdr/server/internal/ingest"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func queueFixture(t *testing.T) (context.Context, *ent.Client, *sql.DB, *ingest.Processor, *Engine, ingest.Envelope) {
	t.Helper()
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := ingest.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	a := client.Asset.Create().SetHostname("durable-graph").SetIPAddrs([]string{"10.0.0.1"}).SaveX(ctx)
	p := &ingest.Processor{DB: db, Rules: sigma.LoadDir(t.TempDir()), Suppress: suppress.New(client, 0), Intel: intel.New(client, 0)}
	e := &Engine{DB: client, SQL: db}
	ev := ingest.Envelope{Version: ingest.EnvelopeVersion, ID: uuid.New(), PartitionKey: a.ID.String(), Timestamp: time.Now().UTC().Truncate(time.Microsecond), ClassUID: classNetwork, Source: "agent", AssetID: &a.ID, Raw: json.RawMessage(`{"src_endpoint":{"ip":"10.0.0.1","port":40000},"dst_endpoint":{"ip":"8.8.8.8","port":443},"process":{"name":"curl"}}`)}
	return ctx, client, db, p, e, ev
}

func pendingCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM assetmap_queue`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestQueuedGraphLateArrivalAndReplay(t *testing.T) {
	ctx, client, db, p, e, event := queueFixture(t)
	if err := p.Process(ctx, event); err != nil {
		t.Fatal(err)
	}
	if n, err := e.batch(ctx); err != nil || n != 1 {
		t.Fatalf("首批: %d %v", n, err)
	}
	late := event
	late.ID = uuid.New()
	late.Timestamp = event.Timestamp.Add(-time.Minute)
	if err := p.Process(ctx, late); err != nil {
		t.Fatal(err)
	}
	// 换工作者，事件时间早于持久游标也必须消费。
	cur, curID := e.loadCursor(ctx)
	next := &Engine{DB: client, SQL: db, cursor: cur, cursorID: curID}
	if n, err := next.batch(ctx); err != nil || n != 1 {
		t.Fatalf("迟到网络事件被跳过: %d %v", n, err)
	}
	if err := p.Process(ctx, late); err != nil {
		t.Fatal(err)
	}
	if n, err := next.batch(ctx); err != nil || n != 0 {
		t.Fatalf("重投被重复物化: %d %v", n, err)
	}
	link := client.AssetLink.Query().OnlyX(ctx)
	if link.Count != 2 || !link.FirstSeen.Equal(late.Timestamp) || !link.LastSeen.Equal(event.Timestamp) {
		t.Fatalf("计数或时间范围错误: %+v", link)
	}
	if n := pendingCount(t, db); n != 0 {
		t.Fatalf("已提交待办未清理: %d", n)
	}
}

func TestQueuedGraphRollbackAndRowClaims(t *testing.T) {
	ctx, client, db, p, e, event := queueFixture(t)
	late := event
	late.ID = uuid.New()
	late.Timestamp = event.Timestamp.Add(-time.Minute)
	if err := p.ProcessBatch(ctx, []ingest.Envelope{event, late}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE asset_links ADD CONSTRAINT test_graph_failure CHECK(dst_port<>443) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`ALTER TABLE asset_links DROP CONSTRAINT IF EXISTS test_graph_failure`)
	if _, err := e.batch(ctx); err == nil {
		t.Fatal("必须传播物化失败")
	}
	if n := pendingCount(t, db); n != 2 {
		t.Fatalf("回滚丢了待办: %d", n)
	}
	if n := client.AssetLink.Query().CountX(ctx); n != 0 {
		t.Fatalf("失败留下部分图谱: %d", n)
	}
	if _, err := db.Exec(`ALTER TABLE asset_links DROP CONSTRAINT test_graph_failure`); err != nil {
		t.Fatal(err)
	}
	first, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback()
	if rows, err := queuedEvents(ctx, first); err != nil || len(rows) != 2 {
		t.Fatalf("领取失败: %d %v", len(rows), err)
	}
	second, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback()
	if rows, err := queuedEvents(ctx, second); err != nil || len(rows) != 0 {
		t.Fatalf("重复领取未提交事件: %d %v", len(rows), err)
	}
	if err := first.Rollback(); err != nil {
		t.Fatal(err)
	}
	if rows, err := queuedEvents(ctx, second); err != nil || len(rows) != 2 {
		t.Fatalf("旧工作者回滚后未能接管: %d %v", len(rows), err)
	}
	if err := second.Rollback(); err != nil {
		t.Fatal(err)
	}
	if n, err := e.batch(ctx); err != nil || n != 2 {
		t.Fatalf("重试: %d %v", n, err)
	}
	link := client.AssetLink.Query().OnlyX(ctx)
	if link.Count != 2 || !link.FirstSeen.Equal(late.Timestamp) || !link.LastSeen.Equal(event.Timestamp) {
		t.Fatalf("批内乱序时间范围错误: %+v", link)
	}
}

func TestQueuedGraphLegacyHandoff(t *testing.T) {
	ctx, client, db, p, e, event := queueFixture(t)
	if _, err := db.Exec(`UPDATE settings SET value='"legacy"'::jsonb WHERE id=$1`, graphqueue.ModeKey); err != nil {
		t.Fatal(err)
	}
	e.cursor = event.Timestamp.Add(-time.Hour)
	if err := p.Process(ctx, event); err != nil {
		t.Fatal(err)
	}
	// 模拟切换请求与旧工作者正在处理的批次重叠：旧批提交时必须清除同事件待办。
	if _, err := db.Exec(`INSERT INTO assetmap_queue(event_id,event_ts) VALUES($1,$2)`, event.ID, event.Timestamp); err != nil {
		t.Fatal(err)
	}
	if n, err := e.batch(ctx); err != nil || n != 1 {
		t.Fatalf("旧模式消费: %d %v", n, err)
	}
	if n := pendingCount(t, db); n != 0 {
		t.Fatalf("旧批提交未清除待办: %d", n)
	}
	if _, err := db.Exec(`UPDATE settings SET value='"requested"'::jsonb WHERE id=$1`, graphqueue.ModeKey); err != nil {
		t.Fatal(err)
	}
	late := event
	late.ID = uuid.New()
	late.Timestamp = event.Timestamp.Add(-time.Minute)
	fresh := event
	fresh.ID = uuid.New()
	fresh.Timestamp = event.Timestamp.Add(time.Second)
	if err := p.ProcessBatch(ctx, []ingest.Envelope{late, fresh}); err != nil {
		t.Fatal(err)
	}
	if n, err := e.batch(ctx); err != nil || n != 2 {
		t.Fatalf("切换漏掉事件: %d %v", n, err)
	}
	if mode, err := graphqueue.Mode(ctx, db); err != nil || mode != graphqueue.Queued {
		t.Fatalf("模式未持久化: %s %v", mode, err)
	}
	if link := client.AssetLink.Query().OnlyX(ctx); link.Count != 3 {
		t.Fatalf("切换重复计数: %+v", link)
	}
	if err := graphqueue.Activate(ctx, db, event.Timestamp.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := pendingCount(t, db); n != 0 {
		t.Fatalf("重复切换重新投递已物化事件: %d", n)
	}
}

func TestQueuedGraphCaptureRollsBackAndExpires(t *testing.T) {
	ctx, client, db, p, _, event := queueFixture(t)
	bad := event
	bad.ID = uuid.New()
	bad.ClassUID = ClassInventory
	if _, err := db.Exec(`ALTER TABLE events ADD CONSTRAINT test_graph_ingest_failure CHECK(class_uid<>5001) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`ALTER TABLE events DROP CONSTRAINT IF EXISTS test_graph_ingest_failure`)
	if err := p.ProcessBatch(ctx, []ingest.Envelope{event, bad}); err == nil {
		t.Fatal("必须传播入库失败")
	}
	if n := pendingCount(t, db); n != 0 {
		t.Fatalf("入库回滚留下待办: %d", n)
	}
	if n := client.Event.Query().CountX(ctx); n != 0 {
		t.Fatalf("批次未回滚: %d", n)
	}
	if err := p.Process(ctx, event); err != nil {
		t.Fatal(err)
	}
	if n := pendingCount(t, db); n != 1 {
		t.Fatalf("入库未登记待办: %d", n)
	}
	if err := client.Event.DeleteOneID(event.ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if n := pendingCount(t, db); n != 0 {
		t.Fatalf("事件删除遗留待办: %d", n)
	}
}

func TestQueuedGraphActivationWaitsForWriter(t *testing.T) {
	ctx, _, db, _, _, event := queueFixture(t)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	writer, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if _, err := writer.ExecContext(ctx, `INSERT INTO events(id,ts,class_uid,source,asset_id,raw) VALUES($1,$2,$3,$4,$5,$6::jsonb)`, event.ID, event.Timestamp, event.ClassUID, event.Source, event.AssetID, string(event.Raw)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- graphqueue.Activate(ctx, db, event.Timestamp.Add(-time.Hour)) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var waiting bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND relation='events'::regclass AND mode='ShareRowExclusiveLock' AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("未等待尚未提交的事件事务")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := graphqueue.Capture(ctx, writer, event.ID, event.Timestamp, event.ClassUID); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := pendingCount(t, db); n != 1 {
		t.Fatalf("切换丢失或重复登记在途事件: %d", n)
	}
}

func TestQueuedGraphKeepsNewestSnapshotsWithinBatch(t *testing.T) {
	ctx, client, _, p, e, event := queueFixture(t)
	latest := event
	latest.ClassUID = ClassInventory
	latest.Raw = json.RawMessage(`{"device":{"listening":[{"proto":"tcp","addr":"0.0.0.0","port":443}]}}`)
	older := latest
	older.ID = uuid.New()
	older.Timestamp = latest.Timestamp.Add(-time.Minute)
	older.Raw = json.RawMessage(`{"device":{"listening":[{"proto":"tcp","addr":"0.0.0.0","port":22}]}}`)
	sw := event
	sw.ID = uuid.New()
	sw.ClassUID = ClassSoftware
	sw.Raw = json.RawMessage(`{"os":{"id":"debian","version_id":"13"},"manager":"dpkg","packages":[["example","2","amd64","source"]]}`)
	oldsw := sw
	oldsw.ID = uuid.New()
	oldsw.Timestamp = sw.Timestamp.Add(-time.Minute)
	oldsw.Raw = json.RawMessage(`{"os":{"id":"debian","version_id":"13"},"manager":"dpkg","packages":[["example","1","amd64","source"]]}`)
	if err := p.ProcessBatch(ctx, []ingest.Envelope{latest, older, sw, oldsw}); err != nil {
		t.Fatal(err)
	}
	if n, err := e.batch(ctx); err != nil || n != 4 {
		t.Fatalf("快照物化: %d %v", n, err)
	}
	a := client.Asset.GetX(ctx, *event.AssetID)
	listeners := listenersOf(a)
	if len(listeners) != 1 || listeners[0].Port != 443 || a.InventoryAt == nil || !a.InventoryAt.Equal(latest.Timestamp) {
		t.Fatalf("旧清单覆盖了新清单: %+v", a)
	}
	var software Software
	if err := json.Unmarshal(a.Software, &software); err != nil {
		t.Fatal(err)
	}
	if len(software.Packages) != 1 || software.Packages[0][1] != "2" || a.SoftwareAt == nil || !a.SoftwareAt.Equal(sw.Timestamp) {
		t.Fatalf("旧软件清单覆盖了新清单: %+v", software)
	}
}

func TestQueuedGraphRejectsUnknownDeliveryMode(t *testing.T) {
	ctx, client, db, p, e, event := queueFixture(t)
	if _, err := db.Exec(`UPDATE settings SET value='"broken"'::jsonb WHERE id=$1`, graphqueue.ModeKey); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(ctx, event); err == nil {
		t.Fatal("未知投递模式不能静默漏登记")
	}
	if _, err := e.batch(ctx); err == nil {
		t.Fatal("未知模式不能回退时间游标")
	}
	if n := client.Event.Query().CountX(ctx); n != 0 {
		t.Fatalf("坏配置仍提交事件: %d", n)
	}
}

func TestQueuedGraphLegacyTableCleanup(t *testing.T) {
	_, _, db, _, _, _ := queueFixture(t)
	ctx := context.Background()
	// 独立 schema 模拟尚未迁移分区的老库，不改共享测试表。
	db.SetMaxOpenConns(1)
	schema := "graph_cleanup_" + uuid.New().String()[:8]
	if _, err := db.Exec(`CREATE SCHEMA ` + schema + `; SET search_path TO ` + schema); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`SET search_path TO public; DROP SCHEMA ` + schema + ` CASCADE`)
	if _, err := db.Exec(`CREATE TABLE settings(id text PRIMARY KEY,value jsonb,updated_at timestamptz);
CREATE TABLE events(id uuid PRIMARY KEY,ts timestamptz,class_uid integer)`); err != nil {
		t.Fatal(err)
	}
	if err := graphqueue.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	// 重复启动不能重复创建清理触发器。
	if err := graphqueue.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO events VALUES($1,now(),4001)`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO assetmap_queue(event_id,event_ts) SELECT id,ts FROM events`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM events WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if n := pendingCount(t, db); n != 0 {
		t.Fatalf("普通 events 表删除后残留待办: %d", n)
	}
}

func TestQueuedGraphRPMSoftwareInventory(t *testing.T) {
	ctx, client, _, p, e, ev := queueFixture(t)
	ev.ClassUID = ClassSoftware
	ev.Raw = json.RawMessage(`{"os":{"id":"uos","version_id":"20"},"manager":"rpm","packages":[["openssl","1:1.1.1k-9.uel20","openssl","1.1.1k-9.uel20"],["local","0:1-1","",""]]}`)
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if n, err := e.batch(ctx); err != nil || n != 1 {
		t.Fatalf("RPM 物化失败: %d %v", n, err)
	}
	a := client.Asset.GetX(ctx, *ev.AssetID)
	var sw Software
	if err := json.Unmarshal(a.Software, &sw); err != nil {
		t.Fatal(err)
	}
	if sw.Manager != "rpm" || sw.OS != "uos" || len(sw.Packages) != 2 || sw.Packages[0][1] != "1:1.1.1k-9.uel20" || a.SoftwareAt == nil {
		t.Fatalf("RPM 数据丢失: %+v", sw)
	}
}
