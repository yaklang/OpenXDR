//go:build integration

// R1/R2 的 janitor 侧集成测试（COLD_ARCHIVE_EVOLUTION.SCRATCH.md §P3「R1/R2 最小修复」）：
// 到期清理（sweep 的逐行 DELETE 会触发 events_release 触发器删派生表；retire 走
// eventpart.Retire）都持同日排他生命周期锁，与引用写入者（共享锁）串行：
//
//   - sweep：引用写入事务持该日共享锁未提交时，sweep 在锁上等到超时明确失败、一行不删；
//     引用提交后（事件被 pin）sweep 只删无引用的到期行，被引用的行保留。
//   - retire（janitor.retireExpired 的锁包装）：同日共享锁被持有时明确失败、不动分区；
//     释放后正常退役。
//
// 专用测试库，与其它集成测试一样串行（-p 1）。
package janitor

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/testdb"
)

// r12Open 建带 *sql.DB 的测试环境（sweep/retire 的锁路径需要 SQL 句柄）。
func r12Open(t *testing.T) (context.Context, *ent.Client, *sql.DB) {
	t.Helper()
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return ctx, client, db
}

// r12HotExists 报告事件是否仍在热表。
func r12HotExists(t *testing.T, ctx context.Context, db *sql.DB, id string) bool {
	t.Helper()
	var ok bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE id = $1)`, id).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

// TestR12SweepWaitsForReferenceWriter：到期清理与引用写入并发。
// 共享锁持有期间 sweep 明确失败（lock_timeout）、不删任何行；引用提交后事件被 pin，
// sweep 只删真正无引用的行——「引用写入的日期在 sweep 完成前不被清理破坏」。
func TestR12SweepWaitsForReferenceWriter(t *testing.T) {
	ctx, client, db := r12Open(t)
	now := time.Now().UTC()
	// 落在默认分区（两天前没有日分区），正是 sweep 逐行清理的实际作用域
	plain := client.Event.Create().SetTs(now.Add(-48 * time.Hour)).
		SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{"mark":"plain"}`)).SaveX(ctx)
	target := client.Event.Create().SetTs(now.Add(-47 * time.Hour)).
		SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{"mark":"target"}`)).SaveX(ctx)
	j := &Janitor{DB: client, SQL: db, Retention: 24 * time.Hour, Interval: time.Hour}

	// 引用写入事务（生产协议：共享生命周期锁 → 锁内重读 → 写 alert）持锁未提交
	conn, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	wtx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wtx.Rollback() }()
	if err := eventpart.LifecycleLockShared(ctx, wtx, target.Ts); err != nil {
		t.Fatalf("引用写入者取共享锁: %v", err)
	}
	if _, err := wtx.ExecContext(ctx, `INSERT INTO alerts (id, ts, rule_id, severity, event_id)
 VALUES (gen_random_uuid(), $1, 'r12-sweep', 5, $2)`, target.Ts, target.ID); err != nil {
		t.Fatal(err)
	}

	// sweep 拿不到该日排他锁：等满 lock_timeout 后明确失败，一行都不删
	if _, err := j.sweep(ctx); err == nil {
		t.Fatal("该日共享生命周期锁被引用事务持有时，sweep 应明确失败（lock_timeout），不得删行")
	}
	if !r12HotExists(t, ctx, db, plain.ID.String()) {
		t.Fatal("被挡下的 sweep 不得删除任何行")
	}

	// 引用提交后（target 被 pin）再清：只删无引用的 plain，target 保留
	if err := wtx.Commit(); err != nil {
		t.Fatal(err)
	}
	deleted, err := j.sweep(ctx)
	if err != nil {
		t.Fatalf("引用提交后 sweep: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("应只删 1 条无引用到期行，实际 %d", deleted)
	}
	if r12HotExists(t, ctx, db, plain.ID.String()) {
		t.Fatal("无引用的到期行应被清理")
	}
	if !r12HotExists(t, ctx, db, target.ID.String()) {
		t.Fatal("被 alert 引用的到期行必须保留（sweep 不得制造悬空引用）")
	}
}

// TestR12RetireTakesLifecycleLock：janitor 的退役包装在动分区前取到期日的排他生命
// 周期锁。共享锁被引用事务持有时明确失败、分区原样；释放后正常退役（pin 行并进月归档
// 分区）。restore 的互斥由同一把锁承担（eventarchive 包的 r12 用例覆盖）。
func TestR12RetireTakesLifecycleLock(t *testing.T) {
	ctx, client, db := r12Open(t)
	// 40 天前：退役窗口内（cutoff = now - max(retention, retireGuard)）
	day := time.Now().UTC().AddDate(0, 0, -40)
	day = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
	if _, err := eventpart.EnsureDays(ctx, db, eventpart.Parent, day, 0); err != nil {
		t.Fatalf("建日分区: %v", err)
	}
	month := time.Date(day.Year(), day.Month(), 1, 0, 0, 0, 0, time.UTC)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+eventpart.ArchiveName(month))
	})
	pin := client.Event.Create().SetTs(day.Add(time.Minute)).
		SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{"mark":"pin"}`)).SaveX(ctx)
	client.Alert.Create().SetTs(pin.Ts).SetRuleID("r12-retire").SetSeverity(3).SetEventID(pin.ID).SaveX(ctx)
	j := &Janitor{DB: client, SQL: db, Retention: 24 * time.Hour, Interval: time.Hour}
	cutoff := retireCutoff(time.Now(), j.Retention)

	// 引用写入者持该日共享锁未提交：退役必须明确失败，分区原样
	conn, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	wtx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := eventpart.LifecycleLockShared(ctx, wtx, day); err != nil {
		t.Fatal(err)
	}
	retired, dropped, err := j.retireExpired(ctx, cutoff)
	if err == nil {
		t.Fatal("该日共享生命周期锁被持有时，退役应明确失败（lock_timeout），不能交错完成")
	}
	if retired != 0 || dropped != 0 {
		t.Fatalf("失败的退役不得退役任何分区（retired=%d dropped=%d）", retired, dropped)
	}
	if !r12HotExists(t, ctx, db, pin.ID.String()) {
		t.Fatal("被挡下的退役不得动数据")
	}

	// 释放引用事务后正常退役：pin 行并进月归档分区
	if err := wtx.Rollback(); err != nil {
		t.Fatal(err)
	}
	retired, dropped, err = j.retireExpired(ctx, cutoff)
	if err != nil {
		t.Fatalf("锁释放后退役: %v", err)
	}
	if retired < 1 {
		t.Fatalf("应退役该日分区，实际 %d 个", retired)
	}
	var routed string
	if err := db.QueryRowContext(ctx, `SELECT tableoid::regclass::text FROM events WHERE id = $1`, pin.ID).
		Scan(&routed); err != nil {
		t.Fatal(err)
	}
	if routed != eventpart.ArchiveName(month) {
		t.Fatalf("pin 行应随退役并进 %s，实际 %s", eventpart.ArchiveName(month), routed)
	}
}
