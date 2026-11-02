//go:build integration

package assetmap

import (
	"testing"
	"time"
)

func TestGraphMaintenanceDoesNotBlockIngestion(t *testing.T) {
	ctx, client, db, p, e, ev := queueFixture(t)
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var locked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, graphMaintenanceLock).Scan(&locked); err != nil || !locked {
		t.Fatalf("维护锁: %v %v", locked, err)
	}
	defer conn.ExecContext(ctx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, graphMaintenanceLock)
	if err := p.Process(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if pendingCount(t, db) != 1 {
		t.Fatal("维护期间必须继续登记事件")
	}
	if n, err := e.batch(ctx); err != nil || n != 0 {
		t.Fatalf("维护期间不应消费: %d %v", n, err)
	}
	if client.AssetLink.Query().CountX(ctx) != 0 || pendingCount(t, db) != 1 {
		t.Fatal("维护期间改变了图谱或待办")
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, graphMaintenanceLock); err != nil {
		t.Fatal(err)
	}
	if n, err := e.batch(ctx); err != nil || n != 1 {
		t.Fatalf("释放维护锁后未恢复消费: %d %v", n, err)
	}
	if pendingCount(t, db) != 0 || client.AssetLink.Query().OnlyX(ctx).Count != 1 {
		t.Fatal("恢复后计数不正确")
	}
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, graphMaintenanceLock).Scan(&locked); err != nil || !locked {
		t.Fatalf("重新获取维护锁: %v", err)
	}
	if n, err := e.deleteLinks(ctx, `DELETE FROM asset_links WHERE last_seen < $1`, time.Now().Add(time.Hour)); err != nil || n != 0 {
		t.Fatalf("维护期间不能清理图谱: %d %v", n, err)
	}
	if client.AssetLink.Query().CountX(ctx) != 1 {
		t.Fatal("维护期间图谱被清理")
	}
}
