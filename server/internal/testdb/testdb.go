//go:build integration

// Package testdb 提供集成测试共用的 Postgres 连接与表清理。
// 仅在使用 -tags integration 构建时编译。
//
// 每个测试开始时清空库里全部表，同一个库上的测试不能并发；多包并行用 server/integration-test.sh，
// 它经 cmd/integrationexec 给每个包分配独立的库：
//
//	INTEGRATION_DATABASE_URL=postgres://... sh integration-test.sh
package testdb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
	"openxdr/server/internal/aijob"
	"openxdr/server/internal/authevents"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/graphqueue"
	"openxdr/server/internal/temporal"
)

// New 连接测试库、重建 schema 并清空表。未配置 INTEGRATION_DATABASE_URL 时跳过。
func New(t *testing.T) (context.Context, *ent.Client) {
	t.Helper()
	dsn := os.Getenv("INTEGRATION_DATABASE_URL")
	if dsn == "" {
		t.Skip("INTEGRATION_DATABASE_URL 未设置，跳过集成测试")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	t.Cleanup(func() { client.Close() })

	ctx := context.Background()
	if err := migrate(ctx, client, db, dsn); err != nil {
		t.Fatal(err)
	}
	clean(ctx, t, db)
	return ctx, client
}

var (
	migratedMu sync.Mutex
	// migrated 每个库上次建完 schema 后的指纹
	migrated = map[string]string{}
)

// migrate 建表与 ent diff 每次要上百毫秒：schema 指纹和上次建完时一致就跳过，只清表。
// 有些测试会改 schema（events 在分区表与普通表之间迁移、删冗余索引、换外键与触发器），
// 指纹一变就整套重建，下一个测试照样拿到完整 schema
func migrate(ctx context.Context, client *ent.Client, db *sql.DB, dsn string) error {
	migratedMu.Lock()
	defer migratedMu.Unlock()
	// 空库的指纹也是空串，必须看「迁移过」而不是拿零值比
	if fp, err := fingerprint(ctx, db); err != nil {
		return err
	} else if prev, ok := migrated[dsn]; ok && fp == prev {
		return nil
	}
	if err := eventpart.Migrate(ctx, client, db); err != nil {
		return fmt.Errorf("schema 迁移失败: %w", err)
	}
	if err := aijob.EnsureSchema(ctx, db); err != nil {
		return fmt.Errorf("AI 任务索引失败: %w", err)
	}
	if err := temporal.EnsureSchema(ctx, db); err != nil {
		return fmt.Errorf("时序处理状态初始化失败: %w", err)
	}
	if err := graphqueue.EnsureSchema(ctx, db); err != nil {
		return err
	}
	if err := authevents.EnsureSchema(ctx, db); err != nil {
		return err
	}
	fp, err := fingerprint(ctx, db)
	if err != nil {
		return err
	}
	migrated[dsn] = fp
	return nil
}

// fingerprint public 下表、索引、约束、函数与触发器的摘要；分区子表及其索引、约束、克隆触发器不计，
// 测试按需预建日分区不触发重建
func fingerprint(ctx context.Context, db *sql.DB) (string, error) {
	var fp sql.NullString
	err := db.QueryRowContext(ctx, `SELECT md5(string_agg(x, ',' ORDER BY x)) FROM (
  SELECT 'r:' || c.relname || ':' || c.relkind::text AS x FROM pg_class c
   WHERE c.relnamespace = 'public'::regnamespace AND NOT c.relispartition AND c.relkind IN ('r','p','i','I','v','m','S')
  UNION ALL
  SELECT 'c:' || r.relname || ':' || k.conname || ':' || k.contype::text FROM pg_constraint k JOIN pg_class r ON r.oid = k.conrelid
   WHERE k.connamespace = 'public'::regnamespace AND NOT r.relispartition
  UNION ALL
  SELECT 'f:' || p.proname || ':' || md5(p.prosrc) FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace
  UNION ALL
  SELECT 't:' || r.relname || ':' || g.tgname FROM pg_trigger g JOIN pg_class r ON r.oid = g.tgrelid
   WHERE NOT g.tgisinternal AND g.tgparentid = 0 AND r.relnamespace = 'public'::regnamespace
 ) s`).Scan(&fp)
	return fp.String, err
}

// clean 每个测试从全空的库开始：public 下的全部表（分区子表随父表）一次清空，不维护名单——
// 不归 ent 管的表（身份图、时序证据、归档记录、队列游标……）以前要靠别的包的测试先清，换个顺序或上次中途失败就带着残留。
// 月归档分区（events_aYYYYMM）跨整月，残留会挡住测试要建的历史日分区，一并拆掉。
// 清表时在本事务里暂停外键与触发器（session_replication_role=replica，测试库用户须是超级用户），顺序无关，一次往返
func clean(ctx context.Context, t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `DO $$ DECLARE r record; BEGIN
 PERFORM set_config('session_replication_role', 'replica', true);
 FOR r IN SELECT c.relname FROM pg_class c JOIN pg_inherits i ON c.oid = i.inhrelid
  WHERE i.inhparent = 'events'::regclass AND c.relname LIKE 'events_a%' LOOP
  EXECUTE format('DROP TABLE IF EXISTS %I', r.relname);
 END LOOP;
 FOR r IN SELECT c.relname FROM pg_class c
  WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p') AND NOT c.relispartition LOOP
  EXECUTE format('DELETE FROM %I', r.relname);
 END LOOP;
END $$`); err != nil {
		t.Fatalf("清空测试库失败（测试库用户须是超级用户）: %v", err)
	}
}
