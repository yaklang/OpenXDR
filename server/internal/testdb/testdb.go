//go:build integration

// Package testdb 提供集成测试共用的 Postgres 连接与表清理。
// 仅在使用 -tags integration 构建时编译。
//
// 所有集成测试共享同一测试库并在跑前清空表，因此多包集成测试必须串行：
//
//	go test -tags integration -p 1 ./...
package testdb

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/ent"
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
	if err := client.Schema.Create(ctx); err != nil {
		t.Fatalf("schema 迁移失败: %v", err)
	}
	truncate(ctx, t, client)
	return ctx, client
}

// truncate 按外键依赖顺序清空全部表，保证每个测试从干净状态开始。
func truncate(ctx context.Context, t *testing.T, c *ent.Client) {
	t.Helper()
	dels := []func(context.Context) (int, error){
		func(ctx context.Context) (int, error) { return c.Alert.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Event.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Incident.Delete().Exec(ctx) },
		// Command 引用 Asset，必须先删
		func(ctx context.Context) (int, error) { return c.Command.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Asset.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Session.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.User.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.AuditLog.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Intel.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Suppression.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.ProcessBaseline.Delete().Exec(ctx) },
	}
	for i, del := range dels {
		if _, err := del(ctx); err != nil {
			t.Fatalf("清空表 #%d 失败: %v", i, err)
		}
	}
}
