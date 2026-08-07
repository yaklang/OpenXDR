//go:build integration

// Package testdb 提供集成测试共用的 Postgres 连接与表清理。
// 仅在使用 -tags integration 构建时编译。
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
	truncate(ctx, t, db)
	return ctx, client
}

// truncate 按外键依赖顺序清空全部表，保证每个测试从干净状态开始。
func truncate(ctx context.Context, t *testing.T, db *sql.DB) {
	t.Helper()
	for _, name := range []string{"alert", "event", "incident", "asset"} {
		if _, err := db.ExecContext(ctx, "DELETE FROM "+name); err != nil {
			t.Fatalf("清空 %s 表失败: %v", name, err)
		}
	}
}
