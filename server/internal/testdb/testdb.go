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
	"openxdr/server/internal/aijob"
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
	if err := eventpart.Migrate(ctx, client, db); err != nil {
		t.Fatalf("schema 迁移失败: %v", err)
	}
	if err := aijob.EnsureSchema(ctx, db); err != nil {
		t.Fatalf("AI 任务索引失败: %v", err)
	}
	if err := temporal.EnsureSchema(ctx, db); err != nil {
		t.Fatalf("时序处理状态初始化失败: %v", err)
	}
	if err := graphqueue.EnsureSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	truncateRaw(ctx, t, db)
	truncate(ctx, t, client)
	return ctx, client
}

// truncateRaw 清空不归 ent 管的身份图表（由 identity.EnsureSchema 建，表可能还不存在）。
// 游标表也要清，否则上一个测试的增量游标会让新数据被跳过。
func truncateRaw(ctx context.Context, t *testing.T, db *sql.DB) {
	t.Helper()
	for _, table := range []string{"assetmap_queue", "identity_login_matches", "identity_candidate_rejections", "identity_links", "identities", "identity_accounts", "identity_graph_cursors"} {
		if _, err := db.ExecContext(ctx, `DO $$ BEGIN IF to_regclass('`+table+`') IS NOT NULL THEN DELETE FROM `+table+`; END IF; END $$`); err != nil {
			t.Fatalf("清空表 %s 失败: %v", table, err)
		}
	}
}

// truncate 按外键依赖顺序清空全部表，保证每个测试从干净状态开始。
func truncate(ctx context.Context, t *testing.T, c *ent.Client) {
	t.Helper()
	dels := []func(context.Context) (int, error){
		func(ctx context.Context) (int, error) { return c.TriageRun.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.IntegrationIdempotency.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.ExternalTicket.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.IntegrationAttempt.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.IntegrationDelivery.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.IntegrationSubscription.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.IntegrationEvent.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.IntegrationToken.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.IntegrationGroup.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Integration.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.DecoyObservation.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.DecoyRevision.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.DecoyEngineRelease.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.DecoyDeployment.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.AIJob.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.HostCredential.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Finding.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Memory.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.TaskRun.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Task.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Approval.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.CommandPolicy.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Report.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.ReportRead.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.SessionMessage.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.AgentSession.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.TrustedSource.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.SSHLogin.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.GroupMember.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Group.Delete().Exec(ctx) },
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
		func(ctx context.Context) (int, error) { return c.VulnRecord.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.BeaconBaseline.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Setting.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.AssetLink.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.IPInfo.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.AIUsage.Delete().Exec(ctx) },
		func(ctx context.Context) (int, error) { return c.Zone.Delete().Exec(ctx) },
	}
	for i, del := range dels {
		if _, err := del(ctx); err != nil {
			t.Fatalf("清空表 #%d 失败: %v", i, err)
		}
	}
}
