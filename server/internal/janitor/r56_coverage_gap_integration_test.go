//go:build integration

package janitor

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entevent "openxdr/server/ent/event"
	"openxdr/server/internal/testdb"
)

// R6（gap 清理断链）回归：temporal_evaluation_gaps 按 gap 自身的 created_at（诊断时间）
// 清理，绝不 JOIN events——swap 移出热表的事件的 gap 不随退役 / 删除走。
//
//	用例                                        | 覆盖的点
//	--------------------------------------------|----------------------------------
//	TestR6GapSweptByDiagnosticAge               | 默认 30 天口径：旧删新留、重复清理幂等
//	TestR6GapRetentionConfigured                | 显式配置 7 天：按配置的保留期清理
//	TestR6GapAgeByCreatedAtNotEventTs           | 事件 ts 很老、gap 今天产生：不因事件过期
//	TestR6GapRetentionDisabled                  | 0 关闭 / 无 SQL 时不清理

// r56Seeder 建好 gap 需要的外键行（revision 快照、资产），返回按诊断时间播种 gap 的函数。
// 共享测试库串行跑，先清掉 gaps，保证删除计数只来自本用例。
func r56Seeder(t *testing.T, ctx context.Context, client *ent.Client, db *sql.DB) func(eventID uuid.UUID, createdAgo time.Duration) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `DELETE FROM temporal_evaluation_gaps`); err != nil {
		t.Fatalf("清空 gaps: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO temporal_rule_snapshots(revision, document)
 VALUES('r56-r1', '{}'::jsonb) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatalf("建规则快照: %v", err)
	}
	asset := client.Asset.Create().SetHostname("r56-gap").SaveX(ctx)
	groupID := uuid.Must(uuid.NewV7())
	return func(eventID uuid.UUID, createdAgo time.Duration) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO temporal_evaluation_gaps
		 (revision, event_id, asset_id, group_id, reason, candidate_count_lower_bound, window_from, window_to, created_at)
		 VALUES('r56-r1', $1, $2, $3, 'late', 0, now(), now(), now() - make_interval(secs => $4))`,
			eventID, asset.ID, groupID, createdAgo.Seconds()); err != nil {
			t.Fatalf("播种 gap: %v", err)
		}
	}
}

func r56GapCount(t *testing.T, ctx context.Context, db *sql.DB, eventID uuid.UUID) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM temporal_evaluation_gaps WHERE event_id = $1`, eventID).Scan(&n); err != nil {
		t.Fatalf("统计 gap: %v", err)
	}
	return n
}

func r56Open(t *testing.T) (context.Context, *ent.Client, *sql.DB) {
	t.Helper()
	ctx, client := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return ctx, client, db
}

// 默认口径（TEMPORAL_GAP_RETENTION_DAYS=30）：超过 30 天的诊断删，保留期内的留；
// 重复清理不再删任何行。
func TestR6GapSweptByDiagnosticAge(t *testing.T) {
	ctx, client, db := r56Open(t)
	seed := r56Seeder(t, ctx, client, db)
	expired, kept := uuid.New(), uuid.New()
	seed(expired, 31*24*time.Hour)
	seed(kept, 24*time.Hour)

	j := &Janitor{DB: client, SQL: db, GapRetention: 30 * 24 * time.Hour}
	n, err := j.sweepTemporalGaps(ctx)
	if err != nil || n != 1 {
		t.Fatalf("应只删 1 条过期 gap: %d %v", n, err)
	}
	if c := r56GapCount(t, ctx, db, expired); c != 0 {
		t.Fatalf("过期的 gap 应被清理: %d", c)
	}
	if c := r56GapCount(t, ctx, db, kept); c != 1 {
		t.Fatalf("保留期内的 gap 不应被清理: %d", c)
	}
	// 重复清理：没有新的过期行，删 0 条
	if n, err := j.sweepTemporalGaps(ctx); err != nil || n != 0 {
		t.Fatalf("重复清理应删 0 条: %d %v", n, err)
	}
}

// 显式配置的保留期（TEMPORAL_GAP_RETENTION_DAYS=7）：按配置生效，不用默认值。
func TestR6GapRetentionConfigured(t *testing.T) {
	ctx, client, db := r56Open(t)
	seed := r56Seeder(t, ctx, client, db)
	eightDays, sixDays := uuid.New(), uuid.New()
	seed(eightDays, 8*24*time.Hour)
	seed(sixDays, 6*24*time.Hour)

	j := &Janitor{DB: client, SQL: db, GapRetention: 7 * 24 * time.Hour}
	if n, err := j.sweepTemporalGaps(ctx); err != nil || n != 1 {
		t.Fatalf("7 天口径应只删 8 天前那条: %d %v", n, err)
	}
	if c := r56GapCount(t, ctx, db, eightDays); c != 0 {
		t.Fatalf("8 天前的 gap 应被清理: %d", c)
	}
	if c := r56GapCount(t, ctx, db, sixDays); c != 1 {
		t.Fatalf("6 天前的 gap 在 7 天口径内不应被清理: %d", c)
	}
}

// 旧事件今天产生 late gap（事件 ts 很老、created_at 新）：清理只看诊断时间——
// 事件早已过了任何保留口径，gap 仍在保留期内就必须留下；对照：新事件 + 过期的
// gap 照删。顺带证明清理不删事件本身（不 JOIN events）。
func TestR6GapAgeByCreatedAtNotEventTs(t *testing.T) {
	ctx, client, db := r56Open(t)
	seed := r56Seeder(t, ctx, client, db)
	oldEvent := client.Event.Create().SetTs(time.Now().Add(-40 * 24 * time.Hour)).
		SetClassUID(4001).SetSource("agent").SetRaw([]byte(`{"mark":"r56-late"}`)).SaveX(ctx)
	freshEvent := client.Event.Create().SetTs(time.Now()).
		SetClassUID(4001).SetSource("agent").SetRaw([]byte(`{"mark":"r56-fresh"}`)).SaveX(ctx)
	seed(oldEvent.ID, 0)                 // 迟到事件今天刚产生的诊断
	seed(freshEvent.ID, 31*24*time.Hour) // 新事件上早已过期的诊断

	j := &Janitor{DB: client, SQL: db, GapRetention: 30 * 24 * time.Hour}
	if n, err := j.sweepTemporalGaps(ctx); err != nil || n != 1 {
		t.Fatalf("应只删按 created_at 过期的那条: %d %v", n, err)
	}
	if c := r56GapCount(t, ctx, db, oldEvent.ID); c != 1 {
		t.Fatalf("旧事件今天产生的 gap 不应因事件时间过期: %d", c)
	}
	if c := r56GapCount(t, ctx, db, freshEvent.ID); c != 0 {
		t.Fatalf("created_at 过期的 gap 应被清理: %d", c)
	}
	// 清理 gap 不删事件：老事件行原样在热表（它的删除走事件自己的保留策略）
	if n, err := client.Event.Query().IDs(ctx); err != nil || len(n) != 2 {
		t.Fatalf("gap 清理不应删除事件: %v %v", n, err)
	}
}

// 0 关闭清理；没有 SQL 连接的部署也不清（与其它步骤的闸门一致）。
func TestR6GapRetentionDisabled(t *testing.T) {
	ctx, client, db := r56Open(t)
	seed := r56Seeder(t, ctx, client, db)
	ancient := uuid.New()
	seed(ancient, 400*24*time.Hour)

	if n, err := (&Janitor{DB: client, SQL: db}).sweepTemporalGaps(ctx); err != nil || n != 0 {
		t.Fatalf("GapRetention=0 应关闭清理: %d %v", n, err)
	}
	if c := r56GapCount(t, ctx, db, ancient); c != 1 {
		t.Fatalf("关闭时不应清理: %d", c)
	}
	if n, err := (&Janitor{DB: client, GapRetention: time.Hour}).sweepTemporalGaps(ctx); err != nil || n != 0 {
		t.Fatalf("无 SQL 连接应跳过清理: %d %v", n, err)
	}
}

// R6 补全后的完整清理链回归：gaps 已移出事件删除级联（触发器 + retire 派生清单），
// 唯一清理入口是按 created_at 的 PruneGaps；资产删除的 ON DELETE CASCADE 是唯一例外。
// 这里逐条验证三条此前会连带删 gap 的路径，现在都保留到诊断期。
func TestR6GapSurvivesEventLifecyclePaths(t *testing.T) {
	ctx, client, db := r56Open(t)
	seed := r56Seeder(t, ctx, client, db)
	j := &Janitor{DB: client, SQL: db, GapRetention: 30 * 24 * time.Hour}

	// 路径一：普通未 swap 事件走保留期退役（逐行 DELETE → 触发器）。旧实现会连带删 gap，
	// 现在触发器不再删 temporal_evaluation_gaps。
	oldEvent := client.Event.Create().SetTs(time.Now().Add(-40 * 24 * time.Hour)).
		SetClassUID(4001).SetSource("agent").SetRaw([]byte(`{"mark":"r6c-retire"}`)).SaveX(ctx)
	seed(oldEvent.ID, 0)
	if _, err := client.Event.Delete().Where(entevent.ID(oldEvent.ID)).Exec(ctx); err != nil {
		t.Fatalf("删除事件: %v", err)
	}
	if c := r56GapCount(t, ctx, db, oldEvent.ID); c != 1 {
		t.Fatalf("逐行删除事件后 gap 必须保留（按诊断期独立清理）: %d", c)
	}

	// 路径二：swap→restore 后再次到期清理（restore 把行插回热表，janitor 再删）。
	restored := client.Event.Create().SetTs(time.Now().Add(-40 * 24 * time.Hour)).
		SetClassUID(4001).SetSource("agent").SetRaw([]byte(`{"mark":"r6c-restore"}`)).SaveX(ctx)
	seed(restored.ID, 0)
	if err := client.Event.DeleteOneID(restored.ID).Exec(ctx); err != nil {
		t.Fatalf("删除 restore 后的事件: %v", err)
	}
	if c := r56GapCount(t, ctx, db, restored.ID); c != 1 {
		t.Fatalf("restore 后再清理，gap 必须保留: %d", c)
	}

	// 到期后 PruneGaps 统一清理（不依赖热行）
	if _, err := db.ExecContext(ctx,
		`UPDATE temporal_evaluation_gaps SET created_at = now() - interval '31 days'
WHERE event_id IN ($1, $2)`, oldEvent.ID, restored.ID); err != nil {
		t.Fatalf("推进诊断时间: %v", err)
	}
	if n, err := j.sweepTemporalGaps(ctx); err != nil || n != 2 {
		t.Fatalf("到期后应清理两条: %d %v", n, err)
	}
	if c := r56GapCount(t, ctx, db, oldEvent.ID) + r56GapCount(t, ctx, db, restored.ID); c != 0 {
		t.Fatalf("到期 gap 应清零: %d", c)
	}

	// 例外：资产删除的 ON DELETE CASCADE 仍连带删 gap（资产生命周期，明确保留）。
	// 不走 seed()——它有自己的资产；这里手工造「独立资产 + 指向它的事件与 gap」。
	cascadeAsset := client.Asset.Create().SetHostname("r6c-cascade").SetOs("linux").SaveX(ctx)
	ev := client.Event.Create().SetTs(time.Now()).SetAssetID(cascadeAsset.ID).
		SetClassUID(4001).SetSource("agent").SetRaw([]byte(`{}`)).SaveX(ctx)
	if _, err := db.ExecContext(ctx, `INSERT INTO temporal_evaluation_gaps
	 (revision, event_id, asset_id, group_id, reason, candidate_count_lower_bound, window_from, window_to, created_at)
	 VALUES('r56-r1', $1, $2, $3, 'late', 0, now(), now(), now())`,
		ev.ID, cascadeAsset.ID, uuid.Must(uuid.NewV7())); err != nil {
		t.Fatalf("播种级联例外 gap: %v", err)
	}
	if err := client.Asset.DeleteOneID(cascadeAsset.ID).Exec(ctx); err != nil {
		t.Fatalf("删除资产: %v", err)
	}
	if c := r56GapCount(t, ctx, db, ev.ID); c != 0 {
		t.Fatalf("资产级联是唯一例外：gap 应随资产删除: %d", c)
	}
}
