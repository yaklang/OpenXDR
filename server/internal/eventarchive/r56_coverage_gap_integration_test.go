//go:build integration

package eventarchive

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/temporal"
)

// R6（gap 清理断链）全链路：swap 跳过 gaps（P4 决策表）→ retire 的「日分区 − 暂存」差集
// 与逐行删除触发器都看不到已被移出热表的事件的 gap（无第三条提前删除路径）→ janitor 按
// gap 自身 created_at 的诊断保留期（TEMPORAL_GAP_RETENTION_DAYS，默认 30 天）清理。
// 保留期内 gap 不被 swap / retire / 清理动，到期后不依赖热行仍可清。
func TestR6GapSurvivesSwapAndRetireUntilDiagnosticExpiry(t *testing.T) {
	ctx, client, db := p0Open(t)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	old := p0Day(t, ctx, db, 20)
	asset := client.Asset.Create().SetHostname("r6-chain").SetOs("linux").SaveX(ctx)
	groupID := uuid.Must(uuid.NewV7())
	// A：口径内（4001/agent），swap 会把它移出热表；B：口径外（1007），retire 时随分区消失
	idA := p0Event(t, ctx, client, old.Add(time.Minute), 4001, "agent", `{"mark":"r6-a","conn":{"dst":"10.0.0.1:443"}}`)
	idB := p0Event(t, ctx, client, old.Add(2*time.Minute), 1007, "agent", `{"process":{"name":"r6-b"}}`)
	if _, err := db.ExecContext(ctx, `INSERT INTO temporal_rule_snapshots(revision, document)
 VALUES('r6-r1', '{}'::jsonb) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatalf("建规则快照: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM temporal_evaluation_gaps`); err != nil {
		t.Fatalf("清空 gaps: %v", err)
	}
	gap := func(event uuid.UUID) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO temporal_evaluation_gaps
		 (revision, event_id, asset_id, group_id, reason, candidate_count_lower_bound, window_from, window_to)
		 VALUES('r6-r1', $1, $2, $3, 'late', 0, $4, $5)`,
			event, asset.ID, groupID, old.Add(-time.Hour), old.Add(25*time.Hour)); err != nil {
			t.Fatalf("播种 gap(%s): %v", event, err)
		}
	}
	gap(idA)
	gap(idB)
	count := func(query string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
			t.Fatalf("统计 %q: %v", query, err)
		}
		return n
	}

	runID := p0VerifiedRun(t, ctx, db, old, old)
	p4SeedConsumed(t, ctx, db, old)
	p, err := Swap(ctx, db, runID, old)
	if err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if p.Dropped != 1 {
		t.Fatalf("应只移出 A，实际 %d", p.Dropped)
	}
	// swap 不删 gaps（P4 决策表，现行为保持）
	if n := count(`SELECT count(*) FROM temporal_evaluation_gaps WHERE event_id = $1`, idA); n != 1 {
		t.Fatalf("swap 后 A 的 gap 必须保留: %d", n)
	}

	// Retire 把该月钉住的行并进月归档分区（events_aYYYYMM），用完拆掉，别挡后面的用例
	month := time.Date(old.Year(), old.Month(), 1, 0, 0, 0, 0, time.UTC)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `ALTER TABLE events DETACH PARTITION `+eventpart.ArchiveName(month))
		_, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+eventpart.ArchiveName(month))
	})
	if _, _, err := eventpart.Retire(ctx, db, old.AddDate(0, 0, 2)); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	// B 仍在分区里且未被钉住：gaps 已移出派生清理清单（R6 补全），retire 差集不再
	// 连带删除——诊断记录按自身 created_at 的保留期由 PruneGaps 独立清理，与事件生命周期脱钩
	if n := count(`SELECT count(*) FROM temporal_evaluation_gaps WHERE event_id = $1`, idB); n != 1 {
		t.Fatalf("retire 后未钉住事件 B 的 gap 必须保留（按诊断期独立清理）: %d", n)
		// A 已被 swap 移出分区：retire 差集与逐行删除触发器都看不到它的 gap——
	}
	// 这正是 R6 要接住的断链（无第三条提前删除路径，也不会被提前删）
	if n := count(`SELECT count(*) FROM temporal_evaluation_gaps WHERE event_id = $1`, idA); n != 1 {
		t.Fatalf("已被 swap 移出分区的事件 A 的 gap 在退役后必须仍在: %d", n)
	}

	// 保留期内（TEMPORAL_GAP_RETENTION_DAYS 默认 30 天）：janitor 清理不动它
	if n, err := temporal.PruneGaps(ctx, db, 30*24*time.Hour); err != nil || n != 0 {
		t.Fatalf("保留期内的 gap 不应被清理: %d %v", n, err)
	}
	if n := count(`SELECT count(*) FROM temporal_evaluation_gaps WHERE event_id = $1`, idA); n != 1 {
		t.Fatalf("保留期内 A 的 gap 必须可查: %d", n)
	}
	// 到期后（时间流逝到 created_at 超过保留期）：不依赖热行仍可清——A 早已不在热表
	if _, err := db.ExecContext(ctx,
		`UPDATE temporal_evaluation_gaps SET created_at = now() - interval '31 days' WHERE event_id = $1`, idA); err != nil {
		t.Fatalf("推进诊断时间: %v", err)
	}
	if n, err := temporal.PruneGaps(ctx, db, 30*24*time.Hour); err != nil || n != 1 {
		t.Fatalf("到期的 gap 应被清理: %d %v", n, err)
	}
	if n := count(`SELECT count(*) FROM temporal_evaluation_gaps WHERE event_id = $1`, idA); n != 0 {
		t.Fatalf("到期的 gap 清理后不应残留: %d", n)
	}
}
