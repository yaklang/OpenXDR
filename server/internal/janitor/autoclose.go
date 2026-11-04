package janitor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"entgo.io/ent/dialect/sql"
	"openxdr/server/ent"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/incidentstate"
	"openxdr/server/internal/review"
)

// AutoClose 把 AI 判良性、放了 Days 天没人处理的事件按误报结案，
// 免得待处理清单被噪声撑满。需人工复核的事件（review.Needed）以及未证实为良性的可疑事件永远不会被自动按误报关掉。
type AutoClose struct {
	DB       *ent.Client
	Days     int
	Interval time.Duration
}

// Run 拿到租约先扫一次再按周期扫：只靠定时器的话，部署频繁时每次重启都把计时清零，永远轮不到。
func (a *AutoClose) Run(ctx context.Context) {
	ticker := time.NewTicker(a.Interval)
	defer ticker.Stop()
	for {
		if n, err := a.sweep(ctx); err != nil {
			slog.Error("良性事件自动结案失败", "err", err)
		} else if n > 0 {
			slog.Info("良性事件自动结案", "closed", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweep 锁住候选后将结案、审计和发件箱一起提交，批量有界。
func (a *AutoClose) sweep(ctx context.Context) (int, error) {
	if a.Days <= 0 {
		return 0, nil
	}
	now := time.Now()
	note := fmt.Sprintf("AI 判良性、%d 天无人处理，系统自动结案", a.Days)
	tx, err := a.DB.Tx(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.Incident.Query().Where(review.StaleBenign(now.AddDate(0, 0, -a.Days))).Order(ent.Asc(incident.FieldID)).Limit(500).
		Where(func(s *sql.Selector) { s.ForUpdate(sql.WithLockAction(sql.SkipLocked)) }).All(ctx)
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		err := tx.Incident.UpdateOneID(row.ID).SetStatus("false_positive").SetResolution(note).SetResolvedBy(review.ClosedBy).SetResolvedAt(now).ClearClosureProposal().Exec(ctx)
		if err != nil {
			return 0, err
		}
		if err := incidentstate.Record(ctx, tx, row.ID, incidentstate.StatusChanged, incidentstate.Origin{Kind: "system"}, row.Status); err != nil {
			return 0, err
		}
	}
	if len(rows) > 0 {
		if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "incident_auto_closed", "", fmt.Sprintf("自动结案 %d 个事件（%d 天无人处理的 AI 判良性事件）", len(rows), a.Days)); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(rows), nil
}
