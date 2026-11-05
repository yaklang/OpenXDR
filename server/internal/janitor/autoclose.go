package janitor

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/review"
)

// AutoClose 将到期且已有当前结案建议的良性事件交独立审计。
// 等待天数仅决定复查时机，不是良性证据；所有结案由 Review 完成。
type AutoClose struct {
	DB       *ent.Client
	Days     int
	Interval time.Duration
	Review   func(context.Context, uuid.UUID) (bool, error)
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

// sweep 只触发有界复核，不持锁调用模型，也不绕过独立审计直接按超时结案。
func (a *AutoClose) sweep(ctx context.Context) (int, error) {
	if a.Days <= 0 || a.Review == nil {
		return 0, nil
	}
	rows, err := a.DB.Incident.Query().Where(review.StaleBenign(time.Now().AddDate(0, 0, -a.Days)), incident.ClosureProposalNotNil()).Order(ent.Asc(incident.FieldID)).Limit(500).All(ctx)
	if err != nil {
		return 0, err
	}
	closed := 0
	for _, row := range rows {
		p := row.ClosureProposal
		if p == nil || p.Status != "false_positive" || row.TriagedAt == nil || p.EvidenceKey == "" || p.VerdictHash == "" || p.At.Before(*row.TriagedAt) {
			continue
		}
		stale := false
		for _, at := range []*time.Time{row.EvidenceAt, row.UrgentAt} {
			if at != nil && p.At.Before(*at) {
				stale = true
			}
		}
		if stale {
			continue
		}
		ok, err := a.Review(ctx, row.ID)
		if err != nil {
			return closed, err
		}
		if ok {
			closed++
		}
	}
	return closed, nil
}
