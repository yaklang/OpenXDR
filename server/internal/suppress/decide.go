package suppress

import (
	"context"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/suppression"
)

// Decide 审批一条待批准的提议：批准即生效，有效期从批准那一刻按原时长重新算；拒绝记为 rejected。
// 组管理员与 AI 审计员共用。只改仍是 proposed 的，已被别人处理返回 false；审计与重载索引由调用方做
func Decide(ctx context.Context, db *ent.Client, s *ent.Suppression, approve bool, by string, at time.Time) (bool, error) {
	update := db.Suppression.Update().Where(suppression.IDEQ(s.ID), suppression.StatusEQ("proposed")).
		SetReviewedBy(by).SetReviewedAt(at).SetStatus("rejected")
	if approve {
		update.SetStatus("active")
		if s.ExpiresAt != nil {
			update.SetExpiresAt(at.Add(s.ExpiresAt.Sub(s.CreatedAt)))
		}
	}
	n, err := update.Save(ctx)
	return n == 1, err
}
