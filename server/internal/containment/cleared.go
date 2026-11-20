package containment

import (
	"context"
	"errors"
	"log/slog"

	"entgo.io/ent/dialect/sql"

	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/internal/audit"
)

// ClearedActor 事件按误报结案后解除处置时记的操作者
const ClearedActor = "system:false_positive"

// liftCleared 自动处置常在告警进事件之前就下发了，处置上不一定有事件号：按触发告警现在所在的事件判断，
// 事件在处置之后被按误报结案（false_positive），说明触发它的信号本身是误报，处置随之解除，不等租约到期。
// 按 closed 结案的（已遏制的威胁、授权运维）不解除：那里的处置可能正是结案的前提
func (e *Engine) liftCleared(ctx context.Context) error {
	rows, err := e.DB.Containment.Query().
		Where(entcontainment.StateIn(entcontainment.StateActive, entcontainment.StateExecuted), entcontainment.LiftCommandIDIsNil(),
			func(s *sql.Selector) {
				s.Where(sql.ExprP(`EXISTS (SELECT 1 FROM alerts a JOIN incidents i ON i.id = COALESCE(a.incident_id, ` + s.C(entcontainment.FieldIncidentID) + `)
WHERE a.id = ` + s.C(entcontainment.FieldAlertID) + ` AND i.status = 'false_positive' AND i.resolved_at > ` + s.C(entcontainment.FieldCreatedAt) + `)`))
			}).
		Limit(50).All(ctx)
	if err != nil {
		return err
	}
	for _, c := range rows {
		if !Liftable(c) {
			continue
		}
		_, err := Lift(ctx, e.DB, e.Hub, c, ClearedActor, "触发告警所在事件已按误报结案")
		if errors.Is(err, ErrNotLiftable) {
			continue
		}
		if err != nil {
			slog.Error("误报结案后解除处置失败", "containment", c.ID, "err", err)
			continue
		}
		audit.System(ctx, e.DB, "containment_lifted", c.ID.String(), c.Kind+" "+c.Target+"（触发告警所在事件已按误报结案）")
	}
	return nil
}
