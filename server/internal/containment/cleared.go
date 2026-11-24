package containment

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/internal/audit"
)

// ClearedActor 事件按误报结案后解除处置时记的操作者
const ClearedActor = "system:false_positive"

// liftCleared 自动处置常在告警进事件之前就下发了，处置上不一定有事件号：按触发告警现在所在的事件判断，
// 事件在处置之后被按误报结案（false_positive），说明触发它的信号本身是误报，处置随之解除，不等租约到期。
// 按 closed 结案的（已遏制的威胁、授权运维）不解除：那里的处置可能正是结案的前提。
// 允许对先前解除失败的记录在退避期满后重试，SSO 账号走身份源接口而非 agent 指令通道。
func (e *Engine) liftCleared(ctx context.Context) error {
	now := e.now()
	rows, err := e.DB.Containment.Query().
		Where(entcontainment.StateIn(entcontainment.StateActive, entcontainment.StateExecuted),
			func(s *sql.Selector) {
				liftCol := s.C(entcontainment.FieldLiftCommandID)
				// 解除指令失败过，或预留了 ID 却没建成单（下发在建单前失败），都可以重新解除
				s.Where(sql.ExprP(`(` + liftCol + ` IS NULL OR NOT EXISTS (SELECT 1 FROM commands cmd WHERE cmd.id = ` + liftCol + ` AND cmd.status <> 'failed'))`))
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
		if e.inClearedBackoff(c.ID, now) {
			continue
		}
		if c.Kind == KindSSO {
			if _, err := e.LiftSSO(ctx, c, ClearedActor, "触发告警所在事件已按误报结案"); err != nil {
				if !errors.Is(err, ErrNotLiftable) {
					e.setClearedBackoff(c.ID, now.Add(liftRetry))
					slog.Error("误报结案后恢复 SSO 账号失败", "containment", c.ID, "err", err)
				}
				continue
			}
			e.clearClearedBackoff(c.ID)
			audit.System(ctx, e.DB, "containment_lifted", c.ID.String(), c.Kind+" "+c.Target+"（触发告警所在事件已按误报结案）")
			continue
		}
		existingCmd, _, prevFailedID, err := resolveLiftCommand(ctx, e.DB, c)
		if err != nil {
			return err
		}
		// 已有非 failed 解除指令（sent/pending/unknown/unsupported/succeeded）时不重复并发下发。
		if existingCmd != nil {
			continue
		}
		if prevFailedID != uuid.Nil {
			if prevCmd, getErr := e.DB.Command.Get(ctx, prevFailedID); getErr == nil {
				failedAt := prevCmd.CreatedAt
				if prevCmd.CompletedAt != nil {
					failedAt = *prevCmd.CompletedAt
				}
				if now.Before(failedAt.Add(liftRetry)) {
					continue
				}
			} else if !ent.IsNotFound(getErr) {
				return getErr
			}
		}
		_, err = Lift(ctx, e.DB, e.Hub, c, ClearedActor, "触发告警所在事件已按误报结案")
		if errors.Is(err, ErrNotLiftable) {
			continue
		}
		if err != nil {
			e.setClearedBackoff(c.ID, now.Add(liftRetry))
			slog.Error("误报结案后解除处置失败", "containment", c.ID, "err", err)
			continue
		}
		e.clearClearedBackoff(c.ID)
		audit.System(ctx, e.DB, "containment_lifted", c.ID.String(), c.Kind+" "+c.Target+"（触发告警所在事件已按误报结案）")
	}
	return nil
}

func (e *Engine) inClearedBackoff(id uuid.UUID, now time.Time) bool {
	if e.clearedBackoff == nil {
		return false
	}
	until, ok := e.clearedBackoff[id]
	if !ok {
		return false
	}
	if !now.Before(until) {
		delete(e.clearedBackoff, id)
		return false
	}
	return true
}

func (e *Engine) setClearedBackoff(id uuid.UUID, until time.Time) {
	if e.clearedBackoff == nil {
		e.clearedBackoff = map[uuid.UUID]time.Time{}
	}
	e.clearedBackoff[id] = until
}

func (e *Engine) clearClearedBackoff(id uuid.UUID) {
	delete(e.clearedBackoff, id)
}
