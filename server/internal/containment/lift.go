package containment

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/response"
)

// reverse 人工能撤回的处置与对应的恢复动作。结束进程撤不回
var reverse = map[string]string{
	"isolate_host":      "unisolate_host",
	"isolate_container": "unisolate_container",
	"block_network":     "unblock_network",
	"quarantine_file":   "restore_file",
	"disable_account":   "enable_account",
}

// ErrNotLiftable 这条处置不在生效中，或动作撤不回（结束进程）
var ErrNotLiftable = errors.New("只有生效中的封锁、隔离与已执行的隔离文件、锁定账号可以解除")

// Lift 人工解除或恢复一条处置：先原子预留确定性 LiftCommandID 再下发恢复动作，收到成功回执才经对账记 lifted。
// 已有解除指令在途或结果未知时不重复建指令；解除时间之前的证据不再触发同一处置（见 decide），新的证据照样会。
func Lift(ctx context.Context, db *ent.Client, hub *response.Hub, c *ent.Containment, actor, why string) (*ent.Containment, error) {
	curr, err := db.Containment.Get(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	if !Liftable(curr) {
		return nil, ErrNotLiftable
	}
	reason := buildManualLiftReason(curr.Reason, actor, why)

	existingCmd, cmdID, prevFailedID, err := resolveLiftCommand(ctx, db, curr)
	if err != nil {
		return nil, err
	}
	if existingCmd != nil {
		return settleExistingLift(ctx, db, curr, existingCmd, actor, reason)
	}
	// 若当前记录已预留同一待下发 cmdID，说明另一并发调用正在下发该指令，绝不重复建单或重送。
	if curr.LiftCommandID != nil && *curr.LiftCommandID == cmdID {
		if curr.LiftedBy == nil || *curr.LiftedBy == "" || curr.Reason != reason {
			_ = db.Containment.Update().
				Where(entcontainment.IDEQ(curr.ID), entcontainment.LiftCommandIDEQ(cmdID)).
				SetLiftedBy(actor).SetReason(reason).Exec(ctx)
		}
		return db.Containment.Get(ctx, curr.ID)
	}

	reserve := db.Containment.Update().
		Where(
			entcontainment.IDEQ(curr.ID),
			entcontainment.StateIn(entcontainment.StateActive, entcontainment.StateExecuted),
		).
		SetLiftCommandID(cmdID).
		SetLiftedBy(actor).
		SetReason(reason)
	if prevFailedID == uuid.Nil {
		reserve.Where(entcontainment.LiftCommandIDIsNil())
	} else {
		reserve.Where(entcontainment.LiftCommandIDEQ(prevFailedID))
	}
	n, err := reserve.Save(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		latest, getErr := db.Containment.Get(ctx, curr.ID)
		if getErr != nil {
			return nil, getErr
		}
		if !Liftable(latest) {
			return nil, ErrNotLiftable
		}
		existingCmd, _, _, err := resolveLiftCommand(ctx, db, latest)
		if err != nil {
			return nil, err
		}
		if existingCmd != nil {
			return settleExistingLift(ctx, db, latest, existingCmd, actor, buildManualLiftReason(latest.Reason, actor, why))
		}
		return latest, nil
	}

	kind := reverse[curr.Kind]
	cmd, issueErr := hub.Issue(ctx, response.Request{
		CommandID: cmdID, AssetID: curr.AssetID, Kind: kind, Target: curr.Target, IncidentID: curr.IncidentID, IssuedBy: actor,
	})
	if issueErr != nil && !errors.Is(issueErr, response.ErrDeliveryUnknown) && cmd == nil {
		if _, lookupErr := db.Command.Get(ctx, cmdID); ent.IsNotFound(lookupErr) {
			rollback := db.Containment.Update().
				Where(entcontainment.IDEQ(curr.ID), entcontainment.LiftCommandIDEQ(cmdID)).
				ClearLiftedBy().SetReason(curr.Reason)
			if prevFailedID == uuid.Nil {
				rollback.ClearLiftCommandID()
			} else {
				rollback.SetLiftCommandID(prevFailedID)
			}
			_ = rollback.Exec(ctx)
		}
		return nil, issueErr
	}
	if cmd == nil {
		return db.Containment.Get(ctx, curr.ID)
	}
	if cmd.Status == "failed" || cmd.Status == "unsupported" {
		detail := "agent 未执行"
		if cmd.Detail != nil && *cmd.Detail != "" {
			detail = *cmd.Detail
		}
		if cmd.Status == "failed" {
			_ = db.Containment.Update().
				Where(entcontainment.IDEQ(curr.ID), entcontainment.LiftCommandIDEQ(cmd.ID)).
				ClearLiftedBy().Exec(ctx)
		}
		return nil, errors.New("恢复指令下发失败：" + detail)
	}
	if cmd.Status == "succeeded" {
		ended := time.Now()
		if cmd.CompletedAt != nil {
			ended = *cmd.CompletedAt
		}
		_ = db.Containment.Update().
			Where(entcontainment.IDEQ(curr.ID), entcontainment.LiftCommandIDEQ(cmd.ID)).
			SetState(entcontainment.StateLifted).SetLiftedBy(actor).SetEndedAt(ended).SetReason(reason).Exec(ctx)
	} else if cmd.Status == "unknown" || errors.Is(issueErr, response.ErrDeliveryUnknown) {
		_ = db.Containment.Update().
			Where(entcontainment.IDEQ(curr.ID), entcontainment.LiftCommandIDEQ(cmd.ID)).
			SetLiftedBy(actor).SetReason(appendReasonOnce(reason, "解除执行结果未知（禁止自动重发）")).Exec(ctx)
	}
	return db.Containment.Get(ctx, curr.ID)
}

func sameLiftCommandPredicate(curr *ent.Containment) predicate.Containment {
	if curr.LiftCommandID == nil {
		return entcontainment.LiftCommandIDIsNil()
	}
	return entcontainment.LiftCommandIDEQ(*curr.LiftCommandID)
}

func settleExistingLift(ctx context.Context, db *ent.Client, curr *ent.Containment, prev *ent.Command, actor, reason string) (*ent.Containment, error) {
	switch prev.Status {
	case "succeeded":
		ended := time.Now()
		if prev.CompletedAt != nil {
			ended = *prev.CompletedAt
		}
		_ = db.Containment.Update().
			Where(entcontainment.IDEQ(curr.ID), entcontainment.StateIn(entcontainment.StateActive, entcontainment.StateExecuted), sameLiftCommandPredicate(curr)).
			SetLiftCommandID(prev.ID).SetState(entcontainment.StateLifted).SetLiftedBy(actor).SetEndedAt(ended).SetReason(reason).Exec(ctx)
		return db.Containment.Get(ctx, curr.ID)
	case "sent", "pending", "unknown":
		upd := db.Containment.Update().
			Where(entcontainment.IDEQ(curr.ID), entcontainment.StateIn(entcontainment.StateActive, entcontainment.StateExecuted), sameLiftCommandPredicate(curr)).
			SetLiftCommandID(prev.ID).SetReason(reason)
		if curr.LiftedBy == nil || *curr.LiftedBy == "" {
			upd.SetLiftedBy(actor)
		}
		_ = upd.Exec(ctx)
		return db.Containment.Get(ctx, curr.ID)
	case "unsupported":
		return nil, errors.New("恢复指令下发失败：agent 不支持该动作")
	default:
		return db.Containment.Get(ctx, curr.ID)
	}
}

func buildManualLiftReason(base, actor, why string) string {
	suffix := actor + " 人工解除"
	if why != "" {
		suffix += "：" + why
	}
	return appendReasonOnce(base, suffix)
}

// Liftable 这条处置现在能不能人工解除或恢复
func Liftable(c *ent.Containment) bool {
	_, ok := reverse[c.Kind]
	return ok && (c.State == entcontainment.StateActive || c.State == entcontainment.StateExecuted)
}
