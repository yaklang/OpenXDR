package containment

import (
	"context"
	"errors"
	"time"

	"openxdr/server/ent"
	entcontainment "openxdr/server/ent/containment"
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

// Lift 人工解除或恢复一条处置：先下发恢复动作，收到成功回执才经对账记 lifted。
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
	if curr.LiftCommandID != nil {
		prev, err := db.Command.Get(ctx, *curr.LiftCommandID)
		if err != nil && !ent.IsNotFound(err) {
			return nil, err
		}
		if prev != nil {
			switch prev.Status {
			case "succeeded":
				ended := time.Now()
				if prev.CompletedAt != nil {
					ended = *prev.CompletedAt
				}
				return curr.Update().SetState(entcontainment.StateLifted).
					SetLiftedBy(actor).SetEndedAt(ended).SetReason(reason).Save(ctx)
			case "sent", "pending", "unknown":
				if curr.LiftedBy == nil || *curr.LiftedBy == "" {
					return curr.Update().SetLiftedBy(actor).SetReason(reason).Save(ctx)
				}
				return curr, nil
			case "unsupported":
				return nil, errors.New("恢复指令下发失败：agent 不支持该动作")
			}
		}
	}
	kind := reverse[curr.Kind]
	cmd, err := hub.Issue(ctx, response.Request{
		AssetID: curr.AssetID, Kind: kind, Target: curr.Target, IncidentID: curr.IncidentID, IssuedBy: actor,
	})
	if err != nil {
		return nil, err
	}
	if cmd.Status == "failed" || cmd.Status == "unsupported" {
		detail := "agent 未执行"
		if cmd.Detail != nil && *cmd.Detail != "" {
			detail = *cmd.Detail
		}
		return nil, errors.New("恢复指令下发失败：" + detail)
	}
	upd := curr.Update().SetLiftCommandID(cmd.ID).SetLiftedBy(actor).SetReason(reason)
	if cmd.Status == "succeeded" {
		ended := time.Now()
		if cmd.CompletedAt != nil {
			ended = *cmd.CompletedAt
		}
		upd.SetState(entcontainment.StateLifted).SetEndedAt(ended)
	}
	return upd.Save(ctx)
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
