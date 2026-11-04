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
	"isolate_host":    "unisolate_host",
	"block_network":   "unblock_network",
	"quarantine_file": "restore_file",
	"disable_account": "enable_account",
}

// ErrNotLiftable 这条处置不在生效中，或动作撤不回（结束进程）
var ErrNotLiftable = errors.New("只有生效中的封锁、隔离与已执行的隔离文件、锁定账号可以解除")

// Lift 人工解除或恢复一条处置：先下发恢复动作，送达才记 lifted。
// 解除时间之前的证据不再触发同一处置（见 decide），新的证据照样会。
func Lift(ctx context.Context, db *ent.Client, hub *response.Hub, c *ent.Containment, actor, why string) (*ent.Containment, error) {
	if !Liftable(c) {
		return nil, ErrNotLiftable
	}
	kind := reverse[c.Kind]
	cmd, err := hub.Issue(ctx, response.Request{
		AssetID: c.AssetID, Kind: kind, Target: c.Target, IncidentID: c.IncidentID, IssuedBy: actor,
	})
	if err != nil {
		return nil, err
	}
	if cmd.Status == "failed" {
		detail := "agent 未执行"
		if cmd.Detail != nil {
			detail = *cmd.Detail
		}
		return nil, errors.New("恢复指令下发失败：" + detail)
	}
	reason := c.Reason + "；" + actor + " 人工解除"
	if why != "" {
		reason += "：" + why
	}
	return c.Update().SetState(entcontainment.StateLifted).SetLiftCommandID(cmd.ID).
		SetLiftedBy(actor).SetEndedAt(time.Now()).SetReason(reason).Save(ctx)
}

// Liftable 这条处置现在能不能人工解除或恢复
func Liftable(c *ent.Containment) bool {
	_, ok := reverse[c.Kind]
	return ok && (c.State == entcontainment.StateActive || c.State == entcontainment.StateExecuted)
}
