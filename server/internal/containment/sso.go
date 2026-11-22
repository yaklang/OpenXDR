package containment

import (
	"context"
	"errors"

	"openxdr/server/ent"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/internal/audit"
)

// KindSSO 停用 SSO 账号：server 直接调身份源（Authentik），不经 agent。一次性处置，到期不自动恢复
const KindSSO = "disable_sso_account"

// SSOAccounts 身份源上的账号停用与恢复，返回给人看的结果
type SSOAccounts interface {
	Disable(ctx context.Context, username string) (string, error)
	Enable(ctx context.Context, username string) (string, error)
}

// disableSSO 先落库预占 pending（含熔断检查），再调身份源执行停用，最后按结果回写 executed 或 failed；
// 落库失败或主键冲突时绝不调用外部身份源，避免账号已在外部停用而库中无记录。
func (e *Engine) disableSSO(ctx context.Context, create *ent.ContainmentCreate, a action, al *ent.Alert) error {
	if e.SSO == nil {
		return ignoreConflict(create.SetState(entcontainment.StateSkipped).SetReason(a.why + "；未配置 SSO 处置（AUTHENTIK_RESPONSE_TOKEN）").Exec(ctx))
	}
	var c *ent.Containment
	var heldReason string
	if err := e.withFuseLock(ctx, func() error {
		held, err := e.fuse(ctx, a)
		if err != nil {
			return err
		}
		if held != "" {
			if err := create.SetState(entcontainment.StateHeld).SetReason(held).Exec(ctx); err != nil {
				if ent.IsConstraintError(err) {
					return nil
				}
				return err
			}
			heldReason = held
			return nil
		}
		saved, err := create.SetState(entcontainment.StatePending).SetReason(a.why).Save(ctx)
		if err != nil {
			if ent.IsConstraintError(err) {
				return nil
			}
			return err
		}
		c = saved
		return nil
	}); err != nil {
		return err
	}
	if heldReason != "" {
		audit.System(ctx, e.DB, "containment_held", al.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+heldReason)
		return nil
	}
	if c == nil {
		return nil
	}
	msg, disableErr := e.SSO.Disable(ctx, a.target)
	state, reason := entcontainment.StateExecuted, a.why+"；"+msg
	if disableErr != nil {
		state, reason = entcontainment.StateFailed, a.why+"；执行失败："+disableErr.Error()
		audit.System(ctx, e.DB, "containment_failed", al.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+disableErr.Error())
	} else {
		audit.System(ctx, e.DB, "containment", al.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+msg)
	}
	return e.DB.Containment.Update().
		Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StatePending)).
		SetState(state).SetReason(reason).Exec(ctx)
}

func ignoreConflict(err error) error {
	if ent.IsConstraintError(err) {
		return nil
	}
	return err
}

// LiftSSO 人工或系统误报恢复被停用的 SSO 账号
func (e *Engine) LiftSSO(ctx context.Context, c *ent.Containment, actor, why string) (*ent.Containment, error) {
	curr, err := e.DB.Containment.Get(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	if curr.Kind != KindSSO || curr.State != entcontainment.StateExecuted {
		return nil, ErrNotLiftable
	}
	if e.SSO == nil {
		return nil, errors.New("未配置 SSO 处置（AUTHENTIK_RESPONSE_TOKEN），恢复请在 Authentik 后台操作")
	}
	msg, err := e.SSO.Enable(ctx, curr.Target)
	if err != nil {
		return nil, err
	}
	reason := curr.Reason + "；" + actor + " 恢复：" + msg
	if why != "" {
		reason += "（" + why + "）"
	}
	if err := e.DB.Containment.Update().Where(entcontainment.IDEQ(curr.ID), entcontainment.StateEQ(entcontainment.StateExecuted)).
		SetState(entcontainment.StateLifted).SetEndedAt(e.now()).SetLiftedBy(actor).SetReason(reason).Exec(ctx); err != nil {
		return nil, err
	}
	return e.DB.Containment.Get(ctx, curr.ID)
}
