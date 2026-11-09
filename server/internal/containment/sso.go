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

// disableSSO 落库并执行 SSO 账号停用：成功记 executed，失败或被保护记 failed，原因写进记录
func (e *Engine) disableSSO(ctx context.Context, create *ent.ContainmentCreate, a action, al *ent.Alert) error {
	if e.SSO == nil {
		return ignoreConflict(create.SetState(entcontainment.StateSkipped).SetReason(a.why + "；未配置 SSO 处置（AUTHENTIK_RESPONSE_TOKEN）").Exec(ctx))
	}
	held, err := e.fuse(ctx, a)
	if err != nil {
		return err
	}
	if held != "" {
		return ignoreConflict(create.SetState(entcontainment.StateHeld).SetReason(held).Exec(ctx))
	}
	msg, err := e.SSO.Disable(ctx, a.target)
	state, reason := entcontainment.StateExecuted, a.why+"；"+msg
	if err != nil {
		state, reason = entcontainment.StateFailed, a.why+"；执行失败："+err.Error()
		audit.System(ctx, e.DB, "containment_failed", al.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+err.Error())
	} else {
		audit.System(ctx, e.DB, "containment", al.ID.String(), a.asset.Hostname+" "+a.kind+" "+a.target+"："+msg)
	}
	return ignoreConflict(create.SetState(state).SetReason(reason).Exec(ctx))
}

func ignoreConflict(err error) error {
	if ent.IsConstraintError(err) {
		return nil
	}
	return err
}

// LiftSSO 人工恢复被停用的 SSO 账号
func (e *Engine) LiftSSO(ctx context.Context, c *ent.Containment, actor, why string) (*ent.Containment, error) {
	if c.Kind != KindSSO || c.State != entcontainment.StateExecuted {
		return nil, ErrNotLiftable
	}
	if e.SSO == nil {
		return nil, errors.New("未配置 SSO 处置（AUTHENTIK_RESPONSE_TOKEN），恢复请在 Authentik 后台操作")
	}
	msg, err := e.SSO.Enable(ctx, c.Target)
	if err != nil {
		return nil, err
	}
	reason := c.Reason + "；" + actor + " 恢复：" + msg
	if why != "" {
		reason += "（" + why + "）"
	}
	if err := e.DB.Containment.Update().Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StateExecuted)).
		SetState(entcontainment.StateLifted).SetEndedAt(e.now()).SetLiftedBy(actor).SetReason(reason).Exec(ctx); err != nil {
		return nil, err
	}
	return e.DB.Containment.Get(ctx, c.ID)
}
