package containment

import (
	"context"
	"errors"
	"time"

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
	// 身份源那边已经动过了，回写不能跟着调用方的 ctx 一起被取消；写不进去的由 settleStaleSSO 兜底
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return e.DB.Containment.Update().
		Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StatePending)).
		SetState(state).SetReason(reason).Exec(wctx)
}

// ssoPendingStale SSO 处置停在 pending 多久算回写丢了：身份源调用 30 秒超时，留足余量
const ssoPendingStale = 5 * time.Minute

// settleStaleSSO 停用结果没写回（停机、丢 leader、写库失败）的 SSO 处置按已停用处理：
// 账号可能已在身份源停用，转 executed 才能经 LiftSSO 恢复（Enable 幂等），也不再挡住同一账号以后的处置
func (e *Engine) settleStaleSSO(ctx context.Context) error {
	stale, err := e.DB.Containment.Query().Where(
		entcontainment.KindEQ(KindSSO),
		entcontainment.StateEQ(entcontainment.StatePending),
		entcontainment.CreatedAtLT(e.now().Add(-ssoPendingStale)),
	).All(ctx)
	if err != nil {
		return err
	}
	for _, c := range stale {
		n, err := e.DB.Containment.Update().
			Where(entcontainment.IDEQ(c.ID), entcontainment.StateEQ(entcontainment.StatePending)).
			SetState(entcontainment.StateExecuted).SetReason(c.Reason + "；停用结果未写回，按已停用处理，可人工恢复").Save(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			audit.System(ctx, e.DB, "containment_failed", c.AlertID.String(), c.Kind+" "+c.Target+"：停用结果未写回，按已停用处理")
		}
	}
	return nil
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
