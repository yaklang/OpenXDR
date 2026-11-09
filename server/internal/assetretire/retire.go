// Package assetretire 主机下线（退役）与恢复。
//
// 资产表被事件、告警、指令、处置引用着，删掉会断掉历史证据，所以下线只打标记：
//   - 清掉 agent_id：失联监控、采集健康、指令下发都以它为前提，下线后这些地方自然不再管这台主机；
//     agent 注册与事件流按主机名或 agent_id 认人，下线的主机在接入口被拒（旧证书接不回来，见 grpcsvc）
//   - 结束挂在它身上的处置：待审批的作废，生效中的标记为解除（主机已不在，解除指令送不到，不再重试）
//   - 资产列表默认不显示，历史事件、告警照常可查
//
// 用接入令牌重新接入或在控制台恢复即取消下线；恢复后 agent 重新注册会拿到新的 agent_id。
package assetretire

import (
	"context"
	"errors"
	"strings"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	entcontainment "openxdr/server/ent/containment"
)

var ErrRetired = errors.New("主机已下线")
var ErrNotRetired = errors.New("主机没有下线")
var ErrNoReason = errors.New("请填写下线原因")

// Retire 下线主机。reason 必填：下线是不可见的变化，事后要能说清为什么
func Retire(ctx context.Context, db *ent.Client, a *ent.Asset, actor, reason string, now time.Time) (*ent.Asset, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, ErrNoReason
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	n, err := tx.Asset.Update().Where(asset.IDEQ(a.ID), asset.RetiredAtIsNil()).
		SetRetiredAt(now).SetRetiredBy(actor).SetRetiredReason(reason).
		ClearAgentID().ClearSilentSince().ClearHealthProblem().ClearSensorProblem().
		Save(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrRetired
	}
	why := "主机已下线（" + actor + "：" + reason + "）"
	open, err := tx.Containment.Query().Where(entcontainment.AssetIDEQ(a.ID),
		entcontainment.StateIn(entcontainment.StateProposed, entcontainment.StatePending, entcontainment.StateActive)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range open {
		upd := tx.Containment.UpdateOne(c).SetEndedAt(now).ClearExpiresAt().SetReason(c.Reason + "；" + why)
		if c.State == entcontainment.StateProposed {
			upd.SetState(entcontainment.StateDeclined).SetDecidedBy(actor)
		} else {
			// 主机已不在，解除指令送不到；记为解除，到期不再重试
			upd.SetState(entcontainment.StateLifted).SetLiftedBy(actor)
		}
		if err := upd.Exec(ctx); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return db.Asset.Get(ctx, a.ID)
}

// Restore 取消下线。agent 下次注册时拿新的 agent_id
func Restore(ctx context.Context, db *ent.Client, a *ent.Asset) (*ent.Asset, error) {
	n, err := db.Asset.Update().Where(asset.IDEQ(a.ID), asset.RetiredAtNotNil()).
		ClearRetiredAt().ClearRetiredBy().ClearRetiredReason().Save(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotRetired
	}
	return db.Asset.Get(ctx, a.ID)
}
