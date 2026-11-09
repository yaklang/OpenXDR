package containment

import (
	"time"

	"context"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
)

// edgeActions 封锁公网地址时，在边界网关（EdgeHosts，公网流量的入口）上一并封锁：
// 攻击来源在入口挡住，网关后面所有对外服务一起受保护。内网地址不上边界，原动作不该执行的边界也不执行
func (e *Engine) edgeActions(ctx context.Context, a action) ([]action, error) {
	if a.kind != "block_network" || a.role == "edge" || len(e.EdgeHosts) == 0 || !public(a.target) {
		return nil, nil
	}
	hosts, err := e.DB.Asset.Query().
		Where(entasset.HostnameIn(e.EdgeHosts...), entasset.AgentIDNotNil(), entasset.RetiredAtIsNil()).
		All(ctx)
	if err != nil {
		return nil, err
	}
	var out []action
	for _, h := range hosts {
		if h.ID == a.asset.ID {
			continue
		}
		out = append(out, action{asset: h, kind: "block_network", target: a.target, role: "edge", skip: a.skip, alert: a.alert,
			why: a.why + "；在边界网关 " + h.Hostname + " 一并封锁"})
	}
	return out, nil
}

// decideWithEdge 执行一个动作，是公网封锁就连同边界一起
func (e *Engine) decideWithEdge(ctx context.Context, al *ent.Alert, source *ent.Asset, a action, last time.Time) error {
	if err := e.decide(ctx, al, source, a, last); err != nil {
		return err
	}
	edge, err := e.edgeActions(ctx, a)
	if err != nil {
		return err
	}
	for _, ea := range edge {
		if err := e.decide(ctx, al, source, ea, last); err != nil {
			return err
		}
	}
	return nil
}
