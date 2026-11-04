package containment

import (
	"context"
	"encoding/json"

	"openxdr/server/ent"
	"openxdr/server/ent/zone"
	"openxdr/server/internal/assetmap"
)

// 处置等级，与 zones.response_tier / assets.response_tier 的取值一致
const (
	TierLab        = "lab"
	TierProduction = "production"
	TierCore       = "core"
)

func tierName(t string) string {
	return map[string]string{TierLab: "实验等级", TierProduction: "生产等级", TierCore: "核心等级"}[t]
}

// tier 资产的处置等级与依据：跑着 OpenXDR server 的一律核心 > 资产单独指定 > 所在区域 > 默认生产。
// 监听清单是 agent 报的，失陷主机能把自己伪造成核心；核心只让它自己免于隔离，受害方照样封锁它
func (e *Engine) tier(ctx context.Context, a *ent.Asset) (string, string, error) {
	if runsServer(a.Listening) {
		return TierCore, "运行 OpenXDR server", nil
	}
	if a.ResponseTier != nil {
		return string(*a.ResponseTier), "资产指定", nil
	}
	if a.GroupID == nil {
		return TierProduction, "默认", nil
	}
	zones, err := e.DB.Zone.Query().Where(zone.GroupIDEQ(*a.GroupID)).All(ctx)
	if err != nil {
		return "", "", err
	}
	if z, _ := assetmap.ZoneOf(a, zones); z.ID != nil {
		for _, row := range zones {
			if row.ID == *z.ID {
				return string(row.ResponseTier), "区域 " + row.Name, nil
			}
		}
	}
	return TierProduction, "默认", nil
}

func runsServer(listening json.RawMessage) bool {
	var ports []struct {
		Process string `json:"process"`
	}
	if json.Unmarshal(listening, &ports) != nil {
		return false
	}
	for _, p := range ports {
		if p.Process == "openxdr-server" {
			return true
		}
	}
	return false
}
