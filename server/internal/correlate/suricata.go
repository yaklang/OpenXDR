package correlate

import (
	"encoding/json"
	"strings"

	"openxdr/server/ent"
)

// 无法归属的外部告警按可信来源和连接隔离，不进入全局 unknown 桶。
func externalScope(al *ent.Alert) string {
	if al.AssetID != nil || al.Edges.Event == nil || al.Edges.Event.Source != "suricata" {
		return ""
	}
	var raw struct {
		Metadata struct {
			Scope string `json:"suricata_scope"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(al.Edges.Event.Raw, &raw)
	if raw.Metadata.Scope == "" {
		return al.ID.String()
	}
	return raw.Metadata.Scope
}

func (e *Engine) alertTitle(al *ent.Alert) string {
	if strings.HasPrefix(al.RuleID, "suricata:") && al.Detail != nil {
		return *al.Detail
	}
	return e.ruleTitle(al.RuleID)
}
