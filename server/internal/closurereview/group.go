package closurereview

import (
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"openxdr/server/ent"
)

// alertGroup 同规则、同主机、原文去掉易变字段后完全相同的一组告警：只把代表事件交审计员，结论适用于整组
type alertGroup struct {
	EventID uuid.UUID `json:"event_id"`
	RuleID  string    `json:"rule_id"`
	Alerts  int       `json:"alerts"`
}

// volatileKey 每次执行都会变、不影响行为判断的字段：进程号、对象唯一标识、源端口与时间
func volatileKey(k string) bool {
	switch k {
	case "pid", "ppid", "tid", "uid", "src_port", "ts":
		return true
	}
	return strings.HasSuffix(k, "guid") || strings.HasSuffix(k, "time") || strings.HasSuffix(k, "_ts")
}

func stripVolatile(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if volatileKey(k) {
				delete(t, k)
				continue
			}
			t[k] = stripVolatile(x)
		}
	case []any:
		for i, x := range t {
			t[i] = stripVolatile(x)
		}
	}
	return v
}

// rawSignature 原文去掉易变字段后的规范化 JSON（键有序）；没有原文或解析不了的告警自成一组
func rawSignature(a *ent.Alert) string {
	var v any
	if a.Edges.Event == nil || json.Unmarshal(a.Edges.Event.Raw, &v) != nil {
		return "alert:" + a.ID.String()
	}
	b, _ := json.Marshal(stripVolatile(v))
	return string(b)
}

// groupAlerts 按首次出现的顺序分组，组里第一条告警是代表
func groupAlerts(alerts []*ent.Alert) ([]*ent.Alert, []alertGroup) {
	var reps []*ent.Alert
	var groups []alertGroup
	index := map[string]int{}
	for _, a := range alerts {
		key := a.RuleID + "\x00" + a.AssetID.String() + "\x00" + rawSignature(a)
		if i, ok := index[key]; ok {
			groups[i].Alerts++
			continue
		}
		index[key] = len(reps)
		reps = append(reps, a)
		g := alertGroup{RuleID: a.RuleID, Alerts: 1}
		if a.EventID != nil {
			g.EventID = *a.EventID
		}
		groups = append(groups, g)
	}
	return reps, groups
}
