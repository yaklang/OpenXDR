package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Alert 告警：规则引擎命中产物。去重窗口内 count 累加，ts 是首次、last_ts 是最近。
type Alert struct {
	ent.Schema
}

func (Alert) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("ts"),
		field.String("rule_id"),
		field.Int16("severity"),
		field.UUID("event_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("asset_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("incident_id", uuid.UUID{}).Optional().Nillable(),
		field.Int("count").Default(1),
		field.Time("last_ts").Optional().Nillable(),
		// 平台下发的指令（人工或 AI exec）拉起的进程触发的告警：照常留痕、挂在指令上，不进事件关联与研判
		field.UUID("command_id", uuid.UUID{}).Optional().Nillable(),
		// 登记的可信自动化来源（见 TrustedSource）的登录会话触发的告警：照常留痕、挂在来源上，不进事件关联与研判
		field.UUID("automation_id", uuid.UUID{}).Optional().Nillable(),
		// 来自可信来源或容器健康检查、但规则属于高危例外（见 internal/automation.Watch）：仍进关联与研判
		field.Bool("automation_watch").Default(false),
		// 事件是 agent 认出的 docker 容器健康检查（HEALTHCHECK）进程或其后代：照常留痕，不进事件关联与研判；
		// 高危例外记在 automation_watch 上，仍进关联与研判
		field.Bool("healthcheck").Default(false),
		// 合成检测的依据（如心跳的间隔统计），一行人读的话；研判上下文与事件页一并展示。规则命中为空
		field.Text("detail").Optional().Nillable(),
	}
}

func (Alert) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("event", Event.Type).Ref("alerts").Field("event_id").Unique(),
		edge.From("asset", Asset.Type).Ref("alerts").Field("asset_id").Unique(),
		edge.From("incident", Incident.Type).Ref("alerts").Field("incident_id").Unique(),
	}
}

func (Alert) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("incident_id"),
		index.Fields("asset_id", "ts"),
		index.Fields("command_id"),
		index.Fields("automation_id"),
	}
}
