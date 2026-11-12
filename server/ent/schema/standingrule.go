package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// StandingRule 自治总控的常设规矩：重复出现的已知模式由管理员定死条件、封闭动作模板与三档边界
// （auto 自动做 / propose 提议等人批 / human 只给人工队列）。
// 档位与启停只有平台管理员能改，变更留审计；同一规矩连续出错自动降级为 propose。
type StandingRule struct {
	ent.Schema
}

func (StandingRule) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		// 内置规矩的稳定标识，自定义规矩为空
		field.String("builtin_key").Default(""),
		field.String("name").NotEmpty(),
		field.String("condition_summary").NotEmpty(),
		field.JSON("condition", map[string]any{}).Optional(),
		field.String("action_template").NotEmpty(),
		field.JSON("action_params", map[string]any{}).Optional(),
		field.Enum("tier").Values("auto", "propose", "human").Default("propose"),
		// 空表示全局（内置规矩或跨组规矩），非空限定到指定组
		field.UUID("group_id", uuid.UUID{}).Optional().Nillable(),
		// 空表示作用范围内全部 Linux 主机，非空限定到精确主机列表
		field.JSON("asset_ids", []uuid.UUID{}).Optional(),
		// 维护窗口 HH:MM-HH:MM，空表示不限时段
		field.String("maintenance_window").Default(""),
		// 单资产冷却时间（分钟，60~10080）
		field.Int("cooldown_minutes").Default(360),
		field.String("created_by"),
		field.Bool("enabled").Default(false),
		field.Int("consecutive_failures").Default(0),
		field.Time("degraded_at").Optional().Nillable(),
		field.String("degraded_reason").Default(""),
		field.Time("last_run_at").Optional().Nillable(),
		field.String("last_run_status").Default(""),
	}
}

func (StandingRule) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("builtin_key"),
		index.Fields("enabled", "tier"),
		index.Fields("group_id"),
	}
}
