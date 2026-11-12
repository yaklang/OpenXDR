package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// StandingRuleRun 常设规矩的命中与执行记录：保存当时的档位、封闭命令、回执结果与明确回退方式。
type StandingRuleRun struct {
	ent.Schema
}

func (StandingRuleRun) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.UUID("rule_id", uuid.UUID{}),
		field.UUID("group_id", uuid.UUID{}),
		field.UUID("asset_id", uuid.UUID{}),
		field.UUID("finding_id", uuid.UUID{}).Optional().Nillable(),
		field.Time("finding_first_seen").Optional().Nillable(),
		field.String("tier"),
		field.Enum("status").Values(
			"succeeded",
			"failed",
			"pending_approval",
			"rejected",
			"expired",
			"queued_human",
			"skipped",
		).Default("pending_approval"),
		field.Text("hit_summary"),
		field.Text("command").Default(""),
		field.UUID("command_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("approval_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("reservation_id", uuid.UUID{}).Optional().Nillable(),
		field.Text("result").Default(""),
		field.Text("rollback").Default(""),
		field.Time("completed_at").Optional().Nillable(),
	}
}

func (StandingRuleRun) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("rule_id", "created_at"),
		index.Fields("status"),
		index.Fields("finding_id", "rule_id"),
		index.Fields("asset_id", "created_at"),
	}
}
