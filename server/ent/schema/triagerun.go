package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"time"
)

// TriageRun 一次研判尝试；失败不会被后续成功覆盖，不存提示词、工具原文或凭据。
type TriageRun struct{ ent.Schema }

func (TriageRun) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("incident_id", uuid.UUID{}),
		field.Time("started_at").Default(time.Now),
		field.Time("ready_at").Optional().Nillable(),
		field.Time("finished_at").Optional().Nillable(),
		field.String("trigger"),
		field.Enum("status").Values("running", "succeeded", "failed", "interrupted").Default("running"),
		field.String("model").Default(""),
		field.String("error_code").Default(""),
		field.Int64("duration_ms").Default(0),
		field.Int64("model_ms").Default(0),
		field.Int64("tool_ms").Default(0),
		field.Int("model_calls").Default(0),
		field.Int("tool_calls").Default(0),
		field.Int("tool_errors").Default(0),
		field.JSON("tool_details", []map[string]any{}).Optional(),
		field.Int("input_tokens").Default(0),
		field.Int("output_tokens").Default(0),
	}
}
func (TriageRun) Indexes() []ent.Index {
	return []ent.Index{index.Fields("incident_id", "started_at"), index.Fields("status", "started_at")}
}
