package schema

import (
	"encoding/json"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Event 归一化事件：三路数据（EDR / NTA / 日志）统一进这张表，OCSF 风格。
type Event struct {
	ent.Schema
}

func (Event) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("ts"),
		field.Int("class_uid"),
		field.String("source"),
		field.UUID("asset_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("process_guid", uuid.UUID{}).Optional().Nillable(),
		field.String("username").Optional().Nillable(),
		field.String("conn_tuple").Optional().Nillable(),
		field.JSON("raw", json.RawMessage{}),
	}
}

func (Event) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("asset", Asset.Type).Ref("events").Field("asset_id").Unique(),
		edge.To("alerts", Alert.Type),
	}
}

func (Event) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("ts"),
		index.Fields("asset_id", "ts"),
		index.Fields("process_guid"),
	}
}
