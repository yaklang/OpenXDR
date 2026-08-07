package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

func newV7() uuid.UUID { return uuid.Must(uuid.NewV7()) }

// Asset 资产：所有事件挂靠的根实体。
type Asset struct {
	ent.Schema
}

func (Asset) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.String("hostname"),
		field.String("os").Optional().Nillable(),
		field.Strings("ip_addrs").Optional(),
		field.UUID("agent_id", uuid.UUID{}).Optional().Nillable().Unique(),
		field.Time("first_seen").Default(time.Now),
		field.Time("last_seen").Default(time.Now),
	}
}

func (Asset) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("events", Event.Type),
		edge.To("alerts", Alert.Type),
		edge.To("commands", Command.Type),
	}
}
