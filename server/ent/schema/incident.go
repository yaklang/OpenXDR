package schema

import (
	"encoding/json"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// Incident 事件：关联引擎聚合出的攻击故事，AI 研判的对象。
// 状态机：open → triaged →（新证据）→ open → triaged；closed / false_positive 是分析师终态。
type Incident struct {
	ent.Schema
}

func (Incident) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.String("status").Default("open"),
		field.JSON("graph", json.RawMessage{}),
		field.JSON("ai_verdict", json.RawMessage{}).Optional(),
		field.String("title").Optional().Nillable(),
	}
}

func (Incident) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("alerts", Alert.Type),
	}
}
