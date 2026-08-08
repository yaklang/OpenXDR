package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// ProcessBaseline UEBA 基线：某资产上见过的可执行文件。
// (asset_id, exe_path) 首次入表即"首次出现"，之后同一组合不再触发。
type ProcessBaseline struct {
	ent.Schema
}

func (ProcessBaseline) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("asset_id", uuid.UUID{}),
		field.String("exe_path"),
		field.Time("first_seen"),
	}
}

func (ProcessBaseline) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("asset_id", "exe_path").Unique(),
	}
}
