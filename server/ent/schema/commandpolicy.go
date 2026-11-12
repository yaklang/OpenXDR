package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"time"
)

// CommandPolicy 的 pattern 按完整命令字符串匹配，不解释 shell 语义。
type CommandPolicy struct{ ent.Schema }

func (CommandPolicy) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.UUID("group_id", uuid.UUID{}),
		field.Enum("origin").Values("ai", "human"),
		field.Enum("mode").Values("allow", "deny"),
		field.String("pattern").NotEmpty(),
	}
}
func (CommandPolicy) Indexes() []ent.Index { return []ent.Index{index.Fields("group_id", "origin")} }

type Approval struct{ ent.Schema }

func (Approval) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.UUID("group_id", uuid.UUID{}),
		field.UUID("session_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("asset_id", uuid.UUID{}),
		field.String("requested_by"),
		field.Enum("origin").Values("ai", "human"),
		field.Text("cmd"),
		field.Uint32("timeout_ms"),
		field.Enum("status").Values("pending", "approved", "rejected", "expired", "cancelled", "consumed").Default("pending"),
		field.Time("expires_at"),
		field.String("decided_by").Optional().Nillable(),
		field.Time("decided_at").Optional().Nillable(),
		// 平台生成的异步提议（无阻塞调用方等待），组管理员批准时由 Gate.Decide 当场下发执行
		field.Bool("async").Default(false),
	}
}
func (Approval) Indexes() []ent.Index {
	return []ent.Index{index.Fields("group_id", "status"), index.Fields("expires_at")}
}
