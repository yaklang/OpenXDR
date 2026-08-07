package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// AuditLog 操作审计。谁在什么时候对什么做了什么——安全产品自己必须经得起追问。
// 只增不改；全是人手操作，量级极小，不设自动清理。
type AuditLog struct {
	ent.Schema
}

func (AuditLog) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("ts").Default(time.Now),
		field.String("username"),
		field.String("action"),
		// 操作对象：incident/user/suppression 的 id 或名字，无对象则空
		field.String("target").Optional().Nillable(),
		field.String("detail").Optional().Nillable(),
		field.String("remote_addr"),
	}
}

func (AuditLog) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("ts"),
	}
}
