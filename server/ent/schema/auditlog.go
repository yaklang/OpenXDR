package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// AuditLog 操作审计。谁在什么时候对什么做了什么——安全产品自己必须经得起追问。
// 只增不改（封存时补上 seq / seal 两列除外）；全是人手操作，量级极小，不设自动清理。
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
		// 审计链（internal/auditchain）：封存时按顺序编号，seal 是 HMAC(前一条的 seal + 本条内容)，密钥不在库里。
		// 改或删已封存的记录链就断；刚写入、还没封存的为空
		field.Int64("seq").Optional().Nillable(),
		field.String("seal").Optional().Nillable(),
	}
}

func (AuditLog) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("ts"),
		index.Fields("seq").Unique(),
	}
}
