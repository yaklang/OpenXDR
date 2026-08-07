package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Session 登录会话。库里只存 token 的 SHA-256——库被拖走也拼不回可用凭证。
// 不透明 token 换来的是随时可吊销：删行即失效，没有 JWT 的黑名单问题。
type Session struct {
	ent.Schema
}

func (Session) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.String("token_hash").Unique(),
		field.UUID("user_id", uuid.UUID{}),
		field.Time("expires_at"),
	}
}

func (Session) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id"),
	}
}
