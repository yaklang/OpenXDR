package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// User 分析师账号。角色三档：admin 管用户与一切，analyst 研判与处置，viewer 只读。
type User struct {
	ent.Schema
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.String("username").Unique(),
		// bcrypt 哈希，绝不落明文
		field.String("password_hash").Sensitive(),
		field.String("role"),
	}
}
