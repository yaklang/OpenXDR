package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Intel 威胁情报 IOC：恶意 IP / 域名 / 文件哈希。
// 事件入库时与之碰撞，命中即产生告警。与抑制规则同一套设计哲学：
// 命中计数持续累加，界面上看得见每条情报到底撞上了多少事件。
type Intel struct {
	ent.Schema
}

func (Intel) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.Enum("kind").Values("ip", "domain", "hash"),
		field.String("value"),
		field.String("source").Default("manual"),
		field.Int16("severity").Default(4),
		field.String("note").Optional().Nillable(),
		// 为空表示长期有效；情报会过时，到期自动失效避免陈年 IOC 制造误报
		field.Time("expires_at").Optional().Nillable(),
		field.Int("matched_count").Default(0),
		field.Time("last_matched_at").Optional().Nillable(),
	}
}

func (Intel) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("kind", "value").Unique(),
	}
}
