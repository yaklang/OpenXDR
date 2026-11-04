package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Zone 组管理员定义的网络区域：网段命中即归入，也可以手工把资产指派进来。
// 未定义区域时资产按 IP 与云环境自动划成内网 / 公网 / 云。
type Zone struct{ ent.Schema }

func (Zone) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("group_id", uuid.UUID{}),
		field.String("name").MaxLen(64),
		// internal 内网 / dmz 隔离区 / external 公网 / cloud 云上
		field.Enum("kind").Values("internal", "dmz", "external", "cloud"),
		field.Strings("cidrs").Optional(),
		// 自主响应的处置等级：lab 实验（可以直接隔离）/ production 生产（不隔离整机）/ core 核心（只封锁来源）。
		// 为空不指定，区域内的资产按 AI 定级
		field.Enum("response_tier").Values("lab", "production", "core").Optional().Nillable(),
		field.Time("created_at").Default(time.Now),
	}
}

func (Zone) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id", "name").Unique(),
	}
}
