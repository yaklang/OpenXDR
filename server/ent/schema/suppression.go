package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Suppression 误报抑制规则。分析师判定某条检测规则在某台主机（或全局）上
// 是噪声后，后续命中不再产生告警。
//
// 抑制永远不是静默的：命中次数持续累加，界面上看得见被压掉了多少，
// 避免一条抑制规则悄悄把真实攻击也吃掉。
type Suppression struct {
	ent.Schema
}

func (Suppression) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.String("rule_id"),
		// 为空表示对所有资产生效
		field.UUID("asset_id", uuid.UUID{}).Optional().Nillable(),
		field.String("reason").Optional().Nillable(),
		field.String("created_by").Default("api"),
		// 为空表示长期有效；到期后自动失效，避免抑制规则无限积累
		field.Time("expires_at").Optional().Nillable(),
		field.Int("matched_count").Default(0),
		field.Time("last_matched_at").Optional().Nillable(),
	}
}

func (Suppression) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("rule_id"),
	}
}
