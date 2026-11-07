package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// CustomRule 控制台维护的自定义 Sigma 规则，叠在规则目录之上，各节点周期热加载。
// 主键就是规则原文里的 id，与规则目录里的 id 不能重复。
type CustomRule struct {
	ent.Schema
}

func (CustomRule) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Immutable().NotEmpty(),
		// Sigma YAML 原文
		field.Text("content"),
		field.Bool("enabled").Default(true),
		field.String("created_by"),
		field.String("updated_by"),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}
