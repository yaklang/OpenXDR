package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Fact 自治总控的权威事实：研判、巡检与结案审计可以当前提引用的结论（这把钥匙是谁的、这个来源地址归谁、
// 这台主机做什么用、管理员定过什么、哪次变更授权过）。
//
// 只收权威来源：管理员录入（human）、平台自己的记录（platform）、部署流水线（pipeline）。
// 日志、事件与模型输出永远不能变成事实；AI 写的环境知识留在长期记忆里。
type Fact struct {
	ent.Schema
}

func (Fact) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		// key 公钥指纹 / channel 来源地址或网段 / asset_role 资产角色 / decision 管理员决定 / change 已授权变更
		field.String("kind"),
		// key 为 SHA256:… 指纹，channel 为地址或 CIDR，decision 为主题；asset_role 与 change 用 asset_id
		field.String("subject").Default(""),
		// 空表示全局（只有管理员能建）
		field.UUID("group_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("asset_id", uuid.UUID{}).Optional().Nillable(),
		// 归属：key 与 channel 的持有人（user:<用户名> 或 integration:<集成 ID>），意图登记按它核对
		field.String("holder").Default(""),
		field.Text("content"),
		field.String("source").Default("human"),
		field.String("created_by"),
		field.Time("expires_at").Optional().Nillable(),
		// 停用只是隐藏：引用过它的研判还要说得清依据
		field.Time("retired_at").Optional().Nillable(),
		field.String("retired_by").Optional().Nillable(),
		field.Int("cited_count").Default(0),
		field.Time("last_cited_at").Optional().Nillable(),
	}
}

func (Fact) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("kind", "subject"),
		index.Fields("asset_id"),
	}
}
