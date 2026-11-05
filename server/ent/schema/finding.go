package schema

import (
	"encoding/json"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Finding 运维待办：巡检发现的问题，按（组、主机、key）去重。
// AI 登记与复查（open ↔ resolved），人可以标记已处理或忽略；忽略的 AI 不再登记。
type Finding struct{ ent.Schema }

func (Finding) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("group_id", uuid.UUID{}),
		field.UUID("asset_id", uuid.UUID{}),
		// 模型给的稳定标识，如 backup-service-failed；同一主机同一问题每轮用同一个
		field.String("key").MaxLen(64),
		field.String("title").MaxLen(200),
		field.Text("detail").Default(""),
		// low / medium / high；包括由平台持续跟进的问题
		field.String("severity").Default("low"),
		// open / resolved / ignored
		field.String("status").Default("open"),
		// 归属不代表已执行；只有 work_session_id 与有效租约同时存在才正在跟进。
		field.String("work_owner").Default("ai"),
		field.Time("work_next_check_at").Optional().Nillable(),
		field.Int("work_attempts").Default(0),
		field.UUID("work_session_id", uuid.UUID{}).Optional().Nillable(),
		field.Time("work_lease_until").Optional().Nillable(),
		// 服务端保存计划、阻塞依据、回执与唤醒条件；不作为人工判断回喂。
		field.JSON("work", json.RawMessage{}).Optional(),
		field.Time("first_seen").Default(time.Now),
		field.Time("last_seen").Default(time.Now),
		// 最近一次登记或复查它的会话
		field.UUID("session_id", uuid.UUID{}).Optional().Nillable(),
		field.Time("resolved_at").Optional().Nillable(),
		// 用户名，或 AI 复查确认修复时为 system
		field.String("resolved_by").Optional().Nillable(),
		field.Text("note").Optional().Nillable(),
	}
}

func (Finding) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id", "asset_id", "key").Unique(),
		index.Fields("group_id", "status"),
		index.Fields("work_owner", "status", "work_next_check_at"),
	}
}
