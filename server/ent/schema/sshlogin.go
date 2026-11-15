package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// SSHLogin agent 核对过出处的 SSH 成功登录（带 login_session 的 3002 事件）的精简副本，
// 供运维自动化的自动识别统计登录规律。按事件 ID 去重，只留统计窗口内的。
// 直接按天扫 events 要过上千万行，这里每轮只增量扫新到的事件
type SSHLogin struct {
	ent.Schema
}

func (SSHLogin) Fields() []ent.Field {
	return []ent.Field{
		// 即事件 ID
		field.UUID("id", uuid.UUID{}),
		field.Time("ts"),
		field.UUID("group_id", uuid.UUID{}),
		field.UUID("asset_id", uuid.UUID{}),
		field.String("login_user"),
		field.String("src_ip"),
		field.String("auth_method"),
		field.String("key_fp").Optional().Nillable(),
		field.String("key_type").Optional().Nillable(),
		field.Time("recorded_at").Default(time.Now),
	}
}

func (SSHLogin) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id", "ts"),
		index.Fields("asset_id", "ts"),
		index.Fields("ts"),
	}
}
