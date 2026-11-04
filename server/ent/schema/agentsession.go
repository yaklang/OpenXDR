package schema

import (
	"encoding/json"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// AgentSession 一次 Pi 会话：一段对话，或一次定时任务运行。会话绑定一个组，
// 只能触达组内资产；发起人决定权限（定时任务为 system）。
type AgentSession struct {
	ent.Schema
}

func (AgentSession) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		// chat 对话 / task 定时任务
		field.String("kind"),
		field.UUID("group_id", uuid.UUID{}),
		// 发起人用户名；定时任务为 system
		field.String("initiator"),
		field.String("model"),
		field.String("title").Optional().Nillable(),
		// running / idle（对话等待下一轮）/ succeeded / failed
		field.String("status").Default("running"),
		field.Text("error").Optional().Nillable(),
		field.Time("finished_at").Optional().Nillable(),
		// 对话执行期限；定时任务为短租约，过期后按可信副作用标记决定能否安全重跑。
		field.Time("run_expires_at").Optional().Nillable(),
		// 定时任务的执行所有者与硬期限；短租约只在所有者仍有效时续期。
		field.UUID("run_owner", uuid.UUID{}).Optional().Nillable(),
		field.Time("run_deadline_at").Optional().Nillable(),
		// 只由执行入口置真，任何可能产生副作用的工具调用前置假；旧记录默认不允许重跑。
		field.Bool("run_replay_safe").Default(false),
		// 从事件或待办「交给 AI」时绑定的对象：incident:<id> / finding:<id>，同组、最多 10 个
		field.Strings("subjects").Optional(),
		// 人在界面上点了停止：后台运行在哪个节点都靠轮询这个字段收手，前端断开不再影响运行
		field.Time("cancel_requested_at").Optional().Nillable(),
	}
}

func (AgentSession) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id", "created_at"),
		index.Fields("initiator"),
		index.Fields("status", "run_expires_at"),
	}
}

// SessionMessage 会话消息。content 原样存 Pi 的消息对象（含工具调用与结果），
// 下一轮原样喂回，历史不做有损转换。
type SessionMessage struct {
	ent.Schema
}

func (SessionMessage) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.UUID("session_id", uuid.UUID{}),
		field.Int("seq"),
		// user / assistant / toolResult，冗余出来便于前端过滤
		field.String("role"),
		field.JSON("content", json.RawMessage{}),
	}
}

func (SessionMessage) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("session_id", "seq").Unique(),
	}
}
