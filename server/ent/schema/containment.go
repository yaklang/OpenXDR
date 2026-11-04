package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Containment 自主响应的一次处置决定。执行了的是租约：证据持续就续期，到期自动下发解除；
// 没执行的（被熔断挡住、超出自动处置范围、目标受保护、下发失败）也留一条，决策记录就是这张表。
type Containment struct{ ent.Schema }

func (Containment) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		// 执行处置的资产与它所在的组（组可见性按它判断）
		field.UUID("asset_id", uuid.UUID{}),
		field.UUID("group_id", uuid.UUID{}).Optional().Nillable(),
		// isolate_host / block_network；target 是封锁的地址
		field.String("kind"),
		field.String("target").Optional(),
		// 结束进程用：target 是进程 GUID，这里是 PID（agent 两个都核对）
		field.Uint32("pid").Default(0),
		// 资产 + 动作 + 目标：同一个键同时只有一条 active，新证据续期它而不是重复下发
		field.String("key"),
		// 触发信号（规则 ID）与告警；来源主机是发起攻击的纳管主机（外部来源时为空）。
		// role 说明这条处置落在哪一方：source 来源 / victim 受害方 / host 失陷主机自身（情报命中）
		field.String("signal"),
		field.UUID("alert_id", uuid.UUID{}),
		field.UUID("incident_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("source_asset_id", uuid.UUID{}).Optional().Nillable(),
		field.Enum("role").Values("source", "victim", "host"),
		// active 生效中（封锁、隔离主机这类可逆处置的租约）/ expired 到期已解除 / executed 一次性处置已下发
		// （结束进程、隔离文件、锁定账号：自动恢复比不恢复更危险，只能人工恢复）/ lifted 人工解除或恢复 /
		// held 熔断挡下 / skipped 不该自动处置 / failed 下发失败
		field.Enum("state").Values("active", "expired", "executed", "lifted", "held", "skipped", "failed"),
		field.Text("reason"),
		field.UUID("command_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("lift_command_id", uuid.UUID{}).Optional().Nillable(),
		field.Time("expires_at").Optional().Nillable(),
		// 租约到期、人工解除的时间；人工解除的，这之前的证据不再触发同一处置
		field.Time("ended_at").Optional().Nillable(),
		field.String("lifted_by").Optional().Nillable(),
	}
}

func (Containment) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("key", "state"),
		index.Fields("state", "expires_at"),
		index.Fields("alert_id"),
		index.Fields("created_at"),
	}
}
