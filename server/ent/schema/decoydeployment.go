package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
	"time"
)

// DecoyDeployment 登记多种诱饵载体；状态不代表远程进程是否存活。
// 授权随资产当前归组，避免资产迁组后原组仍能读取或修改记录。
type DecoyDeployment struct{ ent.Schema }

func (DecoyDeployment) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("asset_id", uuid.UUID{}).Immutable(),
		field.String("profile").Immutable(),
		field.String("template").Immutable(),
		field.Int("port").Min(0).Max(65535).Immutable(),
		field.Enum("status").Values("registered", "revoked").Default("registered"),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.String("created_by").Immutable(),
		field.Time("revoked_at").Optional().Nillable(),
		field.String("revoked_by").Optional().Nillable(),
		field.Enum("kind").Values("ssh", "http", "file", "shell").Default("ssh").Immutable(),
		field.String("resource").Default("").Immutable(),
		field.String("marker").Optional().Sensitive(),
		field.String("token_hash").Optional().Sensitive(),
		field.UUID("token_group_id", uuid.UUID{}).Optional().Nillable(),
		field.Time("token_expires_at").Optional().Nillable(),
		field.UUID("runtime_instance_id", uuid.UUID{}).Optional().Nillable(),
		field.Time("runtime_seen_at").Optional().Nillable(),
		field.Int("runtime_pending").Min(0).Max(10000).Optional().Nillable(),
		field.String("runtime_error").Default(""),
		field.Enum("runtime_state").Values("unknown", "starting", "running", "stopped", "failed").Default("unknown"),
		field.String("runtime_generation").Optional().Sensitive(),
		field.Enum("install_state").Values("idle", "installing", "installed", "unconfirmed").Default("idle"),
		field.Time("install_started_at").Optional().Nillable(),
		field.UUID("active_revision_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("token_revision_id", uuid.UUID{}).Optional().Nillable(),
		field.Bool("stop_requested").Default(false),
	}
}
func (DecoyDeployment) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("asset_id", "port").Unique().Annotations(entsql.IndexWhere("status = 'registered' AND port > 0")),
		index.Fields("asset_id", "created_at"),
		index.Fields("asset_id", "kind", "resource").Unique().Annotations(entsql.IndexWhere("status = 'registered' AND kind IN ('file', 'shell')")),
	}
}

// DecoyObservation 保存经布放令牌认证的有限事实，不将标记命中直接定性为攻击。
type DecoyObservation struct{ ent.Schema }

func (DecoyObservation) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}),
		field.UUID("deployment_id", uuid.UUID{}).Immutable(),
		field.UUID("incident_id", uuid.UUID{}).Optional().Nillable(),
		field.String("kind").Immutable(),
		field.String("generation").Default("").Immutable().Sensitive(),
		field.Time("received_at").Default(time.Now).Immutable(),
		field.UUID("revision_id", uuid.UUID{}).Optional().Nillable().Immutable(),
		field.String("session_id").Default("").Immutable(),
		field.String("trigger_key").Default("").Immutable(),
		field.String("payload_hash").Default("").Immutable().Sensitive(),
		field.Time("occurred_at").Optional().Nillable().Immutable(),
		field.JSON("details", map[string]any{}).Optional().Immutable(),
	}
}
func (DecoyObservation) Indexes() []ent.Index {
	return []ent.Index{index.Fields("received_at"), index.Fields("deployment_id", "received_at"), index.Fields("deployment_id", "generation").Unique().Annotations(entsql.IndexWhere("kind = 'marker_used'")), index.Fields("deployment_id", "trigger_key").Unique().Annotations(entsql.IndexWhere("trigger_key <> ''")), index.Fields("deployment_id", "session_id")}
}

// DecoyRevision 保存不可变引擎配置；切换修订不覆盖历史证据。
type DecoyRevision struct{ ent.Schema }

func (DecoyRevision) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("deployment_id", uuid.UUID{}).Immutable(),
		field.Int("number").Positive().Immutable(),
		field.UUID("release_id", uuid.UUID{}).Immutable(),
		field.JSON("spec", map[string]any{}).Immutable(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.String("created_by").Immutable(),
	}
}
func (DecoyRevision) Indexes() []ent.Index {
	return []ent.Index{index.Fields("deployment_id", "number").Unique()}
}

// DecoyEngineRelease 只登记已准入的产物身份，不接收远程脚本或任意下载地址。
type DecoyEngineRelease struct{ ent.Schema }

func (DecoyEngineRelease) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.String("engine").Immutable(),
		field.String("version").Immutable(),
		field.String("digest").Immutable(),
		field.Int("protocol").Immutable(),
		field.String("state_schema").Immutable(),
		field.Bool("enabled").Default(true),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.String("created_by").Immutable(),
	}
}
func (DecoyEngineRelease) Indexes() []ent.Index {
	return []ent.Index{index.Fields("engine", "version", "digest").Unique()}
}
