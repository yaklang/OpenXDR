package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// ChangeSource 外部变更记录源（首类为 GitHub 仓库提交）。
// 只读访问令牌使用 HOST_CREDENTIAL_KEY 绑定记录 ID 加密存储；单活任务按 since_cursor 增量拉取。
type ChangeSource struct {
	ent.Schema
}

func (ChangeSource) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.String("provider").Default("github"),
		field.String("name").Default(""),
		// GitHub owner/repo
		field.String("repo").NotEmpty(),
		// 空表示仓库默认分支
		field.String("branch").Default(""),
		// HOST_CREDENTIAL_KEY 加密后的只读令牌密文，绝不明文落库或经接口返回
		field.Bytes("secret").Optional().Sensitive(),
		field.String("token_hint").Default(""),
		field.Bool("enabled").Default(true),
		field.Time("since_cursor").Optional().Nillable(),
		field.Time("last_synced_at").Optional().Nillable(),
		field.Time("last_attempted_at").Optional().Nillable(),
		field.String("last_error").Default(""),
		field.String("created_by").Default(""),
	}
}

func (ChangeSource) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("provider", "repo").Unique(),
		index.Fields("enabled"),
	}
}

// ChangeRecord 从外部代码/配置仓库增量拉取的变更记录。
// 只存提交元数据、标题正文与改动文件路径，绝不存文件内容与 diff；
// 仅作研判与结案审计的时间线佐证，不是权威事实。
type ChangeRecord struct {
	ent.Schema
}

func (ChangeRecord) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("source_id", uuid.UUID{}),
		field.String("repo").NotEmpty(),
		field.String("sha").NotEmpty(),
		field.Time("committed_at"),
		field.String("author").Default(""),
		field.String("title").Default(""),
		field.Text("body").Default(""),
		field.JSON("files", []string{}).Optional(),
		field.Int("file_count").Default(0),
		field.Time("created_at").Default(time.Now),
	}
}

func (ChangeRecord) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("source_id", "sha").Unique(),
		index.Fields("committed_at"),
	}
}

// ChangeRecordAsset 变更记录与纳管资产的确定性关联索引表。
// 按 (asset_id, committed_at) 建联合索引，供研判、结案审计与资产详情按时间窗直接走索引查询。
type ChangeRecordAsset struct {
	ent.Schema
}

func (ChangeRecordAsset) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("change_record_id", uuid.UUID{}),
		field.UUID("asset_id", uuid.UUID{}),
		field.Time("committed_at"),
		// 命中的确定性线索（如 host:gateway、ip:10.0.0.100、vmid:100、lxc:gateway）
		field.JSON("clues", []string{}).Optional(),
	}
}

func (ChangeRecordAsset) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("change_record_id", "asset_id").Unique(),
		index.Fields("asset_id", "committed_at"),
	}
}
