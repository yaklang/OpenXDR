package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// SSHKeyBaseline 记录资产的 SSH 钥匙盘点基线与 sshd 级动态配置。
// 首次上报只建立基线，不把存量钥匙当作新出现的后门告警；基线之后新出现的钥匙才触发告警与移除提议。
type SSHKeyBaseline struct {
	ent.Schema
}

func (SSHKeyBaseline) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("asset_id", uuid.UUID{}).Unique(),
		field.Time("first_reported_at").Default(time.Now),
		field.Time("last_reported_at").Default(time.Now),
		// sshd -T 解析出的 AuthorizedKeysCommand 配置（仅记录文本作提示，agent 不执行）
		field.String("authorized_keys_command").Default(""),
		field.String("authorized_keys_command_user").Default(""),
	}
}

// SSHKeyObservation 资产上观测到的 SSH 授权钥匙（观测不是事实，归属须管理员确认后写入 Fact）。
type SSHKeyObservation struct {
	ent.Schema
}

func (SSHKeyObservation) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.UUID("asset_id", uuid.UUID{}),
		field.String("account"),
		field.String("file_path"),
		field.String("key_type"),
		field.String("fingerprint"),
		// 公钥尾部注释（攻击者可控，仅作提示，绝不作为归属依据）
		field.String("comment").Default(""),
		field.JSON("options", []string{}).Optional(),
		// 当前仍在授权文件中为 true，文件移除该行后置 false
		field.Bool("present").Default(true),
		field.Time("first_seen").Default(time.Now),
		field.Time("last_seen").Default(time.Now),
		// 新出现时关联到的写入登录会话（能从同机近期事件对上时记录）
		field.String("added_by_user").Default(""),
		field.String("added_by_ip").Default(""),
		field.String("added_by_key_fp").Default(""),
		// 与 SSH 成功公钥登录记录交叉比对出的最近登录时间与来源地址
		field.Time("last_login_at").Optional().Nillable(),
		field.String("last_login_ip").Default(""),
		// 新出现或人工发起的移除提议审批单 ID（走现有 commandgate 审批，从不自动删除）
		field.UUID("removal_approval_id", uuid.UUID{}).Optional().Nillable(),
	}
}

func (SSHKeyObservation) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("asset_id", "account", "file_path", "fingerprint").Unique(),
		index.Fields("asset_id", "present"),
		index.Fields("fingerprint"),
	}
}
