package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// QuestionEvidence 问题的一条证据引用。Note 可能含攻击者可控的原文（钥匙注释、命令行、审计理由），只在控制台显示，不进群消息
type QuestionEvidence struct {
	At       time.Time  `json:"at"`
	Source   string     `json:"source"` // ask_controller / closure_review / standing_rule / renewal
	Incident *uuid.UUID `json:"incident,omitempty"`
	Finding  *uuid.UUID `json:"finding,omitempty"`
	Session  *uuid.UUID `json:"session,omitempty"`
	// Ref 审计拒绝记录（snapshot=…）、规矩或事实编号
	Ref  string `json:"ref,omitempty"`
	Note string `json:"note,omitempty"`
}

// QuestionAnswer 管理员的结构化作答
type QuestionAnswer struct {
	// grant 授权/续期；deny 不授权/不续期；claim 认领归属；unknown 不认识；rule 改规矩档位；decision 写决定
	Choice  string     `json:"choice"`
	Holder  string     `json:"holder,omitempty"`
	Content string     `json:"content,omitempty"`
	RuleID  *uuid.UUID `json:"ruleId,omitempty"`
	Tier    string     `json:"tier,omitempty"`
	// Scope 域名问题选的范围：空为仅此主机名，否则是「该父域及其全部子域」
	Scope     string     `json:"scope,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// Question 自治总控的待答问题：子 Agent 与结案审计遇到归属、授权、策略、权限类问题，
// 总控确定性查找答不了时进这里，按（类型、主题对象）合并，管理员在控制台作答一次，答案写回事实库或常设规矩。
type Question struct {
	ent.Schema
}

func (Question) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		// owner 归属 / authorization 授权 / policy 策略 / permission 权限
		field.String("kind"),
		// key 公钥指纹 / ip 地址 / asset 资产 / domain 域名 / change 资产上的变更 / rule 常设规矩 / fact 到期续期的事实
		field.String("subject_kind"),
		// 规范化后的对象：指纹、地址、资产 UUID、注册域名、规矩或事实 UUID
		field.String("subject"),
		field.String("status").Default("open"),
		// 证据涉及的组，列表按它裁剪可见范围；作答写回事实时只有一个组就写到该组，否则写全局
		field.JSON("group_ids", []uuid.UUID{}).Optional(),
		field.JSON("incident_ids", []uuid.UUID{}).Optional(),
		field.JSON("finding_ids", []uuid.UUID{}).Optional(),
		field.JSON("evidence", []QuestionEvidence{}).Optional(),
		// 被问到的次数（含合并）
		field.Int("asked_count").Default(1),
		field.String("created_by"),
		field.JSON("answer", &QuestionAnswer{}).Optional(),
		field.String("answered_by").Optional().Nillable(),
		field.Time("answered_at").Optional().Nillable(),
		// 作答写回的事实或规矩
		field.UUID("fact_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("rule_id", uuid.UUID{}).Optional().Nillable(),
	}
}

func (Question) Indexes() []ent.Index {
	return []ent.Index{
		// 同一主题同时只有一条待答：并发提问撞上唯一索引就改为合并
		index.Fields("kind", "subject_kind", "subject").Unique().
			StorageKey("question_open_subject").Annotations(entsql.IndexWhere("status = 'open'")),
		index.Fields("status", "updated_at"),
		index.Fields("subject_kind", "subject"),
	}
}
