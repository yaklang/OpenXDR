package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Suppression 误报抑制规则。分析师判定某条检测规则在某台主机（或全局）上
// 是噪声后，后续命中不再产生告警。
//
// 抑制永远不是静默的：命中次数持续累加，界面上看得见被压掉了多少，
// 避免一条抑制规则悄悄把真实攻击也吃掉。
type Suppression struct {
	ent.Schema
}

func (Suppression) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.String("rule_id"),
		// 为空表示对所有资产生效
		field.UUID("asset_id", uuid.UUID{}).Optional().Nillable(),
		field.String("reason").Optional().Nillable(),
		field.String("created_by").Default("api"),
		// 为空表示长期有效；到期后自动失效，避免抑制规则无限积累
		field.Time("expires_at").Optional().Nillable(),
		field.Int("matched_count").Default(0),
		field.Time("last_matched_at").Optional().Nillable(),
		// active 生效 / disabled 已停用（内置抑制由管理员切停）/ proposed AI 提议、待 AI 审计员或组管理员批准 / rejected 被拒绝。只有 active 进抑制索引
		field.String("status").Default("active"),
		// 内置良性链标识与名称（rules/benign-chains/*.yml，created_by="builtin"）；启动同步时按 builtin_key 幂等更新条件，保留启停与命中计数
		field.String("builtin_key").Optional().Nillable().Unique(),
		field.String("builtin_title").Optional().Nillable(),
		// 字段条件（AND）：只压掉事件体里这些字段对得上的命中，比如只压某个域名、某条命令行。
		// 为空表示整条规则都压——范围大，AI 的提议不允许为空
		field.JSON("conditions", []SuppressCondition{}).Optional(),
		// 提议它的 AI 会话
		field.UUID("session_id", uuid.UUID{}).Optional().Nillable(),
		field.String("reviewed_by").Optional().Nillable(),
		field.Time("reviewed_at").Optional().Nillable(),
		// 误报统计生成的草案带上依据：哪些事件、谁判的、比例。人工与 AI 提议为空
		field.JSON("evidence", &SuppressEvidence{}).Optional(),
	}
}

// SuppressEvidence 误报统计草案的依据
type SuppressEvidence struct {
	// rule 整条规则（实体分散，没法按实体收窄）/ entity 按实体收窄
	Scope      string `json:"scope"`
	WindowDays int    `json:"windowDays"`
	// 计入的人工误报结论数、属实结论数、仍未结案数；误报率 = 误报 / 三者之和
	FalsePositives int `json:"falsePositives"`
	TruePositives  int `json:"truePositives"`
	Pending        int `json:"pending"`
	RatioPercent   int `json:"ratioPercent"`
	// 不计入的：原样采纳 AI 结案建议的误报、系统自动结案的误报
	AIProposals int `json:"aiProposals"`
	AutoClosed  int `json:"autoClosed"`
	// 计入的误报事件，最多 20 个
	Incidents []EvidenceIncident `json:"incidents"`
	// ai_benign 表示按 AI 研判良性的模式生成（另计 AIBenign 个研判良性的未结案事件），只能由人批准；空为人工误报统计
	Basis    string `json:"basis,omitempty"`
	AIBenign int    `json:"aiBenign,omitempty"`
}

// EvidenceIncident 一个被人判为误报的事件
type EvidenceIncident struct {
	ID         uuid.UUID `json:"id"`
	Title      string    `json:"title,omitempty"`
	ResolvedBy string    `json:"resolvedBy"`
	ResolvedAt time.Time `json:"resolvedAt"`
	// 空为人工写的结论；ai_verdict 人选了误报、采纳 AI 研判的说明；ai_benign 未结案、AI 研判为良性
	Source string `json:"source,omitempty"`
}

// SuppressCondition 一条字段条件：事件体（或 ancestor.* 祖先进程）的 dot path 取值比较。
// 除 regex 按原样正则匹配外，其余字符串比较均不区分大小写。
type SuppressCondition struct {
	Field string `json:"field" yaml:"field"`
	// equals / contains / startswith / endswith / in / not_contains / regex（人工与 AI 提议仅开放 equals/contains/endswith）
	Op     string   `json:"op" yaml:"op"`
	Value  string   `json:"value,omitempty" yaml:"value,omitempty"`
	Values []string `json:"values,omitempty" yaml:"values,omitempty"`
	// Group > 0 时，同组的多条 ancestor.* 条件必须同时命中血缘链中的同一个祖先进程
	Group int `json:"group,omitempty" yaml:"group,omitempty"`
}

func (Suppression) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("rule_id"),
	}
}
