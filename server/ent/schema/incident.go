package schema

import (
	"encoding/json"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Incident 事件：关联引擎聚合出的攻击故事，AI 研判的对象。
// 状态机：open（还没有可用结论：新事件、分析师重开）→ triaged；closed / false_positive 是分析师终态。
// 研判后再并入的新证据不改 status，记在 evidence_at / urgent_at，与 triaged_at 比较即知是否待重研判
// （口径见 internal/review/retriage.go）：旧结论在重研判前继续有效，通知与列表不必卡在「待研判」。
type Incident struct {
	ent.Schema
}

func (Incident) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(newV7),
		field.Time("created_at").Default(time.Now),
		field.String("status").Default("open"),
		field.Int64("integration_revision").Default(0),
		field.JSON("graph", json.RawMessage{}),
		field.JSON("ai_verdict", json.RawMessage{}).Optional(),
		field.String("title").Optional().Nillable(),
		// webhook 投递标记：非空表示已推送（或按策略静默跳过），空则待投递
		field.Time("notified_at").Optional().Nillable(),
		// 结案：closed 表示属实已处置，false_positive 表示误报或良性；备注会作为案例喂回研判
		field.Text("resolution").Optional().Nillable(),
		field.String("resolved_by").Optional().Nillable(),
		field.Time("resolved_at").Optional().Nillable(),
		// 结案说明从哪来：空为人工写的；ai_verdict 人没写理由、采纳了 AI 研判；ai_proposal 原样采纳了 AI 结案建议。
		// 后两种不是人的独立判断，不作为人工案例回喂研判
		field.String("resolution_source").Optional().Nillable(),
		// 最近一次完成研判时取上下文的时刻（之后进来的证据都没看过）与累计完成次数
		field.Time("triaged_at").Optional().Nillable(),
		// 当前执行的开始时间与心跳；过期心跳不能继续显示正在研判。
		field.Time("triage_started_at").Optional().Nillable(),
		field.Time("triage_heartbeat_at").Optional().Nillable(),
		field.Int("triage_count").Default(0),
		// 关联引擎最近一次并入新证据的时刻（同实体同规则的重复不算）；晚于 triaged_at 即待重研判，冷却到期再研判
		field.Time("evidence_at").Optional().Nillable(),
		// 其中升级类证据（级别高于已有最高级别，或首次出现的高危例外规则）的时刻：晚于 triaged_at 即立即重研判，通知等新结论
		field.Time("urgent_at").Optional().Nillable(),
		// 研判连续失败次数与退避到期时刻：失败的只退避自己，不堵队首
		field.Int("triage_failures").Default(0),
		field.Time("triage_retry_at").Optional().Nillable(),
		// AI 的结案建议：人在事件页一键采纳（结案仍记在人名下、照常作为人工案例回喂研判）或忽略。
		// 任何状态变更都会清掉它
		field.JSON("closure_proposal", &ClosureProposal{}).Optional(),
		field.JSON("work", &IncidentWork{}).Optional(),
		field.Time("work_next_check_at").Optional().Nillable(),
	}
}

// ClosureProposal AI 提的结案建议
type ClosureProposal struct {
	// closed 属实已处置 / false_positive 误报或良性
	Status    string     `json:"status"`
	Note      string     `json:"note"`
	SessionID uuid.UUID  `json:"sessionId"`
	ReportID  *uuid.UUID `json:"reportId,omitempty"`
	At        time.Time  `json:"at"`
}

func (Incident) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("alerts", Alert.Type),
	}
}

// IncidentWork 服务端持有的自治计划；不接受模型或 API 直接改写负责人和预算。
type IncidentWork struct {
	Version     int           `json:"version"`
	Owner       string        `json:"owner"`
	Stage       string        `json:"stage"`
	EvidenceKey string        `json:"evidence_key"`
	VerdictAt   time.Time     `json:"verdict_at"`
	GapKind     string        `json:"gap_kind,omitempty"`
	Attempts    int           `json:"attempts"`
	Receipts    []WorkReceipt `json:"receipts,omitempty"`
	WakeOn      []string      `json:"wake_on"`
	Reason      string        `json:"reason"`
}

func (Incident) Indexes() []ent.Index {
	return []ent.Index{index.Fields("status", "work_next_check_at")}
}

// WorkReceipt 受控调查工具的服务端回执引用，保留失败状态供下一轮避免盲目重发。
type WorkReceipt struct {
	CommandID string `json:"command_id,omitempty"`
	Template  string `json:"template,omitempty"`
	Status    string `json:"status,omitempty"`
}
