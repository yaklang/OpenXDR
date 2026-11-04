// Package review "需要人看"的统一口径：通知推送、待复核计数与列表、良性事件自动结案共用一套定义，
// 改一处全跟着变，不会出现总览说要看、通知却没推的情况。
package review

import (
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"

	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/decoy"
)

// Severity 高危及以上的级别阈值：用于高危可疑事件的复核判定、误报统计与自动化识别的安全边界
const Severity = 4

// ClosedBy 系统自动结案的 resolved_by，用来和分析师的人工结论区分
const ClosedBy = "system"

// unresolved 引擎已研判但分析师还没结案的也算未结案
func unresolved() predicate.Incident { return incident.StatusIn("open", "triaged") }

// benign AI 结论为良性；没有结论或结论缺字段都不算良性
func benign() predicate.Incident {
	return func(s *sql.Selector) {
		s.Where(sql.ExprP(fmt.Sprintf("COALESCE(%s->>'verdict', '') = 'benign'", s.C(incident.FieldAiVerdict))))
	}
}

// suspicious AI 结论为可疑
func suspicious() predicate.Incident {
	return func(s *sql.Selector) {
		s.Where(sql.ExprP(fmt.Sprintf("COALESCE(%s->>'verdict', '') = 'suspicious'", s.C(incident.FieldAiVerdict))))
	}
}

// responseAction AI 研判要求隔离/阻断响应（response_tier 为 contain/isolate，或 action_codes 含 review_response）
func responseAction() predicate.Incident {
	return func(s *sql.Selector) {
		col := s.C(incident.FieldAiVerdict)
		s.Where(sql.ExprP(fmt.Sprintf(
			"(COALESCE(%[1]s->>'response_tier', '') IN ('contain', 'isolate') OR COALESCE(%[1]s, 'null'::jsonb) @> '{\"action_codes\":[\"review_response\"]}'::jsonb)",
			col,
		)))
	}
}

// proposedFalsePositive AI 会话已深入查证并提交了误报/良性结案建议（closure_proposal.status = false_positive）
func proposedFalsePositive() predicate.Incident {
	return func(s *sql.Selector) {
		s.Where(sql.ExprP(fmt.Sprintf("COALESCE(%s->>'status', '') = 'false_positive'", s.C(incident.FieldClosureProposal))))
	}
}

func severe() predicate.Incident { return incident.HasAlertsWith(alert.SeverityGTE(Severity)) }

func decoyAlert() predicate.Alert { return alert.RuleIDHasPrefix(decoy.ObservationRulePrefix) }

// decoyReview 含分析师提交的诱饵观察：人点名要复核，AI 判良性也不能替人结案。
func decoyReview() predicate.Incident { return incident.HasAlertsWith(decoyAlert()) }

// DecoyOnly 只有诱饵观察：按约定只做站内复核不推送；同主机真实告警并入后照常通知。
func DecoyOnly() predicate.Incident {
	return incident.And(decoyReview(), incident.Not(incident.HasAlertsWith(alert.Not(decoyAlert()))))
}

// quiet 已由 AI 研判（status=triaged 且无升级类待重研判证据）、不含人工提交的诱饵观察，且满足以下任一静默自治条件：
//  1. AI 判良性（benign，不论原规则级别）；
//  2. AI 判可疑（suspicious）且无需隔离/阻断响应，同时级别低于高危（< Severity）或 AI 会话已查证提议 false_positive 结案。
func quiet() predicate.Incident {
	return incident.And(
		incident.StatusEQ("triaged"),
		incident.Not(Urgent()),
		incident.Not(decoyReview()),
		incident.Or(
			benign(),
			incident.And(
				suspicious(),
				incident.Not(responseAction()),
				incident.Or(incident.Not(severe()), proposedFalsePositive()),
			),
		),
	)
}

// Needed 未结案，且超出静默自治范围（未研判、升级待重研判、AI 判恶意、高危可疑/需响应处置、或含人工提交的诱饵观察）。
func Needed() predicate.Incident {
	return incident.And(unresolved(), incident.Not(quiet()))
}

// StaleBenign 属于静默自治范围、之后没有待重研判的新证据且创建早于 before：到期由系统自动结案，不打扰人。
// 结论之后又并入了新证据（待重研判）或分析师重开（open）的不算：旧结论没看过新证据，不能拿它结案
func StaleBenign(before time.Time) predicate.Incident {
	return incident.And(quiet(), incident.Not(newer(incident.FieldEvidenceAt)), incident.CreatedAtLT(before))
}
