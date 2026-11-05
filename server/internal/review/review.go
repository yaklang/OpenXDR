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

// humanEscalation AI 研判要求隔离/阻断响应，或存在平台无法替代的原始日志人工补证（response_tier 为 contain/isolate，或 action_codes 含 review_response / collect_original_records）
func humanEscalation() predicate.Incident {
	return func(s *sql.Selector) {
		col := s.C(incident.FieldAiVerdict)
		s.Where(sql.ExprP(fmt.Sprintf(
			"(COALESCE(%[1]s->>'response_tier', '') IN ('contain', 'isolate') OR COALESCE(%[1]s, 'null'::jsonb) @> '{\"action_codes\":[\"review_response\"]}'::jsonb)",
			col,
		)))
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

// quiet 已由 AI 研判（status=triaged 且无升级类待重研判证据）、不含人工提交的诱饵观察、无需隔离/阻断响应或不可避免的原始记录人工补取，
// 且满足以下任一静默自治条件：
//  1. AI 判良性（benign，不论原规则级别）；
//  2. AI 判可疑（suspicious）且级别低于高危（< Severity）。
//
// 未经人工采纳的 AI 结案建议（closure_proposal）不能降低高危可疑事件的复核要求。
func quiet() predicate.Incident {
	return incident.And(
		incident.StatusEQ("triaged"),
		incident.Not(Urgent()),
		incident.Not(decoyReview()),
		incident.Not(humanEscalation()),
		managedWork(),
		incident.Or(
			benign(),
			incident.And(
				suspicious(),
				incident.Not(severe()),
			),
		),
	)
}

// Needed 未结案，且超出静默自治范围（未研判、升级待重研判、AI 判恶意、高危可疑、需人工响应/原始日志补证、或含人工提交的诱饵观察）。
func Needed() predicate.Incident {
	return incident.And(unresolved(), incident.Not(quiet()))
}

// StaleBenign AI 判良性、无需人工响应或原始记录补取、不含人工提交的诱饵观察、之后没有待重研判的新证据且创建早于 before：到期由系统自动按误报结案。
// 静默不通知的可疑事件（suspicious）不在此列：无需即时打扰人不等于已证明误报，不能自动按 false_positive 结案。
// 结论之后又并入了新证据（待重研判）或分析师重开（open）的不算：旧结论没看过新证据，不能拿它结案
func StaleBenign(before time.Time) predicate.Incident {
	return incident.And(
		incident.StatusEQ("triaged"),
		incident.Not(Urgent()),
		incident.Not(newer(incident.FieldEvidenceAt)),
		benign(),
		incident.Not(hasEvidenceGap()),
		managedWork(),
		incident.Not(humanEscalation()),
		incident.Not(decoyReview()),
		incident.CreatedAtLT(before),
	)
}

// hasEvidenceGap 客观缺证阻断误报结案，不直接等同人工阻塞。
func hasEvidenceGap() predicate.Incident {
	return func(s *sql.Selector) {
		s.Where(sql.ExprP(fmt.Sprintf("COALESCE(%s, '{}'::jsonb) @> '{\"action_codes\":[\"collect_original_records\"]}'::jsonb", s.C(incident.FieldAiVerdict))))
	}
}

func managedWork() predicate.Incident {
	return func(s *sql.Selector) {
		s.Where(sql.ExprP(fmt.Sprintf(`COALESCE((%[1]s->>'owner' = 'ai' AND %[1]s->>'stage' IN ('followup','monitoring') AND %[1]s->>'version' = '1' AND (%[1]s->>'verdict_at')::timestamptz = %[2]s AND (%[1]s->>'evidence_key')::timestamptz = GREATEST(%[3]s,%[4]s,%[5]s) AND (%[1]s->>'stage' = 'monitoring' OR %[6]s IS NOT NULL)), false)`, s.C(incident.FieldWork), s.C(incident.FieldTriagedAt), s.C(incident.FieldCreatedAt), s.C(incident.FieldEvidenceAt), s.C(incident.FieldUrgentAt), s.C(incident.FieldWorkNextCheckAt))))
	}
}
