package triage

import (
	"encoding/json"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"openxdr/server/ent"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"openxdr/server/ent/triagerun"
	"openxdr/server/internal/review"
)

// 只有调查能力变化才提升版本；仍缺证的成功结论不会反复占用队列。
const evidenceCapabilityVersion = 3
const capabilityTrigger = "capability_upgrade_v3"
const capabilityMaxAttempts = 3

func needsCapabilityUpgrade(inc *ent.Incident) bool {
	if inc.Status != "triaged" || review.IsRetriage(inc) || review.IsUrgent(inc) {
		return false
	}
	var verdict struct {
		Version any      `json:"evidence_capability_version"`
		Actions []string `json:"action_codes"`
	}
	if json.Unmarshal(inc.AiVerdict, &verdict) != nil || fmt.Sprint(verdict.Version) == fmt.Sprint(evidenceCapabilityVersion) {
		return false
	}
	for _, action := range verdict.Actions {
		if action == "collect_original_records" {
			return true
		}
	}
	return false
}

func capabilityDue(now time.Time, cooldown time.Duration) predicate.Incident {
	return incident.And(
		incident.StatusEQ("triaged"), incident.Not(review.Retriage()), incident.Not(review.Urgent()),
		incident.Or(incident.TriageRetryAtIsNil(), incident.TriageRetryAtLTE(now)),
		incident.Or(incident.TriagedAtIsNil(), incident.TriagedAtLTE(now.Add(-cooldown))),
		func(s *sql.Selector) {
			v := s.C(incident.FieldAiVerdict)
			s.Where(sql.P(func(b *sql.Builder) {
				b.WriteString(fmt.Sprintf("COALESCE(%s->>'evidence_capability_version', '') <> ", v)).Arg(fmt.Sprint(evidenceCapabilityVersion))
				b.WriteString(fmt.Sprintf(" AND COALESCE(%s, '{}'::jsonb) @> ", v)).Arg(`{"action_codes":["collect_original_records"]}`).WriteString("::jsonb")
			}))
			s.Where(sql.P(func(b *sql.Builder) {
				b.WriteString(fmt.Sprintf("(SELECT count(*) FROM %s r WHERE r.incident_id = %s AND r.trigger = ", triagerun.Table, s.C(incident.FieldID)))
				b.Arg(capabilityTrigger).WriteString(") < ").Arg(capabilityMaxAttempts)
			}))
		},
	)
}

func withEvidenceCapability(verdict json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(verdict, &obj) != nil || obj == nil {
		return verdict
	}
	obj["evidence_capability_version"] = json.RawMessage(fmt.Sprint(evidenceCapabilityVersion))
	out, err := json.Marshal(obj)
	if err != nil {
		return verdict
	}
	return out
}
