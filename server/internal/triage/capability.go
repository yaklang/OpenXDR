package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"entgo.io/ent/dialect/sql"
	"openxdr/server/ent"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"openxdr/server/ent/triagerun"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/review"
)

// 只有调查能力变化才提升版本；仍缺证的成功结论不会反复占用队列。
// v4：上下文补了涉事主机的运维待办、管理员执行决定、监听端口，以及登记晚于告警的可信自动化来源，
// 卡在「来源与授权待核实」（verify_source）的旧结论也按新能力重看一次。
const evidenceCapabilityVersion = 4
const capabilityTrigger = "capability_upgrade_v4"

// capabilityActions 结论里出现这些建议，说明当时缺的正是新能力可能补上的证据
var capabilityActions = []string{"collect_original_records", "verify_source"}

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
		if slices.Contains(capabilityActions, action) {
			return true
		}
	}
	return false
}

// capabilityPending 与 needsCapabilityUpgrade 同口径，不将预算或冷却混入能力版本资格。
func capabilityPending() predicate.Incident {
	return incident.And(incident.StatusEQ("triaged"), incident.Not(review.Retriage()), incident.Not(review.Urgent()), func(s *sql.Selector) {
		v := s.C(incident.FieldAiVerdict)
		s.Where(sql.P(func(b *sql.Builder) {
			b.WriteString(fmt.Sprintf("COALESCE(%s->>'evidence_capability_version', '') <> ", v)).Arg(fmt.Sprint(evidenceCapabilityVersion))
			b.WriteString(" AND (")
			for i, action := range capabilityActions {
				if i > 0 {
					b.WriteString(" OR ")
				}
				b.WriteString(fmt.Sprintf("COALESCE(%s, '{}'::jsonb) @> ", v)).Arg(fmt.Sprintf(`{"action_codes":[%q]}`, action)).WriteString("::jsonb")
			}
			b.WriteString(")")
		}))
	})
}

func capabilityAttempts(exhausted bool) predicate.Incident {
	return func(s *sql.Selector) {
		s.Where(sql.P(func(b *sql.Builder) {
			b.WriteString(fmt.Sprintf("(SELECT count(*) FROM %s r WHERE r.incident_id = %s AND r.trigger = ", triagerun.Table, s.C(incident.FieldID)))
			b.Arg(capabilityTrigger).WriteString(")")
			if exhausted {
				b.WriteString(" >= ")
			} else {
				b.WriteString(" < ")
			}
			b.Arg(capabilityMaxAttempts)
		}))
	}
}

func capabilityDue(now time.Time, cooldown time.Duration) predicate.Incident {
	return incident.And(capabilityPending(), capabilityAttempts(false),
		incident.Or(incident.TriageRetryAtIsNil(), incident.TriageRetryAtLTE(now)),
		incident.Or(incident.TriagedAtIsNil(), incident.TriagedAtLTE(now.Add(-cooldown))))
}

// pauseExhaustedCapabilityWork 将旧能力重试耗尽的工作转为证据唤醒监测，避免误占普通跟进队列。
// 不修改普通工作尝试数；新能力版本仍按自己的 trigger 账本获得独立预算。
func (e *Engine) pauseExhaustedCapabilityWork(ctx context.Context, now time.Time) error {
	rows, err := e.DB.Incident.Query().Where(capabilityPending(), capabilityAttempts(true), incident.WorkNotNil(),
		incident.Or(incident.TriageStartedAtIsNil(), incident.TriageHeartbeatAtIsNil(), incident.TriageHeartbeatAtLTE(now.Add(-RunningTTL))),
		func(s *sql.Selector) {
			s.Where(sql.ExprP(fmt.Sprintf("%[1]s->>'owner' = 'ai' AND %[1]s->>'stage' = 'followup'", s.C(incident.FieldWork))))
		}).
		Order(ent.Asc(incident.FieldID)).Limit(100).All(ctx)
	if err != nil {
		return err
	}
	for _, inc := range rows {
		if err := e.pauseCapabilityWork(ctx, inc, now); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) pauseCapabilityWork(ctx context.Context, inc *ent.Incident, now time.Time) error {
	if !needsCapabilityUpgrade(inc) || inc.Work == nil || inc.Work.Owner != "ai" || inc.Work.Stage != "followup" || inc.TriagedAt == nil ||
		inc.Work.EvidenceKey != incidentwork.EvidenceKey(inc) || !inc.Work.VerdictAt.Equal(*inc.TriagedAt) {
		return nil
	}
	raw, err := json.Marshal(inc.Work)
	if err != nil {
		return err
	}
	paused := *inc.Work
	paused.Stage = "monitoring"
	paused.Reason = fmt.Sprintf("调查能力版本 %d 升级重试预算耗尽；保留缺口，等待新证据或能力变化", evidenceCapabilityVersion)
	upd := e.DB.Incident.Update().Where(incident.IDEQ(inc.ID), capabilityPending(), capabilityAttempts(true), incident.TriagedAtEQ(*inc.TriagedAt),
		incident.Or(incident.TriageStartedAtIsNil(), incident.TriageHeartbeatAtIsNil(), incident.TriageHeartbeatAtLTE(now.Add(-RunningTTL))),
		func(s *sql.Selector) {
			s.Where(sql.P(func(b *sql.Builder) {
				b.Ident(s.C(incident.FieldWork)).WriteString(" = ").Arg(string(raw)).WriteString("::jsonb AND ")
				b.Ident(s.C(incident.FieldAiVerdict)).WriteString(" = ").Arg(string(inc.AiVerdict)).WriteString("::jsonb")
			}))
		}).SetWork(&paused).ClearWorkNextCheckAt()
	if inc.EvidenceAt == nil {
		upd.Where(incident.EvidenceAtIsNil())
	} else {
		upd.Where(incident.EvidenceAtEQ(*inc.EvidenceAt))
	}
	if inc.UrgentAt == nil {
		upd.Where(incident.UrgentAtIsNil())
	} else {
		upd.Where(incident.UrgentAtEQ(*inc.UrgentAt))
	}
	if inc.WorkNextCheckAt == nil {
		upd.Where(incident.WorkNextCheckAtIsNil())
	} else {
		upd.Where(incident.WorkNextCheckAtEQ(*inc.WorkNextCheckAt))
	}
	_, err = upd.Save(ctx)
	return err
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
