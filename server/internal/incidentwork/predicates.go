package incidentwork

import (
	"entgo.io/ent/dialect/sql"
	"fmt"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"time"
)

func proposalEquals(raw string) predicate.Incident {
	return func(s *sql.Selector) {
		s.Where(sql.P(func(b *sql.Builder) {
			b.Ident(s.C(incident.FieldClosureProposal)).WriteString(" = ").Arg(raw).WriteString("::jsonb")
		}))
	}
}

func needsRefresh() predicate.Incident {
	return func(s *sql.Selector) {
		s.Where(sql.ExprP(fmt.Sprintf(`(%[1]s IS NULL OR (%[1]s->>'stage' = 'followup' AND ((%[1]s->>'attempts')::int >= 3 OR %[7]s IS NULL)) OR (%[2]s IS NOT NULL AND (%[1]s->>'verdict_at')::timestamptz IS DISTINCT FROM %[2]s) OR (%[1]s->>'evidence_key')::timestamptz IS DISTINCT FROM GREATEST(%[3]s, %[4]s, %[5]s) OR (%[6]s IS NOT NULL AND (%[6]s->>'at')::timestamptz < GREATEST(%[2]s, %[4]s, %[5]s)))`, s.C(incident.FieldWork), s.C(incident.FieldTriagedAt), s.C(incident.FieldCreatedAt), s.C(incident.FieldEvidenceAt), s.C(incident.FieldUrgentAt), s.C(incident.FieldClosureProposal), s.C(incident.FieldWorkNextCheckAt))))
	}
}

// Due 仅使用仍对应已研判快照、未超预算的 AI 跟进计划。
func Due(now time.Time) predicate.Incident {
	return incident.And(incident.StatusEQ("triaged"), incident.WorkNextCheckAtLTE(now), func(s *sql.Selector) {
		s.Where(sql.ExprP(fmt.Sprintf(`%[1]s->>'owner' = 'ai' AND %[1]s->>'stage' = 'followup' AND (%[1]s->>'version') = '1' AND (%[1]s->>'attempts')::int < 3 AND (%[1]s->>'verdict_at')::timestamptz = %[2]s AND (%[1]s->>'evidence_key')::timestamptz = GREATEST(%[3]s,%[4]s,%[5]s)`, s.C(incident.FieldWork), s.C(incident.FieldTriagedAt), s.C(incident.FieldCreatedAt), s.C(incident.FieldEvidenceAt), s.C(incident.FieldUrgentAt))))
	})
}

func workEquals(raw string) predicate.Incident {
	return func(s *sql.Selector) {
		s.Where(sql.P(func(b *sql.Builder) {
			b.Ident(s.C(incident.FieldWork)).WriteString(" = ").Arg(raw).WriteString("::jsonb")
		}))
	}
}
