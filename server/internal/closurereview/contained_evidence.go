package closurereview

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/containment"
	"openxdr/server/ent/event"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/incidentstate"
	"openxdr/server/internal/suppress"
)

// reopenWindow 只复核最近 7 天内由 ai_review 遏制结案的事件，避免每轮关联全表扫描多年历史。
const reopenWindow = 7 * 24 * time.Hour

type rawEntitySpec struct {
	field string
	expr  string
}

var rawEntitySpecs = []rawEntitySpec{
	{field: "process.cmd_line", expr: "->'process'->>'cmd_line'"},
	{field: "process.file.path", expr: "->'process'->'file'->>'path'"},
	{field: "file.path", expr: "->'file'->>'path'"},
	{field: "query.hostname", expr: "->'query'->>'hostname'"},
	{field: "src_endpoint.ip", expr: "->'src_endpoint'->>'ip'"},
	{field: "dst_endpoint.ip", expr: "->'dst_endpoint'->>'ip'"},
}

type anchorEntities struct {
	guids      []uuid.UUID
	connTuples []string
	rawFields  map[string][]string
}

func (a anchorEntities) empty() bool {
	if len(a.guids) > 0 || len(a.connTuples) > 0 {
		return false
	}
	for _, vals := range a.rawFields {
		if len(vals) > 0 {
			return false
		}
	}
	return true
}

func extractAnchorEntities(anchors []*ent.Event) (anchorEntities, bool) {
	out := anchorEntities{rawFields: map[string][]string{}}
	if len(anchors) == 0 {
		return out, false
	}
	guidSeen := map[uuid.UUID]bool{}
	connSeen := map[string]bool{}
	rawSeen := map[string]map[string]bool{}
	allHaveKeys := true
	for _, anchor := range anchors {
		if anchor == nil {
			allHaveKeys = false
			continue
		}
		hasKey := false
		if anchor.ProcessGUID != nil && *anchor.ProcessGUID != uuid.Nil {
			hasKey = true
			if !guidSeen[*anchor.ProcessGUID] {
				guidSeen[*anchor.ProcessGUID] = true
				out.guids = append(out.guids, *anchor.ProcessGUID)
			}
		}
		if anchor.ParentProcessGUID != nil && *anchor.ParentProcessGUID != uuid.Nil {
			hasKey = true
			if !guidSeen[*anchor.ParentProcessGUID] {
				guidSeen[*anchor.ParentProcessGUID] = true
				out.guids = append(out.guids, *anchor.ParentProcessGUID)
			}
		}
		if anchor.ConnTuple != nil && *anchor.ConnTuple != "" {
			hasKey = true
			if !connSeen[*anchor.ConnTuple] {
				connSeen[*anchor.ConnTuple] = true
				out.connTuples = append(out.connTuples, *anchor.ConnTuple)
			}
		}
		var raw map[string]any
		if json.Unmarshal(anchor.Raw, &raw) == nil {
			for _, spec := range rawEntitySpecs {
				if value, ok := suppress.Lookup(raw, spec.field); ok && value != "" {
					hasKey = true
					seen := rawSeen[spec.field]
					if seen == nil {
						seen = map[string]bool{}
						rawSeen[spec.field] = seen
					}
					if !seen[value] {
						seen[value] = true
						out.rawFields[spec.field] = append(out.rawFields[spec.field], value)
					}
				}
			}
		}
		if !hasKey {
			allHaveKeys = false
		}
	}
	slices.SortFunc(out.guids, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	slices.Sort(out.connTuples)
	for k := range out.rawFields {
		slices.Sort(out.rawFields[k])
	}
	return out, allHaveKeys
}

func buildEntityPredicate(entities anchorEntities) predicate.Event {
	var preds []predicate.Event
	if len(entities.guids) > 0 {
		preds = append(preds, event.ProcessGUIDIn(entities.guids...), event.ParentProcessGUIDIn(entities.guids...))
	}
	if len(entities.connTuples) > 0 {
		preds = append(preds, event.ConnTupleIn(entities.connTuples...))
	}
	for _, spec := range rawEntitySpecs {
		vals := entities.rawFields[spec.field]
		if len(vals) == 0 {
			continue
		}
		expr := spec.expr
		args := make([]any, len(vals))
		for i, v := range vals {
			args[i] = v
		}
		preds = append(preds, func(s *sql.Selector) {
			s.Where(sql.P(func(b *sql.Builder) {
				b.WriteString(s.C(event.FieldRaw))
				b.WriteString(expr)
				b.WriteString(" IN (")
				b.Args(args...)
				b.WriteByte(')')
			}))
		})
	}
	return event.Or(preds...)
}

func hasMatchingEvidence(ctx context.Context, db *ent.Client, assets []uuid.UUID, entities anchorEntities, since time.Time) (bool, error) {
	if len(assets) == 0 || entities.empty() {
		return false, nil
	}
	return db.Event.Query().Where(
		event.AssetIDIn(assets...),
		event.TsGT(since),
		buildEntityPredicate(entities),
	).Exist(ctx)
}

func dedupUUIDs(ids []uuid.UUID) []uuid.UUID {
	if len(ids) <= 1 {
		return ids
	}
	out := append([]uuid.UUID(nil), ids...)
	slices.SortFunc(out, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(out)
}

// quietEvidence 结案前安静窗口核验：按锚点实体在 SQL 层定向检索，实体未知时保守拒绝自动结案，
// 正常活跃主机的无关遥测事件不再触发截断误判。
func quietEvidence(ctx context.Context, db *ent.Client, assets []uuid.UUID, anchors []*ent.Event, since time.Time) (bool, error) {
	assets = dedupUUIDs(assets)
	entities, allHaveKeys := extractAnchorEntities(anchors)
	if len(assets) == 0 || !allHaveKeys || entities.empty() {
		return false, nil
	}
	matched, err := hasMatchingEvidence(ctx, db, assets, entities, since)
	if err != nil {
		return false, err
	}
	return !matched, nil
}

// ReopenContained 在关联事务中检查最近 7 天内自动遏制结案后的新增告警或匹配实体的新证据；人工终态不受影响。
func ReopenContained(ctx context.Context, tx *ent.Tx) error {
	return reopenContainedAt(ctx, tx, time.Now())
}

func reopenContainedAt(ctx context.Context, tx *ent.Tx, now time.Time) error {
	db := tx.Client()
	cutoff := now.Add(-reopenWindow)
	incidents, err := db.Incident.Query().Where(
		incident.StatusEQ("closed"),
		incident.ResolutionSourceEQ("ai_review"),
		incident.ResolvedAtNotNil(),
		incident.ResolvedAtGT(cutoff),
	).All(ctx)
	if err != nil {
		return err
	}
	for _, inc := range incidents {
		if inc.ResolvedAt == nil {
			continue
		}
		alerts, err := db.Alert.Query().Where(alert.IncidentIDEQ(inc.ID)).WithEvent().All(ctx)
		if err != nil {
			return err
		}
		assets := []uuid.UUID{}
		anchors := []*ent.Event{}
		for _, a := range alerts {
			if a.AssetID != nil {
				assets = append(assets, *a.AssetID)
			}
			if a.Edges.Event != nil {
				anchors = append(anchors, a.Edges.Event)
			}
		}
		ids := make([]uuid.UUID, 0, len(alerts))
		for _, a := range alerts {
			ids = append(ids, a.ID)
		}
		rows, err := db.Containment.Query().Where(containment.Or(containment.IncidentIDEQ(inc.ID), containment.AlertIDIn(ids...))).All(ctx)
		if err != nil {
			return err
		}
		for _, c := range rows {
			assets = append(assets, c.AssetID)
			if c.SourceAssetID != nil {
				assets = append(assets, *c.SourceAssetID)
			}
		}
		assets = dedupUUIDs(assets)
		if len(assets) == 0 {
			continue
		}
		noisy, err := db.Alert.Query().Where(alert.AssetIDIn(assets...), alert.Or(alert.TsGT(*inc.ResolvedAt), alert.LastTsGT(*inc.ResolvedAt))).Exist(ctx)
		if err != nil {
			return err
		}
		matched := false
		if !noisy {
			entities, _ := extractAnchorEntities(anchors)
			if !entities.empty() {
				matched, err = hasMatchingEvidence(ctx, db, assets, entities, *inc.ResolvedAt)
				if err != nil {
					return err
				}
			}
		}
		if !noisy && !matched {
			continue
		}
		n, err := db.Incident.Update().Where(incident.IDEQ(inc.ID), incident.StatusEQ("closed"), incident.ResolvedAtEQ(*inc.ResolvedAt), incident.ResolutionSourceEQ("ai_review")).SetStatus("open").SetEvidenceAt(now).ClearResolution().ClearResolvedAt().ClearResolvedBy().ClearResolutionSource().ClearClosureProposal().ClearWork().ClearWorkNextCheckAt().Save(ctx)
		if err != nil {
			return err
		}
		if n != 1 {
			continue
		}
		if err = audit.Checked(ctx, tx.AuditLog.Create(), Actor, "server", "incident_contained_reopened", inc.ID.String(), "遏制结案后出现新增告警或实体证据，重新调查"); err != nil {
			return err
		}
		if err = incidentstate.Record(ctx, tx, inc.ID, incidentstate.StatusChanged, incidentstate.Origin{Kind: "system", ID: Actor}, "closed"); err != nil {
			return err
		}
	}
	return nil
}
