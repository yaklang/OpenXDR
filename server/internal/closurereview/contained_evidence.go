package closurereview

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/containment"
	"openxdr/server/ent/event"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/incidentstate"
	"openxdr/server/internal/suppress"
)

// 对相关资产上原始证据的实体逐项比较；查询截断或实体未知时拒绝自动结案。
func quietEvidence(ctx context.Context, db *ent.Client, assets []uuid.UUID, anchors []*ent.Event, since time.Time) (bool, error) {
	rows, err := db.Event.Query().Where(event.AssetIDIn(assets...), event.TsGT(since)).Limit(1001).All(ctx)
	if err != nil {
		return false, err
	}
	if len(rows) > 1000 {
		return false, nil
	}
	for _, anchor := range anchors {
		keys := entityKeys(anchor)
		if len(keys) == 0 {
			return false, nil
		}
		for _, row := range rows {
			for k, v := range entityKeys(row) {
				if (k == "parent_process_guid" && keys["process_guid"] == v) || (k == "process_guid" && keys["parent_process_guid"] == v) {
					return false, nil
				}
				if keys[k] == v && v != "" {
					return false, nil
				}
			}
		}
	}
	return true, nil
}
func entityKeys(e *ent.Event) map[string]string {
	keys := map[string]string{}
	if e.ProcessGUID != nil {
		keys["process_guid"] = e.ProcessGUID.String()
	}
	if e.ParentProcessGUID != nil {
		keys["parent_process_guid"] = e.ParentProcessGUID.String()
	}
	if e.ConnTuple != nil {
		keys["conn_tuple"] = *e.ConnTuple
	}
	var raw map[string]any
	if json.Unmarshal(e.Raw, &raw) == nil {
		for _, field := range []string{"process.cmd_line", "process.file.path", "file.path", "query.hostname", "src_endpoint.ip", "dst_endpoint.ip"} {
			if value, ok := suppress.Lookup(raw, field); ok && value != "" {
				keys[field] = value
			}
		}
	}
	return keys
}

// ReopenContained 在关联事务中检查自动遏制结案后的新增告警/实体证据；人工终态不受影响。
func ReopenContained(ctx context.Context, tx *ent.Tx) error {
	db := tx.Client()
	incidents, err := db.Incident.Query().Where(incident.StatusEQ("closed"), incident.ResolutionSourceEQ("ai_review")).All(ctx)
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
		noisy, err := db.Alert.Query().Where(alert.AssetIDIn(assets...), alert.Or(alert.TsGT(*inc.ResolvedAt), alert.LastTsGT(*inc.ResolvedAt))).Exist(ctx)
		if err != nil {
			return err
		}
		quiet, err := quietEvidence(ctx, db, assets, anchors, *inc.ResolvedAt)
		if err != nil {
			return err
		}
		if !noisy && quiet {
			continue
		}
		n, err := db.Incident.Update().Where(incident.IDEQ(inc.ID), incident.StatusEQ("closed"), incident.ResolvedAtEQ(*inc.ResolvedAt), incident.ResolutionSourceEQ("ai_review")).SetStatus("open").SetEvidenceAt(time.Now()).ClearResolution().ClearResolvedAt().ClearResolvedBy().ClearResolutionSource().ClearClosureProposal().ClearWork().ClearWorkNextCheckAt().Save(ctx)
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
