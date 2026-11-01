package api

import (
	"context"
	"encoding/json"
	"net/http"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/decoyobservation"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/decoy"
	"openxdr/server/internal/incidentstate"
)

func mapDecoyReview(mux *http.ServeMux, db *ent.Client) {
	mux.HandleFunc("POST /api/decoys/{id}/observations/{observation}/review", func(w http.ResponseWriter, r *http.Request) {
		if !decoyAuthenticated(w, r) {
			return
		}
		deployment, ok := getByPath(w, r, "id", "decoy", db.DecoyDeployment.Get)
		if !ok {
			return
		}
		observationID, err := uuid.Parse(r.PathValue("observation"))
		if err != nil {
			http.Error(w, "观察 ID 无效", 400)
			return
		}
		tx, err := db.Tx(r.Context())
		if err != nil {
			http.Error(w, "开启事务失败", 500)
			return
		}
		defer tx.Rollback()
		if !lockDecoyAssetAs(w, r, tx, deployment.AssetID, "analyst") {
			return
		}
		observation, err := tx.DecoyObservation.Query().Where(decoyobservation.IDEQ(observationID), decoyobservation.DeploymentIDEQ(deployment.ID), func(s *sql.Selector) { s.ForUpdate() }).Only(r.Context())
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "读取观察失败", 500)
			return
		}
		if observation.IncidentID != nil {
			writeJSON(w, map[string]any{"incidentId": observation.IncidentID})
			return
		}
		severity, reviewable := decoy.ReviewSeverity(observation.Kind)
		if !reviewable {
			http.Error(w, "运行生命周期事件不用于安全复核", 400)
			return
		}
		host, err := tx.Asset.Get(r.Context(), deployment.AssetID)
		if err != nil {
			http.Error(w, "读取资产失败", 500)
			return
		}
		incidentID, err := openDecoyIncident(r.Context(), tx, deployment, host, observation, severity, "human")
		if err == nil {
			err = audit.Checked(r.Context(), tx.AuditLog.Create(), auth.From(r.Context()).Username, audit.RemoteAddr(r), "decoy_observation_review_requested", incidentID.String(), "人工提交观察 "+observation.ID.String()+"；仅站内复核，不代表攻击归因")
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			http.Error(w, "保存复核事件失败", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		writeJSON(w, map[string]any{"incidentId": incidentID})
	})
}

// openDecoyIncident 把一条观察落成证据、告警与 incident 并回挂观察；调用方持有资产锁与事务。
// origin 记录是人工提交还是标记命中自动开单，归因始终未确认。
func openDecoyIncident(ctx context.Context, tx *ent.Tx, deployment *ent.DecoyDeployment, host *ent.Asset, observation *ent.DecoyObservation, severity int16, origin string) (uuid.UUID, error) {
	raw, _ := json.Marshal(map[string]any{"class_uid": 0, "source": "decoy", "activity_name": observation.Kind, "time": observation.ReceivedAt,
		"decoy": map[string]any{"observation_id": observation.ID, "deployment_id": deployment.ID, "carrier": deployment.Kind, "profile": deployment.Profile, "template": deployment.Template, "revision_id": observation.RevisionID, "session_id": observation.SessionID, "details": observation.Details, "occurred_at": observation.OccurredAt, "attribution": "unconfirmed", "review_origin": origin, "limitation": "访问或打开不证明读取正文、AI 身份或攻击意图"}})
	event, err := tx.Event.Create().SetTs(observation.ReceivedAt).SetClassUID(0).SetSource("decoy").SetAssetID(host.ID).SetRaw(raw).Save(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	// 只有诱饵观察时仅站内复核（通知按 review.DecoyOnly 跳过）；不预置已通知，
	// 否则同主机随后并入的真实告警也永远不会推送。
	incident, err := tx.Incident.Create().SetGraph(json.RawMessage(`{"nodes":[],"edges":[],"overflow":0}`)).SetTitle("诱饵观察待复核：" + observation.Kind + " @ " + host.Hostname).Save(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	al, err := tx.Alert.Create().SetTs(observation.ReceivedAt).SetRuleID(decoy.ObservationRulePrefix + observation.Kind).SetSeverity(severity).SetAssetID(host.ID).SetEventID(event.ID).SetIncidentID(incident.ID).Save(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	graph, _ := json.Marshal(map[string]any{"nodes": []map[string]string{{"id": "asset:" + host.ID.String(), "type": "asset", "label": host.Hostname}, {"id": "alert:" + al.ID.String(), "type": "alert", "label": "诱饵观察（归因未确认）"}}, "edges": []map[string]string{{"from": "asset:" + host.ID.String(), "to": "alert:" + al.ID.String(), "rel": "observed"}}, "overflow": 0})
	if err = tx.Incident.UpdateOneID(incident.ID).SetGraph(graph).Exec(ctx); err != nil {
		return uuid.Nil, err
	}
	if err := incidentstate.Record(ctx, tx, incident.ID, incidentstate.Created, incidentstate.Origin{Kind: "system"}, ""); err != nil {
		return uuid.Nil, err
	}
	return incident.ID, tx.DecoyObservation.UpdateOneID(observation.ID).SetIncidentID(incident.ID).Exec(ctx)
}
