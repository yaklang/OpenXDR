// Package api 前端专用只读 API + 分析师状态操作。
package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/ent/incident"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

// triaged 是引擎专属状态，分析师只能在这三个之间拨
var analystStatuses = []string{"open", "closed", "false_positive"}

type incidentSummary struct {
	ID         uuid.UUID       `json:"id"`
	CreatedAt  time.Time       `json:"createdAt"`
	Status     string          `json:"status"`
	Title      *string         `json:"title"`
	AiVerdict  json.RawMessage `json:"aiVerdict"`
	AlertCount int             `json:"alertCount"`
	// 派生自告警的最高级别，列表按轻重着色用
	Severity int16 `json:"severity"`
}

type alertRow struct {
	ID        uuid.UUID       `json:"id"`
	Ts        time.Time       `json:"ts"`
	LastTs    *time.Time      `json:"lastTs"`
	Count     int             `json:"count"`
	Severity  int16           `json:"severity"`
	RuleID    string          `json:"ruleId"`
	RuleTitle *string         `json:"ruleTitle"`
	Event     json.RawMessage `json:"event"`
}

type incidentDetail struct {
	incidentSummary
	Graph json.RawMessage `json:"graph"`
	// 响应指令要下发到具体主机，取告警里第一个有归属的资产
	AssetID *uuid.UUID `json:"assetId"`
	Alerts  []alertRow `json:"alerts"`
}

func Handler(db *ent.Client, rules *sigma.Engine, hub *response.Hub, suppressions *suppress.Store, intelStore *intel.Store, selfEndpoints []string) http.Handler {
	mux := http.NewServeMux()
	mapCommands(mux, db, hub, selfEndpoints)
	mapSuppressions(mux, db, suppressions, rules)
	mapIntel(mux, db, intelStore)
	mapStats(mux, db, rules)
	mapEvents(mux, db)
	mapRules(mux, rules)
	mapUsers(mux, db)

	mux.HandleFunc("GET /api/incidents", func(w http.ResponseWriter, r *http.Request) {
		q := db.Incident.Query()
		if status := r.URL.Query().Get("status"); status != "" {
			q = q.Where(incident.StatusEQ(status))
		}
		incidents, err := q.Order(ent.Desc(incident.FieldCreatedAt)).Limit(50).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ids := make([]uuid.UUID, len(incidents))
		for i, inc := range incidents {
			ids[i] = inc.ID
		}
		var counts []struct {
			IncidentID uuid.UUID `json:"incident_id"`
			Count      int       `json:"count"`
			Max        int16     `json:"max"`
		}
		_ = db.Alert.Query().
			Where(alert.IncidentIDIn(ids...)).
			GroupBy(alert.FieldIncidentID).
			Aggregate(ent.Count(), ent.Max(alert.FieldSeverity)).
			Scan(r.Context(), &counts)
		countBy := map[uuid.UUID]int{}
		sevBy := map[uuid.UUID]int16{}
		for _, c := range counts {
			countBy[c.IncidentID] = c.Count
			sevBy[c.IncidentID] = c.Max
		}

		out := make([]incidentSummary, len(incidents))
		for i, inc := range incidents {
			out[i] = summarize(inc, countBy[inc.ID], sevBy[inc.ID])
		}
		writeJSON(w, out)
	})

	mux.HandleFunc("GET /api/incidents/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 incident id", http.StatusBadRequest)
			return
		}
		inc, err := db.Incident.Get(r.Context(), id)
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		alerts, err := db.Alert.Query().
			Where(alert.IncidentIDEQ(id)).
			Order(ent.Asc(alert.FieldTs)).
			Limit(500).
			WithEvent().
			All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var assetID *uuid.UUID
		var maxSev int16
		rows := make([]alertRow, len(alerts))
		for i, a := range alerts {
			if assetID == nil && a.AssetID != nil {
				assetID = a.AssetID
			}
			if a.Severity > maxSev {
				maxSev = a.Severity
			}
			row := alertRow{
				ID: a.ID, Ts: a.Ts, LastTs: a.LastTs, Count: a.Count,
				Severity: a.Severity, RuleID: a.RuleID,
			}
			if title := rules.TitleOf(a.RuleID); title != "" {
				row.RuleTitle = &title
			}
			if a.Edges.Event != nil {
				row.Event = a.Edges.Event.Raw
			}
			rows[i] = row
		}
		writeJSON(w, incidentDetail{
			incidentSummary: summarize(inc, len(alerts), maxSev),
			Graph:           inc.Graph,
			AssetID:         assetID,
			Alerts:          rows,
		})
	})

	mux.HandleFunc("POST /api/incidents/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 incident id", http.StatusBadRequest)
			return
		}
		var body struct {
			Status string `json:"status"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || !slices.Contains(analystStatuses, body.Status) {
			http.Error(w, "status 必须是 open / closed / false_positive", http.StatusBadRequest)
			return
		}
		err = db.Incident.UpdateOneID(id).SetStatus(body.Status).Exec(r.Context())
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "incident_status", id.String(), body.Status)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /api/assets", func(w http.ResponseWriter, r *http.Request) {
		assets, err := db.Asset.Query().Order(ent.Asc(entasset.FieldHostname)).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type assetRow struct {
			ID        uuid.UUID  `json:"id"`
			Hostname  string     `json:"hostname"`
			Os        *string    `json:"os"`
			IPAddrs   []string   `json:"ipAddrs"`
			AgentID   *uuid.UUID `json:"agentId"`
			FirstSeen time.Time  `json:"firstSeen"`
			LastSeen  time.Time  `json:"lastSeen"`
		}
		out := make([]assetRow, len(assets))
		for i, a := range assets {
			out[i] = assetRow{a.ID, a.Hostname, a.Os, a.IPAddrs, a.AgentID, a.FirstSeen, a.LastSeen}
		}
		writeJSON(w, out)
	})

	return mux
}

func summarize(inc *ent.Incident, alertCount int, severity int16) incidentSummary {
	return incidentSummary{
		ID: inc.ID, CreatedAt: inc.CreatedAt, Status: inc.Status,
		Title: inc.Title, AiVerdict: inc.AiVerdict, AlertCount: alertCount,
		Severity: severity,
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
