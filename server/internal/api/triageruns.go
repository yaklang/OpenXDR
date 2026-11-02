package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/triagerun"
	"openxdr/server/internal/triage"
)

func incidentTriageRuns(db *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "事件 ID 无效", 400)
			return
		}
		if !incidentVisible(w, r, db, id, "viewer") {
			return
		}
		inc, err := db.Incident.Get(r.Context(), id)
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "读取事件失败", 500)
			return
		}
		page := 1
		if v := r.URL.Query().Get("page"); v != "" {
			page, err = strconv.Atoi(v)
		}
		if err != nil || page < 1 || page > 100000 {
			http.Error(w, "分页参数无效", 400)
			return
		}
		rows, err := db.TriageRun.Query().Where(triagerun.IncidentIDEQ(id)).Order(ent.Desc(triagerun.FieldStartedAt), ent.Desc(triagerun.FieldID)).Offset((page - 1) * 20).Limit(21).All(r.Context())
		if err != nil {
			http.Error(w, "读取研判记录失败", 500)
			return
		}
		more := len(rows) > 20
		rows = rows[:min(len(rows), 20)]
		if rows == nil {
			rows = []*ent.TriageRun{}
		}
		w.Header().Set("Cache-Control", "no-store")
		type runView struct {
			*ent.TriageRun
			HeartbeatValid bool `json:"heartbeat_valid"`
		}
		items := make([]runView, len(rows))
		active := triage.RunningStartedAt(inc, time.Now())
		for i, row := range rows {
			items[i] = runView{row, active != nil && row.Status == triagerun.StatusRunning && active.Equal(row.StartedAt)}
		}
		writeJSON(w, map[string]any{"items": items, "more": more})
	}
}
