package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entevent "openxdr/server/ent/event"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/eventsearch"
)

const maxEventRows = 200

type eventRow struct {
	ID        uuid.UUID       `json:"id"`
	Ts        time.Time       `json:"ts"`
	ClassUID  int             `json:"classUid"`
	Source    string          `json:"source"`
	AssetID   *uuid.UUID      `json:"assetId"`
	Username  *string         `json:"username"`
	ConnTuple *string         `json:"connTuple"`
	Raw       json.RawMessage `json:"raw"`
	// 这条事件的告警来自登记的可信自动化来源
	Automation *automationRef `json:"automation,omitempty"`
}

// mapEvents 原始事件检索：告警只是线索，取证要能沿着线索翻原始遥测。
// 关键词对整个事件体做子串匹配——分析师拿到的往往是一个 IP、一段命令行、
// 一个文件名，不该要求他先知道字段路径。
func mapEvents(api *http.ServeMux, db *ent.Client) {
	api.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		p := r.URL.Query()
		now := time.Now()

		from := now.Add(-24 * time.Hour)
		if v, err := time.Parse(time.RFC3339, p.Get("from")); err == nil {
			from = v
		}
		to := now
		if v, err := time.Parse(time.RFC3339, p.Get("to")); err == nil {
			to = v
		}

		preds := append([]predicate.Event{entevent.TsGTE(from), entevent.TsLTE(to)}, s.event()...)
		if value := p.Get("assetId"); value != "" {
			id, err := uuid.Parse(value)
			if err != nil {
				http.Error(w, "无效的 assetId", http.StatusBadRequest)
				return
			}
			preds = append(preds, entevent.AssetIDEQ(id))
		}
		if class, err := strconv.Atoi(p.Get("classUid")); err == nil {
			preds = append(preds, entevent.ClassUIDEQ(class))
		}
		if source := p.Get("source"); source != "" {
			preds = append(preds, entevent.SourceEQ(source))
		}

		limit := 100
		if n, err := strconv.Atoi(p.Get("limit")); err == nil && n > 0 && n <= maxEventRows {
			limit = n
		}

		query := func() *ent.EventQuery { return db.Event.Query().Where(preds...) }
		var rows []*ent.Event
		complete := true
		var err error
		if kw := p.Get("q"); kw != "" {
			rows, complete, err = eventsearch.Search(r.Context(), query, eventsearch.Keyword(kw), limit)
		} else {
			rows, err = query().Order(ent.Desc(entevent.FieldTs)).Limit(limit).All(r.Context())
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 取满上限或关键词全量查询超时都说明可能还有更早的，提示前端收窄条件
		if len(rows) == limit || !complete {
			w.Header().Set("X-Truncated", "1")
		}
		ids := make([]uuid.UUID, len(rows))
		for i, e := range rows {
			ids[i] = e.ID
		}
		sources, err := eventAutomation(r.Context(), db, ids)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]eventRow, len(rows))
		for i, e := range rows {
			out[i] = toEventRow(e)
			out[i].Automation = sources[e.ID]
		}
		writeJSON(w, out)
	})
}
