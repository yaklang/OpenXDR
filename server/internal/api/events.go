package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	entevent "openxdr/server/ent/event"
	"openxdr/server/ent/predicate"
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
}

// mapEvents 原始事件检索：告警只是线索，取证要能沿着线索翻原始遥测。
// 关键词对整个事件体做子串匹配——分析师拿到的往往是一个 IP、一段命令行、
// 一个文件名，不该要求他先知道字段路径。
func mapEvents(api *http.ServeMux, db *ent.Client) {
	api.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
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

		preds := []predicate.Event{entevent.TsGTE(from), entevent.TsLTE(to)}
		if id, err := uuid.Parse(p.Get("assetId")); err == nil {
			preds = append(preds, entevent.AssetIDEQ(id))
		}
		if class, err := strconv.Atoi(p.Get("classUid")); err == nil {
			preds = append(preds, entevent.ClassUIDEQ(class))
		}
		if source := p.Get("source"); source != "" {
			preds = append(preds, entevent.SourceEQ(source))
		}
		if kw := p.Get("q"); kw != "" {
			pattern := "%" + escapeLike(kw) + "%"
			preds = append(preds, predicate.Event(func(s *sql.Selector) {
				s.Where(sql.P(func(b *sql.Builder) {
					b.WriteString(s.C(entevent.FieldRaw)).WriteString("::text ILIKE ").Arg(pattern)
				}))
			}))
		}

		limit := 100
		if n, err := strconv.Atoi(p.Get("limit")); err == nil && n > 0 && n <= maxEventRows {
			limit = n
		}

		rows, err := db.Event.Query().
			Where(preds...).
			Order(ent.Desc(entevent.FieldTs)).
			Limit(limit).
			All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		out := make([]eventRow, len(rows))
		for i, e := range rows {
			out[i] = eventRow{
				ID: e.ID, Ts: e.Ts, ClassUID: e.ClassUID, Source: e.Source,
				AssetID: e.AssetID, Username: e.Username, ConnTuple: e.ConnTuple,
				Raw: e.Raw,
			}
		}
		writeJSON(w, out)
	})
}

// escapeLike 关键词是字面量，% _ \ 要转义，不能让用户输入变成通配符。
func escapeLike(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '%' || c == '_' || c == '\\' {
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(out)
}
