package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/ent/finding"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/findings"
)

type findingRow struct {
	ID         uuid.UUID  `json:"id"`
	GroupID    uuid.UUID  `json:"groupId"`
	AssetID    uuid.UUID  `json:"assetId"`
	Hostname   string     `json:"hostname"`
	Key        string     `json:"key"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail"`
	Severity   string     `json:"severity"`
	Status     string     `json:"status"`
	FirstSeen  time.Time  `json:"firstSeen"`
	LastSeen   time.Time  `json:"lastSeen"`
	SessionID  *uuid.UUID `json:"sessionId"`
	ResolvedAt *time.Time `json:"resolvedAt"`
	ResolvedBy *string    `json:"resolvedBy"`
	Note       *string    `json:"note"`
}

// mapFindings 运维待办：巡检 AI 登记与复查，人在这里标记已处理或忽略。忽略的 AI 不再登记。
func mapFindings(mux *http.ServeMux, db *ent.Client) {
	mux.HandleFunc("GET /api/findings", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.Finding.Query()
		if !s.all {
			q = q.Where(finding.GroupIDIn(s.groups...))
		}
		if v := r.URL.Query().Get("assetId"); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				http.Error(w, "无效的 assetId", http.StatusBadRequest)
				return
			}
			q = q.Where(finding.AssetIDEQ(id))
		}
		if status := r.URL.Query().Get("status"); status != "" {
			q = q.Where(finding.StatusEQ(status))
		}
		if values, present := r.URL.Query()["ids"]; present {
			parts := strings.Split(strings.Join(values, ","), ",")
			if len(parts) > 10 {
				http.Error(w, "一次最多查询 10 条待办", http.StatusBadRequest)
				return
			}
			ids := make([]uuid.UUID, len(parts))
			for i, part := range parts {
				id, err := uuid.Parse(part)
				if err != nil {
					http.Error(w, "无效的待办 ID", http.StatusBadRequest)
					return
				}
				ids[i] = id
			}
			q = q.Where(finding.IDIn(ids...))
		}
		limit, offset := 500, 0
		if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil {
			limit = min(max(n, 1), 500)
		}
		if n, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && n > 0 {
			offset = n
		}
		total, err := q.Clone().Count(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rows, err := q.Order(ent.Desc(finding.FieldLastSeen), ent.Desc(finding.FieldID)).Limit(limit).Offset(offset).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ids := make([]uuid.UUID, len(rows))
		for i, f := range rows {
			ids[i] = f.AssetID
		}
		assets, err := db.Asset.Query().Where(entasset.IDIn(ids...)).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		names := map[uuid.UUID]string{}
		for _, a := range assets {
			names[a.ID] = a.Hostname
		}
		out := make([]findingRow, len(rows))
		for i, f := range rows {
			out[i] = findingRow{f.ID, f.GroupID, f.AssetID, names[f.AssetID], f.Key, f.Title, f.Detail, f.Severity,
				f.Status, f.FirstSeen, f.LastSeen, f.SessionID, f.ResolvedAt, f.ResolvedBy, f.Note}
		}
		w.Header().Set("X-Total-Count", strconv.Itoa(total))
		if len(rows) < total-offset {
			w.Header().Set("X-Truncated", "1")
		}
		writeJSON(w, out)
	})

	// 已处理与忽略必须写原因（findings.Clean）；对话里代人忽略也走 findings.Set，口径一致
	mux.HandleFunc("POST /api/findings/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的待办 id", http.StatusBadRequest)
			return
		}
		var body struct {
			Status string `json:"status"`
			Note   string `json:"note"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "请求格式错误", http.StatusBadRequest)
			return
		}
		note, err := findings.Clean(body.Status, body.Note)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f, err := db.Finding.Get(r.Context(), id)
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !requireGroup(w, r, db, f.GroupID, "analyst") {
			return
		}
		if err := findings.Set(r.Context(), db, f, body.Status, note, auth.From(r.Context()).Username, audit.RemoteAddr(r), ""); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
