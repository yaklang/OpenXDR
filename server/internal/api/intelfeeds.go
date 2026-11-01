package api

import (
	"encoding/json"
	"net/http"
	"time"

	"openxdr/server/ent"
	entintel "openxdr/server/ent/intel"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/intel"
)

type feedRow struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	Severity    int16      `json:"severity"`
	Enabled     bool       `json:"enabled"`
	Count       int        `json:"count"`
	Hits        int        `json:"hits"`
	SyncedAt    *time.Time `json:"syncedAt"`
	AttemptedAt *time.Time `json:"attemptedAt"`
	Error       string     `json:"error,omitempty"`
}

// IntelFeeds 情报订阅：各源开关与同步状态、命中过的订阅情报、立即同步。改动只有 admin 能做（见 auth.minRole）。
func IntelFeeds(db *ent.Client, feeds *intel.Feeds) http.Handler {
	mux := http.NewServeMux()
	list := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		settings, err := feeds.Settings(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		status, err := feeds.Status(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		enabled := map[string]bool{}
		for _, id := range settings.Enabled {
			enabled[id] = true
		}
		var counts []struct {
			Source string `json:"source"`
			Count  int    `json:"count"`
			Hits   int    `json:"hits"`
		}
		if err := db.Intel.Query().Where(entintel.SourceHasPrefix("feed:")).
			GroupBy(entintel.FieldSource).
			Aggregate(ent.Count(), ent.As(ent.Sum(entintel.FieldMatchedCount), "hits")).
			Scan(ctx, &counts); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		bySource := map[string]int{}
		hitsBy := map[string]int{}
		for _, c := range counts {
			bySource[c.Source], hitsBy[c.Source] = c.Count, c.Hits
		}
		rows := make([]feedRow, len(intel.Catalog))
		for i, f := range intel.Catalog {
			st := status[f.ID]
			rows[i] = feedRow{f.ID, f.Name, f.URL, f.Severity, enabled[f.ID],
				bySource["feed:"+f.ID], hitsBy["feed:"+f.ID], st.SyncedAt, st.AttemptedAt, st.Error}
		}
		// 命中过的订阅情报：订阅是否起作用，看这里一眼就知道
		hit, err := db.Intel.Query().
			Where(entintel.SourceHasPrefix("feed:"), entintel.MatchedCountGT(0)).
			Order(ent.Desc(entintel.FieldLastMatchedAt)).
			Limit(50).All(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		hits := make([]intelRow, len(hit))
		for i, row := range hit {
			hits[i] = toIntelRow(row)
		}
		writeJSON(w, map[string]any{"feeds": rows, "hits": hits, "intervalHours": int(feeds.Interval.Hours())})
	}
	mux.HandleFunc("GET /api/intel/feeds", list)
	mux.HandleFunc("PUT /api/intel/feeds", func(w http.ResponseWriter, r *http.Request) {
		var body intel.FeedSettings
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		if body.Enabled == nil {
			http.Error(w, "必须提供 enabled 数组；全部关闭请提交空数组", http.StatusBadRequest)
			return
		}
		if err := feeds.SaveSettings(r.Context(), body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		detail, _ := json.Marshal(body.Enabled)
		audit.Log(r.Context(), db, r, "intel_feeds_updated", "intel_feeds", string(detail))
		// 开关即时生效：开的马上拉，关的马上清
		if err := feeds.Sync(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		list(w, r)
	})
	mux.HandleFunc("POST /api/intel/feeds/sync", func(w http.ResponseWriter, r *http.Request) {
		if err := feeds.Sync(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "intel_feeds_synced", "intel_feeds", "")
		list(w, r)
	})
	return mux
}
