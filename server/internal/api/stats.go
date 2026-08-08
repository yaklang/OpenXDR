package api

import (
	"net/http"
	"sort"
	"time"

	"openxdr/server/ent"
	entalert "openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	entevent "openxdr/server/ent/event"
	entincident "openxdr/server/ent/incident"
)

// 与前端资产清单的在线判定保持一致：5 分钟内有心跳算在线
const onlineWindow = 5 * time.Minute

type trendBucket struct {
	Hour  time.Time `json:"hour"`
	Count int       `json:"count"`
}

type topRule struct {
	RuleID    string  `json:"ruleId"`
	RuleTitle *string `json:"ruleTitle"`
	Count     int     `json:"count"`
}

type statsResponse struct {
	// 降噪漏斗：原始事件 → 去重后告警 → 待处理事件
	Events24h         int            `json:"events24h"`
	Alerts24h         int            `json:"alerts24h"`
	OpenIncidents     int            `json:"openIncidents"`
	IncidentsByStatus map[string]int `json:"incidentsByStatus"`
	AlertTrend        []trendBucket  `json:"alertTrend"`
	TopRules          []topRule      `json:"topRules"`
	AssetsTotal       int            `json:"assetsTotal"`
	AssetsOnline      int            `json:"assetsOnline"`
}

func mapStats(api *http.ServeMux, db *ent.Client, rules ruleTitler) {
	api.HandleFunc("GET /api/stats", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		now := time.Now()
		since := now.Add(-24 * time.Hour)
		out := statsResponse{
			IncidentsByStatus: map[string]int{},
			AlertTrend:        make([]trendBucket, 24),
		}

		var err error
		if out.Events24h, err = db.Event.Query().Where(entevent.TsGTE(since)).Count(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 状态分布
		var byStatus []struct {
			Status string `json:"status"`
			Count  int    `json:"count"`
		}
		if err := db.Incident.Query().
			GroupBy(entincident.FieldStatus).
			Aggregate(ent.Count()).
			Scan(ctx, &byStatus); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, s := range byStatus {
			out.IncidentsByStatus[s.Status] = s.Count
		}
		out.OpenIncidents = out.IncidentsByStatus["open"] + out.IncidentsByStatus["triaged"]

		// 24h 告警：一次取回 ts 与 count，趋势分桶在内存里做。
		// 告警是去重后的产物，量级与事件表差着窗口倍数，直接拉没有压力。
		alerts, err := db.Alert.Query().
			Where(entalert.TsGTE(since)).
			Select(entalert.FieldTs, entalert.FieldCount).
			All(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		base := now.Truncate(time.Hour).Add(-23 * time.Hour)
		for i := range out.AlertTrend {
			out.AlertTrend[i].Hour = base.Add(time.Duration(i) * time.Hour)
		}
		for _, a := range alerts {
			out.Alerts24h += a.Count
			if idx := int(a.Ts.Sub(base) / time.Hour); idx >= 0 && idx < 24 {
				out.AlertTrend[idx].Count += a.Count
			}
		}

		// Top 规则（按去重后计数求和）
		var top []struct {
			RuleID string `json:"rule_id"`
			Sum    int    `json:"sum"`
		}
		if err := db.Alert.Query().
			Where(entalert.TsGTE(since)).
			GroupBy(entalert.FieldRuleID).
			Aggregate(ent.Sum(entalert.FieldCount)).
			Scan(ctx, &top); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, t := range top {
			rule := topRule{RuleID: t.RuleID, Count: t.Sum}
			if title := rules.TitleOf(t.RuleID); title != "" {
				rule.RuleTitle = &title
			}
			out.TopRules = append(out.TopRules, rule)
		}
		// GroupBy 不带排序保证，内存里排一下取前五
		sort.Slice(out.TopRules, func(i, j int) bool { return out.TopRules[i].Count > out.TopRules[j].Count })
		if len(out.TopRules) > 5 {
			out.TopRules = out.TopRules[:5]
		}

		if out.AssetsTotal, err = db.Asset.Query().Count(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if out.AssetsOnline, err = db.Asset.Query().
			Where(entasset.LastSeenGTE(now.Add(-onlineWindow))).
			Count(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, out)
	})
}

// ruleTitler 只取标题，避免 stats 依赖整个 sigma 引擎的接口面。
type ruleTitler interface {
	TitleOf(id string) string
}
