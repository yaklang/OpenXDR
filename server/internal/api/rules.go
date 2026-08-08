package api

import (
	"net/http"
	"sort"

	"openxdr/server/internal/sigma"
)

type ruleRow struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity int16  `json:"severity"`
	ClassUID int    `json:"classUid"`
	Product  string `json:"product"`
	// 该类别是否有采集源在供数：false 表示规则加载了但撞不到事件
	Ingested bool   `json:"ingested"`
	Source   string `json:"source"`
}

// mapRules 检测面透明化：运营要能看到跑着哪些规则、哪些只是摆设。
func mapRules(api *http.ServeMux, rules *sigma.Engine) {
	api.HandleFunc("GET /api/rules", func(w http.ResponseWriter, r *http.Request) {
		all := rules.Rules()
		out := make([]ruleRow, len(all))
		for i, rule := range all {
			source, ingested := sigma.IngestedClass(rule.ClassUID)
			// 不限 class 的规则对所有事件求值，永远有数据
			if rule.ClassUID == 0 {
				ingested, source = true, "全部类别"
			}
			out[i] = ruleRow{
				ID: rule.ID, Title: rule.Title, Severity: rule.Severity,
				ClassUID: rule.ClassUID, Product: rule.Product,
				Ingested: ingested, Source: source,
			}
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Severity != out[j].Severity {
				return out[i].Severity > out[j].Severity
			}
			return out[i].Title < out[j].Title
		})
		writeJSON(w, out)
	})
}
