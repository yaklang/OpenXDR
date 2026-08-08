package api

import (
	"net/http"
	"sort"

	"openxdr/server/internal/sigma"
)

type techniqueCell struct {
	ID string `json:"id"`
	// 该技术下的规则数；hasData 表示至少有一条规则的类别有采集源供数
	Rules   int  `json:"rules"`
	HasData bool `json:"hasData"`
}

type tacticColumn struct {
	Tactic     string          `json:"tactic"`
	Rules      int             `json:"rules"`
	Techniques []techniqueCell `json:"techniques"`
}

type attackCoverage struct {
	Tactics []tacticColumn `json:"tactics"`
	// 没打 ATT&CK 标签的规则数：矩阵看不见它们，运营需要知道有多少
	Untagged int `json:"untagged"`
	// 有规则但对应类别无采集源的规则数——纸面覆盖与真实覆盖的差额
	NoDataSource int `json:"noDataSource"`
}

// mapAttack ATT&CK 覆盖矩阵。回答的是"我们防住了哪几环"，
// 以及更重要的"哪些格子看着有规则其实没数据供数"。
func mapAttack(api *http.ServeMux, rules *sigma.Engine) {
	api.HandleFunc("GET /api/attack", func(w http.ResponseWriter, r *http.Request) {
		type agg struct {
			rules   int
			hasData bool
		}
		byTactic := map[string]int{}
		byTechnique := map[string]map[string]*agg{}
		out := attackCoverage{}

		for _, rule := range rules.Rules() {
			_, ingested := sigma.IngestedClass(rule.ClassUID)
			if rule.ClassUID == 0 {
				ingested = true
			}
			if len(rule.Tactics) == 0 && len(rule.Techniques) == 0 {
				out.Untagged++
				continue
			}
			if !ingested {
				out.NoDataSource++
			}
			for _, tactic := range rule.Tactics {
				byTactic[tactic]++
				if byTechnique[tactic] == nil {
					byTechnique[tactic] = map[string]*agg{}
				}
				// 技术挂在同一条规则声明的每个战术下——一条规则可以横跨多环
				for _, tech := range rule.Techniques {
					cell := byTechnique[tactic][tech]
					if cell == nil {
						cell = &agg{}
						byTechnique[tactic][tech] = cell
					}
					cell.rules++
					cell.hasData = cell.hasData || ingested
				}
			}
		}

		// 全部战术都出现在矩阵里，包括零覆盖的——空列才是要看的东西
		for _, tactic := range sigma.Tactics() {
			col := tacticColumn{Tactic: tactic, Rules: byTactic[tactic]}
			for id, cell := range byTechnique[tactic] {
				col.Techniques = append(col.Techniques, techniqueCell{
					ID: id, Rules: cell.rules, HasData: cell.hasData,
				})
			}
			sort.Slice(col.Techniques, func(i, j int) bool {
				return col.Techniques[i].ID < col.Techniques[j].ID
			})
			out.Tactics = append(out.Tactics, col)
		}
		writeJSON(w, out)
	})
}
