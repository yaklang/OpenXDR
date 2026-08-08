package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"openxdr/server/ent"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/sigma"
)

type ruleRow struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity int16  `json:"severity"`
	ClassUID int    `json:"classUid"`
	Product  string `json:"product"`
	// 该类别是否有采集源在供数：false 表示规则加载了但撞不到事件
	Ingested   bool     `json:"ingested"`
	Source     string   `json:"source"`
	Tactics    []string `json:"tactics"`
	Techniques []string `json:"techniques"`
}

// mapRules 检测面透明化：运营要能看到跑着哪些规则、哪些只是摆设。
func mapRules(api *http.ServeMux, rules *sigma.Engine, db *ent.Client, rulesDir string) {
	mapRuleCreate(api, rules, db, rulesDir)
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
				Tactics: rule.Tactics, Techniques: rule.Techniques,
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

// 规则文件名只保留安全字符，路径穿越在这里就不可能发生
var ruleFileName = regexp.MustCompile(`[^a-z0-9_-]+`)

// mapRuleCreate 保存新规则到规则目录，热重载会在下个周期让它生效。
// 落盘前必须过编译器——检测面上不允许存在"看起来在跑"的规则。
func mapRuleCreate(api *http.ServeMux, rules *sigma.Engine, db *ent.Client, rulesDir string) {
	api.HandleFunc("POST /api/rules", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Yaml string `json:"yaml"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || strings.TrimSpace(body.Yaml) == "" {
			http.Error(w, "yaml 必填", http.StatusBadRequest)
			return
		}
		rule, err := sigma.Compile([]byte(body.Yaml))
		if err != nil {
			http.Error(w, "规则编译失败: "+err.Error(), http.StatusBadRequest)
			return
		}
		if rules.TitleOf(rule.ID) != "" {
			http.Error(w, "规则 ID 已存在: "+rule.ID, http.StatusConflict)
			return
		}
		name := ruleFileName.ReplaceAllString(strings.ToLower(rule.ID), "-")
		path := filepath.Join(rulesDir, "hunt_"+name+".yml")
		if _, err := os.Stat(path); err == nil {
			http.Error(w, "同名规则文件已存在", http.StatusConflict)
			return
		}
		if err := os.WriteFile(path, []byte(body.Yaml), 0o644); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "rule_create", rule.ID, rule.Title)
		writeJSON(w, map[string]string{"id": rule.ID, "title": rule.Title})
	})
}
