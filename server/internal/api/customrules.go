package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/customrule"
	"openxdr/server/internal/sigma"
)

type customRuleRow struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Severity  int16     `json:"severity"`
	Enabled   bool      `json:"enabled"`
	Content   string    `json:"content"`
	CreatedBy string    `json:"createdBy"`
	UpdatedBy string    `json:"updatedBy"`
	UpdatedAt time.Time `json:"updatedAt"`
	// 本节点加载失败的原因（升级后旧写法不再支持等），空表示正常
	Error string `json:"error,omitempty"`
}

type customRuleBody struct {
	Content string `json:"content"`
	Enabled bool   `json:"enabled"`
}

// CustomRules 控制台自定义 Sigma 规则：读对所有人开放，增删改与草稿检查只有全局 admin（见 auth.minRole），
// 改完本节点立即重载，其他节点在下一个重载周期生效。
func CustomRules(db *ent.Client, rules *sigma.Overlay, loader *customrule.Loader) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/custom-rules", listCustomRules(db, rules, loader))
	mux.HandleFunc("POST /api/custom-rules/check", checkCustomRule(db, rules))
	mux.HandleFunc("POST /api/custom-rules", saveCustomRule(db, rules, loader, ""))
	mux.HandleFunc("PUT /api/custom-rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		saveCustomRule(db, rules, loader, r.PathValue("id"))(w, r)
	})
	mux.HandleFunc("DELETE /api/custom-rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := db.CustomRule.DeleteOneID(id).Exec(r.Context()); err != nil {
			customRuleError(w, err)
			return
		}
		audit.Log(r.Context(), db, r, "custom_rule_deleted", id, "")
		reloadCustomRules(r, loader)
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func listCustomRules(db *ent.Client, rules *sigma.Overlay, loader *customrule.Loader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.CustomRule.Query().All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		failed := loader.Failed()
		out := make([]customRuleRow, len(rows))
		for i, c := range rows {
			out[i] = customRuleRow{ID: c.ID, Enabled: c.Enabled, Content: c.Content, CreatedBy: c.CreatedBy, UpdatedBy: c.UpdatedBy, UpdatedAt: c.UpdatedAt, Error: failed[c.ID]}
			if rule, err := rules.CheckCustom([]byte(c.Content)); err == nil {
				out[i].Title, out[i].Severity = rule.Title, rule.Severity
			} else if out[i].Error == "" {
				out[i].Error = err.Error()
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
		writeJSON(w, out)
	}
}

func decodeCustomRule(w http.ResponseWriter, r *http.Request, rules *sigma.Overlay) (customRuleBody, *sigma.Rule, bool) {
	var body customRuleBody
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body) != nil {
		http.Error(w, "请求无效", http.StatusBadRequest)
		return body, nil, false
	}
	rule, err := rules.CheckCustom([]byte(body.Content))
	if err != nil {
		http.Error(w, "规则无效："+err.Error(), http.StatusBadRequest)
		return body, nil, false
	}
	return body, rule, true
}

// checkCustomRule 草稿检查：能否加载，加载得了就在本组可见的近期事件上回测
func checkCustomRule(db *ent.Client, rules *sigma.Overlay) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, rule, ok := decodeCustomRule(w, r, rules)
		if !ok {
			return
		}
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		backtest(w, r, db, s, rule)
	}
}

// saveCustomRule id 为空是新建；修改时原文 id 必须与路径一致（id 是主键，换 id 请新建）
func saveCustomRule(db *ent.Client, rules *sigma.Overlay, loader *customrule.Loader, id string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, rule, ok := decodeCustomRule(w, r, rules)
		if !ok {
			return
		}
		actor := auth.From(r.Context()).Username
		var err error
		if id == "" {
			err = db.CustomRule.Create().SetID(rule.ID).SetContent(body.Content).SetEnabled(body.Enabled).
				SetCreatedBy(actor).SetUpdatedBy(actor).Exec(r.Context())
			if ent.IsConstraintError(err) {
				http.Error(w, "已有同 id 的自定义规则", http.StatusConflict)
				return
			}
		} else {
			if rule.ID != id {
				http.Error(w, "不能修改规则 id，换 id 请新建", http.StatusBadRequest)
				return
			}
			err = db.CustomRule.UpdateOneID(id).SetContent(body.Content).SetEnabled(body.Enabled).SetUpdatedBy(actor).Exec(r.Context())
		}
		if err != nil {
			customRuleError(w, err)
			return
		}
		detail, _ := json.Marshal(map[string]any{"title": rule.Title, "enabled": body.Enabled})
		audit.Log(r.Context(), db, r, map[bool]string{true: "custom_rule_created", false: "custom_rule_updated"}[id == ""], rule.ID, string(detail))
		reloadCustomRules(r, loader)
		writeJSON(w, map[string]string{"id": rule.ID})
	}
}

// reloadCustomRules 本节点立即生效；失败不影响已保存的结果，下一个周期会再读
func reloadCustomRules(r *http.Request, loader *customrule.Loader) {
	if err := loader.Reload(r.Context()); err != nil {
		slog.Warn("自定义规则保存后重载失败，等下一个周期", "err", err)
	}
}

func customRuleError(w http.ResponseWriter, err error) {
	if ent.IsNotFound(err) {
		http.Error(w, "自定义规则不存在", http.StatusNotFound)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
