package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/schema"
	entsuppression "openxdr/server/ent/suppression"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

type suppressionRow struct {
	ID            uuid.UUID  `json:"id"`
	CreatedAt     time.Time  `json:"createdAt"`
	RuleID        string     `json:"ruleId"`
	RuleTitle     *string    `json:"ruleTitle"`
	AssetID       *uuid.UUID `json:"assetId"`
	Reason        *string    `json:"reason"`
	CreatedBy     string     `json:"createdBy"`
	ExpiresAt     *time.Time `json:"expiresAt"`
	MatchedCount  int        `json:"matchedCount"`
	LastMatchedAt *time.Time `json:"lastMatchedAt"`
	// Status active 生效 / proposed AI 提议待批准 / rejected 已拒绝
	Status     string     `json:"status"`
	SessionID  *uuid.UUID `json:"sessionId"`
	ReviewedBy *string    `json:"reviewedBy"`
	ReviewedAt *time.Time `json:"reviewedAt"`
	// Conditions 字段条件（AND），空表示整条规则
	Conditions []suppress.Condition `json:"conditions"`
	// Evidence 误报统计草案的依据（createdBy = fp-stats），其余为空
	Evidence *schema.SuppressEvidence `json:"evidence"`
}

func mapSuppressions(api *http.ServeMux, db *ent.Client, store *suppress.Store, rules sigma.Catalog) {
	api.HandleFunc("GET /api/suppressions", func(w http.ResponseWriter, r *http.Request) {
		sc, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.Suppression.Query()
		// 非 admin 只看自己组内资产的抑制；全局抑制（无资产）IN 匹配不到，自然排除
		if !sc.all {
			q = q.Where(entsuppression.AssetIDIn(sc.assets...))
		}
		rows, err := q.
			Order(ent.Desc(entsuppression.FieldCreatedAt)).
			Limit(200).
			All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]suppressionRow, len(rows))
		for i, s := range rows {
			row := suppressionRow{
				ID: s.ID, CreatedAt: s.CreatedAt, RuleID: s.RuleID, AssetID: s.AssetID,
				Reason: s.Reason, CreatedBy: s.CreatedBy, ExpiresAt: s.ExpiresAt,
				MatchedCount: s.MatchedCount, LastMatchedAt: s.LastMatchedAt,
				Status: s.Status, SessionID: s.SessionID, ReviewedBy: s.ReviewedBy, ReviewedAt: s.ReviewedAt,
				Conditions: s.Conditions, Evidence: s.Evidence,
			}
			// 列一串 UUID 没法用，带上规则标题
			if title := rules.TitleOf(s.RuleID); title != "" {
				row.RuleTitle = &title
			}
			out[i] = row
		}
		writeJSON(w, out)
	})

	api.HandleFunc("POST /api/suppressions", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RuleID string `json:"ruleId"`
			// 为空表示对所有资产生效——影响面大，界面上要提示清楚
			AssetID *uuid.UUID `json:"assetId"`
			Reason  string     `json:"reason"`
			// 有效期天数，0 表示长期有效
			ExpiresInDays int `json:"expiresInDays"`
			// 只压字段对得上的命中，空表示整条规则
			Conditions []suppress.Condition `json:"conditions"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.RuleID == "" {
			http.Error(w, "ruleId 必填", http.StatusBadRequest)
			return
		}
		if err := suppress.Validate(body.Conditions); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !suppressionAllowed(w, r, db, body.AssetID) {
			return
		}

		create := db.Suppression.Create().
			SetRuleID(body.RuleID).
			SetNillableAssetID(body.AssetID).
			SetCreatedBy(audit.Actor(r.Context()))
		if len(body.Conditions) > 0 {
			create.SetConditions(body.Conditions)
		}
		if body.Reason != "" {
			create.SetReason(body.Reason)
		}
		if body.ExpiresInDays > 0 {
			create.SetExpiresAt(time.Now().AddDate(0, 0, body.ExpiresInDays))
		}
		s, err := create.Save(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// 立即生效，不必等下一个重载周期
		store.Reload(r.Context())
		audit.Log(r.Context(), db, r, "suppression_created", s.ID.String(), body.RuleID)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, suppressionRow{
			ID: s.ID, CreatedAt: s.CreatedAt, RuleID: s.RuleID, AssetID: s.AssetID,
			Reason: s.Reason, CreatedBy: s.CreatedBy, ExpiresAt: s.ExpiresAt, Status: s.Status, Conditions: s.Conditions,
		})
	})

	// AI 提议的抑制由 AI 审计员评审；仍待批准的组管理员也可以手动批准或拒绝，与命令审批同一档权限。批准时有效期从批准那一刻重新算
	api.HandleFunc("POST /api/suppressions/{id}/review", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Decision string `json:"decision"`
			Note     string `json:"note"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || (body.Decision != "approve" && body.Decision != "reject") {
			http.Error(w, "decision 必须是 approve 或 reject", http.StatusBadRequest)
			return
		}
		s, ok := getByPath(w, r, "id", "suppression", db.Suppression.Get)
		if !ok {
			return
		}
		if s.Status != "proposed" || s.AssetID == nil {
			http.Error(w, "只有待批准的提议能审批", http.StatusConflict)
			return
		}
		if !assetInScope(w, r, db, *s.AssetID, "admin") {
			return
		}
		approve := body.Decision == "approve"
		action := "suppression_rejected"
		if approve {
			action = "suppression_approved"
		}
		done, err := suppress.Decide(r.Context(), db, s, approve, audit.Actor(r.Context()), time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !done {
			http.Error(w, "提议已被别人处理", http.StatusConflict)
			return
		}
		store.Reload(r.Context())
		audit.Log(r.Context(), db, r, action, s.ID.String(), s.RuleID+" "+body.Note)
		w.WriteHeader(http.StatusNoContent)
	})

	api.HandleFunc("DELETE /api/suppressions/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 id", http.StatusBadRequest)
			return
		}
		s, err := db.Suppression.Get(r.Context(), id)
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !suppressionAllowed(w, r, db, s.AssetID) {
			return
		}
		err = db.Suppression.DeleteOneID(id).Exec(r.Context())
		if ent.IsNotFound(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		store.Reload(r.Context())
		audit.Log(r.Context(), db, r, "suppression_deleted", id.String(), "")
		w.WriteHeader(http.StatusNoContent)
	})
}

// suppressionAllowed 增删抑制的权限：单资产抑制要求该资产所在组的 analyst，
// 全局抑制影响所有组，只有全局 admin 能动。拒绝时已写好响应。
func suppressionAllowed(w http.ResponseWriter, r *http.Request, db *ent.Client, assetID *uuid.UUID) bool {
	if assetID != nil {
		return assetInScope(w, r, db, *assetID, "analyst")
	}
	if u := auth.From(r.Context()); u == nil || u.Role != "admin" {
		http.Error(w, "全局抑制仅限管理员", http.StatusForbidden)
		return false
	}
	return true
}
