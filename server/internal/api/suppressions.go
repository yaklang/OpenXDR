package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entsuppression "openxdr/server/ent/suppression"
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
}

func mapSuppressions(api *http.ServeMux, db *ent.Client, store *suppress.Store, rules *sigma.Engine) {
	api.HandleFunc("GET /api/suppressions", func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Suppression.Query().
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
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.RuleID == "" {
			http.Error(w, "ruleId 必填", http.StatusBadRequest)
			return
		}

		create := db.Suppression.Create().
			SetRuleID(body.RuleID).
			SetNillableAssetID(body.AssetID).
			SetCreatedBy(issuer(r))
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
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, suppressionRow{
			ID: s.ID, CreatedAt: s.CreatedAt, RuleID: s.RuleID, AssetID: s.AssetID,
			Reason: s.Reason, CreatedBy: s.CreatedBy, ExpiresAt: s.ExpiresAt,
		})
	})

	api.HandleFunc("DELETE /api/suppressions/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的 id", http.StatusBadRequest)
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
		w.WriteHeader(http.StatusNoContent)
	})
}
