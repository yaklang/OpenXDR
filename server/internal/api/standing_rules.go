package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/group"
	"openxdr/server/ent/standingrule"
	"openxdr/server/ent/standingrulerun"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/standingrules"
)

type standingRuleRow struct {
	ID                  uuid.UUID      `json:"id"`
	Ref                 string         `json:"ref"`
	CreatedAt           time.Time      `json:"createdAt"`
	UpdatedAt           time.Time      `json:"updatedAt"`
	BuiltinKey          string         `json:"builtinKey"`
	Name                string         `json:"name"`
	ConditionSummary    string         `json:"conditionSummary"`
	Condition           map[string]any `json:"condition,omitempty"`
	ActionTemplate      string         `json:"actionTemplate"`
	ActionParams        map[string]any `json:"actionParams,omitempty"`
	Tier                string         `json:"tier"`
	AllowedTiers        []string       `json:"allowedTiers"`
	RollbackHint        string         `json:"rollbackHint"`
	GroupID             *uuid.UUID     `json:"groupId"`
	GroupName           string         `json:"groupName,omitempty"`
	AssetIDs            []uuid.UUID    `json:"assetIds"`
	Hostnames           []string       `json:"hostnames,omitempty"`
	MaintenanceWindow   string         `json:"maintenanceWindow"`
	CooldownMinutes     int            `json:"cooldownMinutes"`
	CreatedBy           string         `json:"createdBy"`
	CreatedByName       string         `json:"createdByName"`
	Enabled             bool           `json:"enabled"`
	ConsecutiveFailures int            `json:"consecutiveFailures"`
	DegradedAt          *time.Time     `json:"degradedAt"`
	DegradedReason      string         `json:"degradedReason,omitempty"`
	LastRunAt           *time.Time     `json:"lastRunAt"`
	LastRunStatus       string         `json:"lastRunStatus"`
	HitsToday           int            `json:"hitsToday"`
	Hits30d             int            `json:"hits30d"`
	AutoToday           int            `json:"autoToday"`
}

type standingRuleRunRow struct {
	ID          uuid.UUID  `json:"id"`
	CreatedAt   time.Time  `json:"createdAt"`
	CompletedAt *time.Time `json:"completedAt"`
	RuleID      uuid.UUID  `json:"ruleId"`
	GroupID     uuid.UUID  `json:"groupId"`
	AssetID     uuid.UUID  `json:"assetId"`
	Hostname    string     `json:"hostname"`
	FindingID   *uuid.UUID `json:"findingId"`
	Tier        string     `json:"tier"`
	Status      string     `json:"status"`
	HitSummary  string     `json:"hitSummary"`
	Command     string     `json:"command"`
	CommandID   *uuid.UUID `json:"commandId"`
	ApprovalID  *uuid.UUID `json:"approvalId"`
	Result      string     `json:"result"`
	Rollback    string     `json:"rollback"`
}

func groupNamesOf(ctx context.Context, db *ent.Client, ids []uuid.UUID) map[uuid.UUID]string {
	out := map[uuid.UUID]string{}
	if len(ids) == 0 {
		return out
	}
	rows, _ := db.Group.Query().Where(group.IDIn(ids...)).Select(group.FieldID, group.FieldName).All(ctx)
	for _, g := range rows {
		out[g.ID] = g.Name
	}
	return out
}

func requireStandingAdmin(w http.ResponseWriter, r *http.Request, db *ent.Client) (*ent.User, bool) {
	u := auth.From(r.Context())
	if u == nil {
		http.Error(w, "需要登录", http.StatusForbidden)
		return nil, false
	}
	cur, err := db.User.Get(r.Context(), u.ID)
	if err != nil || cur.Role != "admin" {
		http.Error(w, "只有平台管理员能修改常设规矩与档位", http.StatusForbidden)
		return nil, false
	}
	return cur, true
}

func registerStandingRuleRoutes(mux *http.ServeMux, db *ent.Client) {
	mux.HandleFunc("GET /api/standing-rules/templates", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireScope(w, r, db, "viewer"); !ok {
			return
		}
		writeJSON(w, standingrules.Templates())
	})

	mux.HandleFunc("GET /api/standing-rules", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.StandingRule.Query()
		if !s.all {
			q = q.Where(standingrule.Or(standingrule.GroupIDIsNil(), standingrule.GroupIDIn(s.groups...)))
		}
		rows, err := q.Order(ent.Desc(standingrule.FieldBuiltinKey), ent.Asc(standingrule.FieldCreatedAt)).Limit(500).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, buildStandingRuleRows(r.Context(), db, rows, s))
	})

	mux.HandleFunc("POST /api/standing-rules", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := requireStandingAdmin(w, r, db)
		if !ok {
			return
		}
		var body struct {
			Name              string         `json:"name"`
			ConditionSummary  string         `json:"conditionSummary"`
			Condition         map[string]any `json:"condition"`
			ActionTemplate    string         `json:"actionTemplate"`
			ActionParams      map[string]any `json:"actionParams"`
			Tier              string         `json:"tier"`
			GroupID           *uuid.UUID     `json:"groupId"`
			AssetIDs          []uuid.UUID    `json:"assetIds"`
			MaintenanceWindow string         `json:"maintenanceWindow"`
			CooldownMinutes   int            `json:"cooldownMinutes"`
			Enabled           bool           `json:"enabled"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		tpl, exists := standingrules.LookupTemplate(body.ActionTemplate)
		if !exists {
			http.Error(w, "不支持的动作模板", http.StatusBadRequest)
			return
		}
		if body.CooldownMinutes == 0 {
			body.CooldownMinutes = tpl.DefaultCooldown
		}
		if strings.TrimSpace(body.Tier) == "" {
			body.Tier = tpl.DefaultTier
		}
		if strings.TrimSpace(body.Name) == "" {
			body.Name = tpl.Name
		}
		if strings.TrimSpace(body.ConditionSummary) == "" {
			body.ConditionSummary = tpl.ConditionSummary
		}
		in := standingrules.RuleInput{
			Name:              strings.TrimSpace(body.Name),
			ConditionSummary:  strings.TrimSpace(body.ConditionSummary),
			Condition:         body.Condition,
			ActionTemplate:    body.ActionTemplate,
			ActionParams:      body.ActionParams,
			Tier:              strings.TrimSpace(body.Tier),
			GroupID:           body.GroupID,
			AssetIDs:          body.AssetIDs,
			MaintenanceWindow: strings.TrimSpace(body.MaintenanceWindow),
			CooldownMinutes:   body.CooldownMinutes,
			Enabled:           body.Enabled,
		}
		if err := standingrules.ValidateInput(r.Context(), db, in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var created *ent.StandingRule
		err := withTx(r, db, func(tx *ent.Tx) error {
			c := tx.StandingRule.Create().
				SetName(in.Name).
				SetConditionSummary(in.ConditionSummary).
				SetActionTemplate(in.ActionTemplate).
				SetTier(standingrule.Tier(in.Tier)).
				SetNillableGroupID(in.GroupID).
				SetAssetIds(in.AssetIDs).
				SetMaintenanceWindow(in.MaintenanceWindow).
				SetCooldownMinutes(in.CooldownMinutes).
				SetCreatedBy("user:" + actor.Username).
				SetEnabled(in.Enabled)
			if in.Condition != nil {
				c.SetCondition(in.Condition)
			}
			if in.ActionParams != nil {
				c.SetActionParams(in.ActionParams)
			}
			var err error
			created, err = c.Save(r.Context())
			if err != nil {
				return err
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor.Username, audit.RemoteAddr(r), "standing_rule_created", created.ID.String(),
				fmt.Sprintf("ref=%s tpl=%s tier=%s enabled=%v name=%s", standingrules.Ref(created.ID), created.ActionTemplate, created.Tier, created.Enabled, created.Name))
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		rows := buildStandingRuleRows(r.Context(), db, []*ent.StandingRule{created}, scope{all: true})
		writeJSON(w, rows[0])
	})

	mux.HandleFunc("PATCH /api/standing-rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := requireStandingAdmin(w, r, db)
		if !ok {
			return
		}
		row, ok := getByPath(w, r, "id", "standing_rule", db.StandingRule.Get)
		if !ok {
			return
		}
		var body struct {
			Name              *string         `json:"name"`
			ConditionSummary  *string         `json:"conditionSummary"`
			Condition         *map[string]any `json:"condition"`
			ActionParams      *map[string]any `json:"actionParams"`
			Tier              *string         `json:"tier"`
			GroupID           *uuid.UUID      `json:"groupId"`
			ClearGroup        bool            `json:"clearGroup"`
			AssetIDs          *[]uuid.UUID    `json:"assetIds"`
			MaintenanceWindow *string         `json:"maintenanceWindow"`
			CooldownMinutes   *int            `json:"cooldownMinutes"`
			Enabled           *bool           `json:"enabled"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		in := standingrules.RuleInput{
			BuiltinKey:        row.BuiltinKey,
			Name:              row.Name,
			ConditionSummary:  row.ConditionSummary,
			Condition:         row.Condition,
			ActionTemplate:    row.ActionTemplate,
			ActionParams:      row.ActionParams,
			Tier:              string(row.Tier),
			GroupID:           row.GroupID,
			AssetIDs:          row.AssetIds,
			MaintenanceWindow: row.MaintenanceWindow,
			CooldownMinutes:   row.CooldownMinutes,
			Enabled:           row.Enabled,
		}
		if body.Name != nil {
			in.Name = strings.TrimSpace(*body.Name)
		}
		if body.ConditionSummary != nil {
			in.ConditionSummary = strings.TrimSpace(*body.ConditionSummary)
		}
		if body.Condition != nil {
			in.Condition = *body.Condition
		}
		if body.ActionParams != nil {
			in.ActionParams = *body.ActionParams
		}
		if body.Tier != nil {
			in.Tier = strings.TrimSpace(*body.Tier)
		}
		if body.ClearGroup {
			in.GroupID = nil
		} else if body.GroupID != nil {
			in.GroupID = body.GroupID
		}
		if body.AssetIDs != nil {
			in.AssetIDs = *body.AssetIDs
		}
		if body.MaintenanceWindow != nil {
			in.MaintenanceWindow = strings.TrimSpace(*body.MaintenanceWindow)
		}
		if body.CooldownMinutes != nil {
			in.CooldownMinutes = *body.CooldownMinutes
		}
		if body.Enabled != nil {
			in.Enabled = *body.Enabled
		}
		if err := standingrules.ValidateInput(r.Context(), db, in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		oldTier := string(row.Tier)
		oldEnabled := row.Enabled
		var updated *ent.StandingRule
		err := withTx(r, db, func(tx *ent.Tx) error {
			u := tx.StandingRule.UpdateOneID(row.ID).
				SetName(in.Name).
				SetConditionSummary(in.ConditionSummary).
				SetTier(standingrule.Tier(in.Tier)).
				SetAssetIds(in.AssetIDs).
				SetMaintenanceWindow(in.MaintenanceWindow).
				SetCooldownMinutes(in.CooldownMinutes).
				SetEnabled(in.Enabled)
			if in.GroupID == nil {
				u.ClearGroupID()
			} else {
				u.SetGroupID(*in.GroupID)
			}
			if in.Condition != nil {
				u.SetCondition(in.Condition)
			}
			if in.ActionParams != nil {
				u.SetActionParams(in.ActionParams)
			}
			// 管理员显式切档或重新启用时，清除连续出错降级标记
			if in.Tier != oldTier || (in.Enabled && !oldEnabled) {
				u.SetConsecutiveFailures(0).ClearDegradedAt().SetDegradedReason("")
			}
			var err error
			updated, err = u.Save(r.Context())
			if err != nil {
				return err
			}
			action := "standing_rule_updated"
			if in.Tier != oldTier {
				action = "standing_rule_tier_changed"
			}
			detail := fmt.Sprintf("ref=%s tier=%s->%s enabled=%v->%v window=%q cooldown=%d",
				standingrules.Ref(row.ID), oldTier, in.Tier, oldEnabled, in.Enabled, in.MaintenanceWindow, in.CooldownMinutes)
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor.Username, audit.RemoteAddr(r), action, row.ID.String(), detail)
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rows := buildStandingRuleRows(r.Context(), db, []*ent.StandingRule{updated}, scope{all: true})
		writeJSON(w, rows[0])
	})

	mux.HandleFunc("DELETE /api/standing-rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := requireStandingAdmin(w, r, db)
		if !ok {
			return
		}
		row, ok := getByPath(w, r, "id", "standing_rule", db.StandingRule.Get)
		if !ok {
			return
		}
		if row.BuiltinKey != "" {
			http.Error(w, "内置常设规矩不可删除，请直接停用", http.StatusBadRequest)
			return
		}
		err := withTx(r, db, func(tx *ent.Tx) error {
			if _, err := tx.StandingRuleRun.Delete().Where(standingrulerun.RuleIDEQ(row.ID)).Exec(r.Context()); err != nil {
				return err
			}
			if err := tx.StandingRule.DeleteOneID(row.ID).Exec(r.Context()); err != nil {
				return err
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor.Username, audit.RemoteAddr(r), "standing_rule_deleted", row.ID.String(),
				fmt.Sprintf("ref=%s name=%s", standingrules.Ref(row.ID), row.Name))
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /api/standing-rules/{id}/runs", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		ruleRow, ok := getByPath(w, r, "id", "standing_rule", db.StandingRule.Get)
		if !ok {
			return
		}
		if !s.all && ruleRow.GroupID != nil && !slices.Contains(s.groups, *ruleRow.GroupID) {
			http.Error(w, "无该组查看权限", http.StatusForbidden)
			return
		}
		q := db.StandingRuleRun.Query().Where(standingrulerun.RuleIDEQ(ruleRow.ID))
		if !s.all {
			q = q.Where(standingrulerun.GroupIDIn(s.groups...))
		}
		if r.URL.Query().Get("skipped") != "1" {
			q = q.Where(standingrulerun.StatusNEQ(standingrulerun.StatusSkipped))
		}
		runs, err := q.Order(ent.Desc(standingrulerun.FieldCreatedAt)).Limit(100).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var assetIDs []uuid.UUID
		for _, run := range runs {
			assetIDs = append(assetIDs, run.AssetID)
		}
		names := hostnamesOf(r.Context(), db, assetIDs)
		out := make([]standingRuleRunRow, len(runs))
		for i, run := range runs {
			out[i] = standingRuleRunRow{
				ID:          run.ID,
				CreatedAt:   run.CreatedAt,
				CompletedAt: run.CompletedAt,
				RuleID:      run.RuleID,
				GroupID:     run.GroupID,
				AssetID:     run.AssetID,
				Hostname:    names[run.AssetID],
				FindingID:   run.FindingID,
				Tier:        run.Tier,
				Status:      string(run.Status),
				HitSummary:  run.HitSummary,
				Command:     run.Command,
				CommandID:   run.CommandID,
				ApprovalID:  run.ApprovalID,
				Result:      run.Result,
				Rollback:    run.Rollback,
			}
		}
		writeJSON(w, out)
	})
}

func buildStandingRuleRows(ctx context.Context, db *ent.Client, rows []*ent.StandingRule, s scope) []standingRuleRow {
	if len(rows) == 0 {
		return []standingRuleRow{}
	}
	var ruleIDs, groupIDs, assetIDs []uuid.UUID
	var creators []string
	for _, r := range rows {
		ruleIDs = append(ruleIDs, r.ID)
		if r.GroupID != nil {
			groupIDs = append(groupIDs, *r.GroupID)
		}
		assetIDs = append(assetIDs, r.AssetIds...)
		creators = append(creators, r.CreatedBy)
	}
	hosts := hostnamesOf(ctx, db, assetIDs)
	groups := groupNamesOf(ctx, db, groupIDs)
	who := principalNames(ctx, db, creators...)

	now := time.Now()
	local := now.In(time.Local)
	midnight := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.Local)
	since30d := now.Add(-30 * 24 * time.Hour)

	runQ := db.StandingRuleRun.Query().Where(
		standingrulerun.RuleIDIn(ruleIDs...),
		standingrulerun.CreatedAtGTE(since30d),
		standingrulerun.StatusNEQ(standingrulerun.StatusSkipped),
	)
	if !s.all {
		runQ = runQ.Where(standingrulerun.GroupIDIn(s.groups...))
	}
	recentRuns, _ := runQ.Select(
		standingrulerun.FieldRuleID,
		standingrulerun.FieldCreatedAt,
		standingrulerun.FieldTier,
		standingrulerun.FieldStatus,
	).All(ctx)

	type hitStat struct{ today, d30, autoToday int }
	stats := map[uuid.UUID]hitStat{}
	for _, run := range recentRuns {
		st := stats[run.RuleID]
		st.d30++
		if !run.CreatedAt.Before(midnight) {
			st.today++
			if run.Tier == "auto" && run.Status == standingrulerun.StatusSucceeded {
				st.autoToday++
			}
		}
		stats[run.RuleID] = st
	}

	out := make([]standingRuleRow, len(rows))
	for i, r := range rows {
		tpl, _ := standingrules.LookupTemplate(r.ActionTemplate)
		st := stats[r.ID]
		item := standingRuleRow{
			ID:                  r.ID,
			Ref:                 standingrules.Ref(r.ID),
			CreatedAt:           r.CreatedAt,
			UpdatedAt:           r.UpdatedAt,
			BuiltinKey:          r.BuiltinKey,
			Name:                r.Name,
			ConditionSummary:    r.ConditionSummary,
			Condition:           r.Condition,
			ActionTemplate:      r.ActionTemplate,
			ActionParams:        r.ActionParams,
			Tier:                string(r.Tier),
			AllowedTiers:        tpl.AllowedTiers,
			RollbackHint:        tpl.RollbackHint,
			GroupID:             r.GroupID,
			AssetIDs:            r.AssetIds,
			MaintenanceWindow:   r.MaintenanceWindow,
			CooldownMinutes:     r.CooldownMinutes,
			CreatedBy:           r.CreatedBy,
			CreatedByName:       who[r.CreatedBy],
			Enabled:             r.Enabled,
			ConsecutiveFailures: r.ConsecutiveFailures,
			DegradedAt:          r.DegradedAt,
			DegradedReason:      r.DegradedReason,
			LastRunAt:           r.LastRunAt,
			LastRunStatus:       r.LastRunStatus,
			HitsToday:           st.today,
			Hits30d:             st.d30,
			AutoToday:           st.autoToday,
		}
		if r.GroupID != nil {
			item.GroupName = groups[*r.GroupID]
		}
		for _, id := range r.AssetIds {
			if h := hosts[id]; h != "" {
				item.Hostnames = append(item.Hostnames, h)
			}
		}
		out[i] = item
	}
	return out
}
