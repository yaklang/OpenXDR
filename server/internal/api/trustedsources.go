package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entalert "openxdr/server/ent/alert"
	"openxdr/server/ent/schema"
	enttrusted "openxdr/server/ent/trustedsource"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/automation"
)

type trustedSourceRow struct {
	ID             uuid.UUID  `json:"id"`
	CreatedAt      time.Time  `json:"createdAt"`
	GroupID        uuid.UUID  `json:"groupId"`
	Name           string     `json:"name"`
	Reason         *string    `json:"reason"`
	CreatedBy      string     `json:"createdBy"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	KeyFingerprint *string    `json:"keyFingerprint"`
	SourceCIDR     *string    `json:"sourceCidr"`
	LoginUser      *string    `json:"loginUser"`
	MatchedCount   int        `json:"matchedCount"`
	LastMatchedAt  *time.Time `json:"lastMatchedAt"`
	RevokedAt      *time.Time `json:"revokedAt"`
	RevokedBy      *string    `json:"revokedBy"`
	// manual / auto
	Origin           string                     `json:"origin"`
	Pinned           bool                       `json:"pinned"`
	Evidence         *schema.AutomationEvidence `json:"evidence"`
	RevokeCause      *string                    `json:"revokeCause"`
	RevokeIncidentID *uuid.UUID                 `json:"revokeIncidentId"`
}

func toTrustedSourceRow(t *ent.TrustedSource) trustedSourceRow {
	return trustedSourceRow{
		ID: t.ID, CreatedAt: t.CreatedAt, GroupID: t.GroupID, Name: t.Name, Reason: t.Reason, CreatedBy: t.CreatedBy,
		ExpiresAt: t.ExpiresAt, KeyFingerprint: t.KeyFingerprint, SourceCIDR: t.SourceCidr, LoginUser: t.LoginUser,
		MatchedCount: t.MatchedCount, LastMatchedAt: t.LastMatchedAt, RevokedAt: t.RevokedAt, RevokedBy: t.RevokedBy,
		Origin: t.Origin, Pinned: t.Pinned, Evidence: t.Evidence, RevokeCause: t.RevokeCause, RevokeIncidentID: t.RevokeIncidentID,
	}
}

// automationRef 告警上标注的可信来源：名称与是否高危例外（仍进研判）
type automationRef struct {
	ID    uuid.UUID `json:"id"`
	Name  string    `json:"name"`
	Watch bool      `json:"watch"`
}

// automationNames 可信来源 ID → 名称，告警与事件列表标注来源用
func automationNames(ctx context.Context, db *ent.Client, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	out := map[uuid.UUID]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := db.TrustedSource.Query().Where(enttrusted.IDIn(ids...)).
		Select(enttrusted.FieldID, enttrusted.FieldName).All(ctx)
	for _, r := range rows {
		out[r.ID] = r.Name
	}
	return out, err
}

func refOf(a *ent.Alert, names map[uuid.UUID]string) *automationRef {
	if a.AutomationID == nil {
		return nil
	}
	return &automationRef{ID: *a.AutomationID, Name: names[*a.AutomationID], Watch: a.AutomationWatch}
}

// eventAutomation 事件触发的告警里来自可信来源的那条（同一事件的命中都按同一次登录核对，取一条即可）
func eventAutomation(ctx context.Context, db *ent.Client, events []uuid.UUID) (map[uuid.UUID]*automationRef, error) {
	out := map[uuid.UUID]*automationRef{}
	if len(events) == 0 {
		return out, nil
	}
	alerts, err := db.Alert.Query().Where(entalert.EventIDIn(events...), entalert.AutomationIDNotNil()).
		Select(entalert.FieldEventID, entalert.FieldAutomationID, entalert.FieldAutomationWatch).All(ctx)
	if err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	for _, a := range alerts {
		ids = append(ids, *a.AutomationID)
	}
	names, err := automationNames(ctx, db, ids)
	if err != nil {
		return nil, err
	}
	for _, a := range alerts {
		ref := refOf(a, names)
		// 高危例外优先展示：它仍进研判，比「已放行」更该被看到
		if prev := out[*a.EventID]; prev == nil || (ref.Watch && !prev.Watch) {
			out[*a.EventID] = ref
		}
	}
	return out, nil
}

// trustedCandidate 组内近期核对过出处的 SSH 登录，按登录身份归并，带「为什么（没）被自动识别」
type trustedCandidate struct {
	User        string    `json:"user"`
	Addresses   []string  `json:"addresses"`
	KeyType     *string   `json:"keyType"`
	KeyFP       *string   `json:"keyFingerprint"`
	Logins      int       `json:"logins"`
	Days        int       `json:"days"`
	Hosts       int       `json:"hosts"`
	LastSeen    time.Time `json:"lastSeen"`
	Alerts      int       `json:"alerts"`
	HumanBenign int       `json:"humanBenign"`
	AIBenign    int       `json:"aiBenign"`
	Pending     int       `json:"pending"`
	// automation.Reason*，另有 covered 已被生效条目覆盖、declined 人停用或删除过、disabled 自动识别已关闭
	Reason    string   `json:"reason"`
	SourceIDs []string `json:"trustedSourceIds"`
}

// mapTrustedSources 运维自动化来源：平台自动识别，组管理员可登记、调整、停用、删除，组内成员可看。
// 只有人和平台自己的识别逻辑能放宽检测——Pi 没有对应工具
func mapTrustedSources(api *http.ServeMux, db *ent.Client) {
	api.HandleFunc("GET /api/trusted-sources", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.TrustedSource.Query().Where(enttrusted.DeletedAtIsNil())
		if !s.all {
			q = q.Where(enttrusted.GroupIDIn(s.groups...))
		}
		if id, err := uuid.Parse(r.URL.Query().Get("groupId")); err == nil {
			q = q.Where(enttrusted.GroupIDEQ(id))
		}
		rows, err := q.Order(ent.Desc(enttrusted.FieldCreatedAt)).Limit(500).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]trustedSourceRow, len(rows))
		for i, t := range rows {
			out[i] = toTrustedSourceRow(t)
		}
		writeJSON(w, out)
	})

	api.HandleFunc("POST /api/trusted-sources", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			GroupID        uuid.UUID `json:"groupId"`
			Name           string    `json:"name"`
			Reason         string    `json:"reason"`
			KeyFingerprint string    `json:"keyFingerprint"`
			SourceCIDR     string    `json:"sourceCidr"`
			LoginUser      string    `json:"loginUser"`
			ExpiresInDays  int       `json:"expiresInDays"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		if !requireGroup(w, r, db, body.GroupID, "admin") {
			return
		}
		body.Name, body.Reason = strings.TrimSpace(body.Name), strings.TrimSpace(body.Reason)
		if n := utf8.RuneCountInString(body.Name); n == 0 || n > 100 {
			http.Error(w, "名称须为 1–100 字", http.StatusBadRequest)
			return
		}
		if utf8.RuneCountInString(body.Reason) > 1000 {
			http.Error(w, "说明不超过 1000 字", http.StatusBadRequest)
			return
		}
		if body.ExpiresInDays < 1 || body.ExpiresInDays > automation.MaxDays {
			http.Error(w, fmt.Sprintf("有效期须为 1–%d 天", automation.MaxDays), http.StatusBadRequest)
			return
		}
		c, err := automation.Criteria{KeyFingerprint: body.KeyFingerprint, SourceCIDR: body.SourceCIDR, LoginUser: body.LoginUser}.Normalize()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		actor := auth.From(r.Context()).Username
		var row *ent.TrustedSource
		err = withTx(r, db, func(tx *ent.Tx) error {
			create := tx.TrustedSource.Create().SetGroupID(body.GroupID).SetName(body.Name).SetCreatedBy(actor).
				SetExpiresAt(time.Now().AddDate(0, 0, body.ExpiresInDays))
			if body.Reason != "" {
				create.SetReason(body.Reason)
			}
			if c.KeyFingerprint != "" {
				create.SetKeyFingerprint(c.KeyFingerprint)
			}
			if c.SourceCIDR != "" {
				create.SetSourceCidr(c.SourceCIDR)
			}
			if c.LoginUser != "" {
				create.SetLoginUser(c.LoginUser)
			}
			var err error
			if row, err = create.Save(r.Context()); err != nil {
				return err
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor, audit.RemoteAddr(r), "trusted_source_created", row.ID.String(),
				fmt.Sprintf("%s 组=%s 指纹=%s 来源=%s 用户=%s 有效期=%d天", body.Name, body.GroupID, c.KeyFingerprint, c.SourceCIDR, c.LoginUser, body.ExpiresInDays))
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, toTrustedSourceRow(row))
	})

	// 停用即时生效（核对时直接查库），记录保留：已挂在它上面的告警还要说得清来源。
	// 停用过的自动识别不会被自动加回
	api.HandleFunc("POST /api/trusted-sources/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		row, ok := getByPath(w, r, "id", "trusted source", db.TrustedSource.Get)
		if !ok {
			return
		}
		if !requireGroup(w, r, db, row.GroupID, "admin") {
			return
		}
		actor := auth.From(r.Context()).Username
		err := withTx(r, db, func(tx *ent.Tx) error {
			n, err := tx.TrustedSource.Update().Where(enttrusted.IDEQ(row.ID), enttrusted.RevokedAtIsNil()).
				SetRevokedAt(time.Now()).SetRevokedBy(actor).ClearNotice().Save(r.Context())
			if err != nil {
				return err
			}
			if n != 1 {
				return errAlreadyRevoked
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor, audit.RemoteAddr(r), "trusted_source_revoked", row.ID.String(), row.Name)
		})
		if err == errAlreadyRevoked {
			http.Error(w, "已撤销", http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

var errAlreadyRevoked = fmt.Errorf("已撤销")

// mapTrustedSourceEdits 调整与删除：改名与说明、改有效期、固定、停用 / 启用、删除，组管理员，落审计
// TrustedCandidates 组内近期 SSH 登录为什么（没）被认成已知自动化，组管理员可见。
// 要按 (id, ts) 直接查分区事件，所以拿原始连接、单独挂路由
func TrustedCandidates(db *ent.Client, sqlDB *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/trusted-sources/candidates", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", http.StatusBadRequest)
			return
		}
		if !requireGroup(w, r, db, id, "admin") {
			return
		}
		out, err := trustedCandidates(r.Context(), db, sqlDB, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, out)
	})
	return mux
}

func mapTrustedSourceEdits(api *http.ServeMux, db *ent.Client) {
	api.HandleFunc("PATCH /api/trusted-sources/{id}", func(w http.ResponseWriter, r *http.Request) {
		row, ok := getByPath(w, r, "id", "trusted source", db.TrustedSource.Get)
		if !ok {
			return
		}
		if !requireGroup(w, r, db, row.GroupID, "admin") {
			return
		}
		var body struct {
			Name          *string `json:"name"`
			Reason        *string `json:"reason"`
			ExpiresInDays *int    `json:"expiresInDays"`
			Pinned        *bool   `json:"pinned"`
			Enabled       *bool   `json:"enabled"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		if row.DeletedAt != nil {
			http.Error(w, "已删除", http.StatusConflict)
			return
		}
		edit, action, detail, err := trustedEdit(row, body.Name, body.Reason, body.ExpiresInDays, body.Pinned, body.Enabled, auth.From(r.Context()).Username, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		actor := auth.From(r.Context()).Username
		var saved *ent.TrustedSource
		err = withTx(r, db, func(tx *ent.Tx) error {
			upd := tx.TrustedSource.UpdateOneID(row.ID)
			edit(upd)
			var err error
			if saved, err = upd.Save(r.Context()); err != nil {
				return err
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor, audit.RemoteAddr(r), action, row.ID.String(), row.Name+" "+detail)
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, toTrustedSourceRow(saved))
	})

	// 删除只是隐藏并停用：已挂上的告警仍说得清来源，自动识别也记得这个身份被人否决过，不会再自动加回
	api.HandleFunc("DELETE /api/trusted-sources/{id}", func(w http.ResponseWriter, r *http.Request) {
		row, ok := getByPath(w, r, "id", "trusted source", db.TrustedSource.Get)
		if !ok {
			return
		}
		if !requireGroup(w, r, db, row.GroupID, "admin") {
			return
		}
		actor := auth.From(r.Context()).Username
		now := time.Now()
		err := withTx(r, db, func(tx *ent.Tx) error {
			upd := tx.TrustedSource.Update().Where(enttrusted.IDEQ(row.ID), enttrusted.DeletedAtIsNil()).
				SetDeletedAt(now).SetDeletedBy(actor).ClearNotice()
			if row.RevokedAt == nil {
				upd.SetRevokedAt(now).SetRevokedBy(actor)
			}
			n, err := upd.Save(r.Context())
			if err != nil {
				return err
			}
			if n != 1 {
				return errAlreadyRevoked
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor, audit.RemoteAddr(r), "trusted_source_deleted", row.ID.String(), row.Name)
		})
		if err == errAlreadyRevoked {
			http.Error(w, "已删除", http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// trustedEdit 校验调整并给出要写的字段、审计动作与说明
func trustedEdit(row *ent.TrustedSource, name, reason *string, days *int, pinned, enabled *bool, actor string, now time.Time) (func(*ent.TrustedSourceUpdateOne), string, string, error) {
	var sets []func(*ent.TrustedSourceUpdateOne)
	var changes []string
	if name != nil {
		v := strings.TrimSpace(*name)
		if n := utf8.RuneCountInString(v); n == 0 || n > 100 {
			return nil, "", "", fmt.Errorf("名称须为 1–100 字")
		}
		sets = append(sets, func(u *ent.TrustedSourceUpdateOne) { u.SetName(v) })
		changes = append(changes, "名称="+v)
	}
	if reason != nil {
		v := strings.TrimSpace(*reason)
		if utf8.RuneCountInString(v) > 1000 {
			return nil, "", "", fmt.Errorf("说明不超过 1000 字")
		}
		sets = append(sets, func(u *ent.TrustedSourceUpdateOne) {
			if v == "" {
				u.ClearReason()
			} else {
				u.SetReason(v)
			}
		})
		changes = append(changes, "说明")
	}
	expires := row.ExpiresAt
	if days != nil {
		if *days < 1 || *days > automation.MaxDays {
			return nil, "", "", fmt.Errorf("有效期须为 1–%d 天", automation.MaxDays)
		}
		expires = now.AddDate(0, 0, *days)
		sets = append(sets, func(u *ent.TrustedSourceUpdateOne) { u.SetExpiresAt(expires) })
		changes = append(changes, fmt.Sprintf("有效期=%d天", *days))
	}
	if pinned != nil {
		v := *pinned
		sets = append(sets, func(u *ent.TrustedSourceUpdateOne) { u.SetPinned(v) })
		changes = append(changes, fmt.Sprintf("固定=%v", v))
	}
	action := "trusted_source_updated"
	if enabled != nil {
		switch {
		case *enabled && row.RevokedAt != nil:
			if !expires.After(now) {
				return nil, "", "", fmt.Errorf("已过期，启用时请同时设置有效期")
			}
			// 人看过之后决定继续信任：此前告警上的结论不再触发自动停用。系统因结论停用的，
			// 重新启用即固定——人推翻了自动判断，自动逻辑不该再替人改它
			sets = append(sets, func(u *ent.TrustedSourceUpdateOne) {
				u.ClearRevokedAt().ClearRevokedBy().ClearRevokeCause().ClearRevokeIncidentID().SetConfirmedAt(now)
			})
			if row.RevokeCause != nil && pinned == nil {
				sets = append(sets, func(u *ent.TrustedSourceUpdateOne) { u.SetPinned(true) })
				changes = append(changes, "固定=true")
			}
			action = "trusted_source_enabled"
		case !*enabled && row.RevokedAt == nil:
			sets = append(sets, func(u *ent.TrustedSourceUpdateOne) { u.SetRevokedAt(now).SetRevokedBy(actor).ClearNotice() })
			action = "trusted_source_revoked"
		}
	}
	if len(sets) == 0 {
		return nil, "", "", fmt.Errorf("没有要改的内容")
	}
	return func(u *ent.TrustedSourceUpdateOne) {
		for _, set := range sets {
			set(u)
		}
	}, action, strings.Join(changes, " "), nil
}

// trustedCandidates 组内窗口内的 SSH 登录，与后台识别同一套判断，解释每个登录身份为什么（没）被自动识别。
// 已被生效条目覆盖的标出条目；自动识别被人停用、删除过的标 declined
func trustedCandidates(ctx context.Context, db *ent.Client, sqlDB *sql.DB, group uuid.UUID) ([]trustedCandidate, error) {
	conf := automation.CurrentConfig()
	now := time.Now()
	assessments, _, err := automation.Assess(ctx, db, sqlDB, conf, &group, now)
	if err != nil {
		return nil, err
	}
	sources, err := db.TrustedSource.Query().Where(enttrusted.GroupIDEQ(group)).Order(ent.Asc(enttrusted.FieldCreatedAt)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]trustedCandidate, 0, len(assessments))
	for _, a := range assessments {
		c := trustedCandidate{User: a.User, Addresses: a.Addresses, Logins: a.Logins, Days: a.Days, Hosts: a.Hosts, LastSeen: a.LastLogin,
			Alerts: a.Alerts, HumanBenign: a.HumanBenign, AIBenign: a.AIBenign, Pending: a.Pending, Reason: a.Reason, SourceIDs: []string{}}
		if a.KeyFP != "" {
			fp := a.KeyFP
			c.KeyFP = &fp
		}
		if a.KeyType != "" {
			kt := a.KeyType
			c.KeyType = &kt
		}
		for _, t := range sources {
			src := automation.Source{ID: t.ID, KeyFingerprint: t.KeyFingerprint, SourceCIDR: t.SourceCidr, LoginUser: t.LoginUser}
			active := t.RevokedAt == nil && t.ExpiresAt.After(now)
			mine := t.Origin == "auto" && t.KeyFingerprint != nil && *t.KeyFingerprint == a.KeyFP && t.LoginUser != nil && *t.LoginUser == a.User
			for _, addr := range a.Addresses {
				login := automation.Login{User: a.User, SrcIP: addr, KeyFP: a.KeyFP}
				if active && src.Matches(login) && !slices.Contains(c.SourceIDs, t.ID.String()) {
					c.SourceIDs = append(c.SourceIDs, t.ID.String())
				}
			}
			if mine && t.RevokedAt != nil {
				if t.RevokeCause != nil {
					c.Reason = automation.ReasonFlagged
				} else {
					c.Reason = "declined"
				}
			}
		}
		switch {
		case len(c.SourceIDs) > 0:
			c.Reason = "covered"
		case c.Reason == automation.ReasonEligible && !conf.Enabled:
			c.Reason = "disabled"
		}
		out = append(out, c)
	}
	if len(out) > 100 {
		out = out[:100]
	}
	return out, nil
}
