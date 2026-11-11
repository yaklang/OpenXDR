package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/ent/fact"
	"openxdr/server/ent/intent"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/facts"
)

type factRow struct {
	ID          uuid.UUID  `json:"id"`
	Ref         string     `json:"ref"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	Kind        string     `json:"kind"`
	Subject     string     `json:"subject"`
	GroupID     *uuid.UUID `json:"groupId"`
	AssetID     *uuid.UUID `json:"assetId"`
	Hostname    string     `json:"hostname,omitempty"`
	Holder      string     `json:"holder"`
	Content     string     `json:"content"`
	Source      string     `json:"source"`
	CreatedBy   string     `json:"createdBy"`
	ExpiresAt   *time.Time `json:"expiresAt"`
	RetiredAt   *time.Time `json:"retiredAt"`
	RetiredBy   *string    `json:"retiredBy"`
	CitedCount  int        `json:"citedCount"`
	LastCitedAt *time.Time `json:"lastCitedAt"`
}

type intentRow struct {
	ID             uuid.UUID   `json:"id"`
	Ref            string      `json:"ref"`
	CreatedAt      time.Time   `json:"createdAt"`
	CreatedBy      string      `json:"createdBy"`
	KeyFingerprint string      `json:"keyFingerprint"`
	SourceAddr     string      `json:"sourceAddr"`
	AssetIDs       []uuid.UUID `json:"assetIds"`
	Hostnames      []string    `json:"hostnames"`
	Category       string      `json:"category"`
	Note           string      `json:"note"`
	StartsAt       time.Time   `json:"startsAt"`
	ExpiresAt      time.Time   `json:"expiresAt"`
	EndedAt        *time.Time  `json:"endedAt"`
	EndedBy        *string     `json:"endedBy"`
	Late           bool        `json:"late"`
	Active         bool        `json:"active"`
}

func hostnamesOf(ctx context.Context, db *ent.Client, ids []uuid.UUID) map[uuid.UUID]string {
	out := map[uuid.UUID]string{}
	if len(ids) == 0 {
		return out
	}
	rows, _ := db.Asset.Query().Where(entasset.IDIn(ids...)).Select(entasset.FieldID, entasset.FieldHostname).All(ctx)
	for _, a := range rows {
		out[a.ID] = a.Hostname
	}
	return out
}

func toIntentRow(in *ent.Intent, names map[uuid.UUID]string, now time.Time) intentRow {
	row := intentRow{ID: in.ID, Ref: facts.Ref("I", in.ID), CreatedAt: in.CreatedAt, CreatedBy: in.CreatedBy, KeyFingerprint: in.KeyFingerprint,
		SourceAddr: in.SourceAddr, AssetIDs: in.AssetIds, Category: in.Category, Note: in.Note, StartsAt: in.StartsAt,
		ExpiresAt: in.ExpiresAt, EndedAt: in.EndedAt, EndedBy: in.EndedBy, Late: in.Late,
		Active: in.EndedAt == nil && now.Before(in.ExpiresAt)}
	for _, id := range in.AssetIds {
		if h := names[id]; h != "" {
			row.Hostnames = append(row.Hostnames, h)
		}
	}
	return row
}

// Control 自治总控：权威事实与运维意图。事实只有平台管理员能写；意图由登记人为自己名下的通道登记，
// 每次登记推送到通知渠道，被盗用的登记当场就能被看到
func Control(db *ent.Client, notify func(ctx context.Context, title, body, path string) error) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/facts", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.Fact.Query()
		if !s.all {
			q = q.Where(fact.Or(fact.GroupIDIsNil(), fact.GroupIDIn(s.groups...)))
		}
		if k := r.URL.Query().Get("kind"); k != "" {
			q = q.Where(fact.KindEQ(k))
		}
		if r.URL.Query().Get("retired") != "1" {
			q = q.Where(fact.RetiredAtIsNil())
		}
		if id, err := uuid.Parse(r.URL.Query().Get("assetId")); err == nil {
			q = q.Where(fact.AssetIDEQ(id))
		}
		rows, err := q.Order(ent.Asc(fact.FieldKind), ent.Desc(fact.FieldUpdatedAt)).Limit(1000).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var ids []uuid.UUID
		for _, f := range rows {
			if f.AssetID != nil {
				ids = append(ids, *f.AssetID)
			}
		}
		names := hostnamesOf(r.Context(), db, ids)
		out := make([]factRow, len(rows))
		for i, f := range rows {
			out[i] = toFactRow(f, names)
		}
		writeJSON(w, out)
	})

	mux.HandleFunc("POST /api/facts", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		var body struct {
			Kind          string     `json:"kind"`
			Subject       string     `json:"subject"`
			GroupID       *uuid.UUID `json:"groupId"`
			AssetID       *uuid.UUID `json:"assetId"`
			Holder        string     `json:"holder"`
			Content       string     `json:"content"`
			ExpiresInDays int        `json:"expiresInDays"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		body.Subject, body.Holder, body.Content = strings.TrimSpace(body.Subject), strings.TrimSpace(body.Holder), strings.TrimSpace(body.Content)
		if err := facts.ValidateFact(body.Kind, body.Subject, body.AssetID, body.Content); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if body.Kind == "channel" {
			p, _ := facts.Prefix(body.Subject)
			body.Subject = p.String()
		}
		if body.ExpiresInDays < 0 || body.ExpiresInDays > 3650 {
			http.Error(w, "有效期须为 0（长期）–3650 天", http.StatusBadRequest)
			return
		}
		if body.AssetID != nil {
			a, err := db.Asset.Get(r.Context(), *body.AssetID)
			if err != nil {
				http.Error(w, "资产不存在", http.StatusBadRequest)
				return
			}
			body.GroupID = a.GroupID
		}
		actor := auth.From(r.Context()).Username
		var row *ent.Fact
		err := withTx(r, db, func(tx *ent.Tx) error {
			c := tx.Fact.Create().SetKind(body.Kind).SetSubject(body.Subject).SetNillableGroupID(body.GroupID).
				SetNillableAssetID(body.AssetID).SetHolder(body.Holder).SetContent(body.Content).SetSource("human").SetCreatedBy(actor)
			if body.ExpiresInDays > 0 {
				c.SetExpiresAt(time.Now().AddDate(0, 0, body.ExpiresInDays))
			}
			var err error
			if row, err = c.Save(r.Context()); err != nil {
				return err
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor, audit.RemoteAddr(r), "fact_created", row.ID.String(),
				fmt.Sprintf("%s %s 持有人=%s：%s", body.Kind, body.Subject, body.Holder, body.Content))
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, toFactRow(row, hostnamesOf(r.Context(), db, assetIDs(row))))
	})

	mux.HandleFunc("PATCH /api/facts/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		row, ok := getByPath(w, r, "id", "fact", db.Fact.Get)
		if !ok {
			return
		}
		var body struct {
			Holder        *string `json:"holder"`
			Content       *string `json:"content"`
			ExpiresInDays *int    `json:"expiresInDays"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		content := row.Content
		if body.Content != nil {
			content = strings.TrimSpace(*body.Content)
		}
		if err := facts.ValidateFact(row.Kind, row.Subject, row.AssetID, content); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		actor := auth.From(r.Context()).Username
		err := withTx(r, db, func(tx *ent.Tx) error {
			u := tx.Fact.UpdateOneID(row.ID).SetContent(content)
			if body.Holder != nil {
				u.SetHolder(strings.TrimSpace(*body.Holder))
			}
			if body.ExpiresInDays != nil {
				switch d := *body.ExpiresInDays; {
				case d == 0:
					u.ClearExpiresAt()
				case d > 0 && d <= 3650:
					u.SetExpiresAt(time.Now().AddDate(0, 0, d))
				default:
					return errBadExpiry
				}
			}
			var err error
			if row, err = u.Save(r.Context()); err != nil {
				return err
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor, audit.RemoteAddr(r), "fact_updated", row.ID.String(),
				fmt.Sprintf("持有人=%s：%s", row.Holder, row.Content))
		})
		if errors.Is(err, errBadExpiry) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, toFactRow(row, hostnamesOf(r.Context(), db, assetIDs(row))))
	})

	mux.HandleFunc("POST /api/facts/{id}/retire", func(w http.ResponseWriter, r *http.Request) {
		if !requireAdmin(w, r) {
			return
		}
		row, ok := getByPath(w, r, "id", "fact", db.Fact.Get)
		if !ok {
			return
		}
		actor := auth.From(r.Context()).Username
		err := withTx(r, db, func(tx *ent.Tx) error {
			n, err := tx.Fact.Update().Where(fact.IDEQ(row.ID), fact.RetiredAtIsNil()).SetRetiredAt(time.Now()).SetRetiredBy(actor).Save(r.Context())
			if err != nil {
				return err
			}
			if n != 1 {
				return errAlreadyRevoked
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), actor, audit.RemoteAddr(r), "fact_retired", row.ID.String(), row.Kind+" "+row.Subject)
		})
		if errors.Is(err, errAlreadyRevoked) {
			http.Error(w, "已停用", http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /api/intents", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		q := db.Intent.Query()
		if r.URL.Query().Get("active") == "1" {
			q = q.Where(intent.EndedAtIsNil(), intent.ExpiresAtGT(time.Now()))
		}
		rows, err := q.Order(ent.Desc(intent.FieldCreatedAt)).Limit(500).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var ids []uuid.UUID
		var visible []*ent.Intent
		for _, in := range rows {
			if s.all || slices.ContainsFunc(in.AssetIds, s.has) {
				visible = append(visible, in)
				ids = append(ids, in.AssetIds...)
			}
		}
		names := hostnamesOf(r.Context(), db, ids)
		now := time.Now()
		out := make([]intentRow, len(visible))
		for i, in := range visible {
			out[i] = toIntentRow(in, names, now)
		}
		writeJSON(w, out)
	})

	mux.HandleFunc("POST /api/intents", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "analyst")
		if !ok {
			return
		}
		var body facts.IntentBody
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		now := time.Now()
		in, err := facts.Register(r.Context(), db, "user:"+auth.From(r.Context()).Username, audit.RemoteAddr(r), body.Request(now), s.has, notify, now)
		if err != nil {
			http.Error(w, err.Error(), IntentStatus(err))
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, toIntentRow(in, hostnamesOf(r.Context(), db, in.AssetIds), now))
	})

	mux.HandleFunc("POST /api/intents/{id}/end", func(w http.ResponseWriter, r *http.Request) {
		row, ok := getByPath(w, r, "id", "intent", db.Intent.Get)
		if !ok {
			return
		}
		u := auth.From(r.Context())
		if row.CreatedBy != "user:"+u.Username && u.Role != "admin" {
			http.Error(w, "只能结束自己登记的意图", http.StatusForbidden)
			return
		}
		err := withTx(r, db, func(tx *ent.Tx) error {
			n, err := tx.Intent.Update().Where(intent.IDEQ(row.ID), intent.EndedAtIsNil()).SetEndedAt(time.Now()).SetEndedBy(u.Username).Save(r.Context())
			if err != nil {
				return err
			}
			if n != 1 {
				return errAlreadyRevoked
			}
			return audit.Checked(r.Context(), tx.AuditLog.Create(), u.Username, audit.RemoteAddr(r), "intent_ended", row.ID.String(), facts.Ref("I", row.ID))
		})
		if errors.Is(err, errAlreadyRevoked) {
			http.Error(w, "已结束", http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

var errBadExpiry = errors.New("有效期须为 0（长期）–3650 天")

func assetIDs(f *ent.Fact) []uuid.UUID {
	if f.AssetID == nil {
		return nil
	}
	return []uuid.UUID{*f.AssetID}
}

func toFactRow(f *ent.Fact, names map[uuid.UUID]string) factRow {
	row := factRow{ID: f.ID, Ref: facts.Ref("F", f.ID), CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt, Kind: f.Kind, Subject: f.Subject,
		GroupID: f.GroupID, AssetID: f.AssetID, Holder: f.Holder, Content: f.Content, Source: f.Source, CreatedBy: f.CreatedBy,
		ExpiresAt: f.ExpiresAt, RetiredAt: f.RetiredAt, RetiredBy: f.RetiredBy, CitedCount: f.CitedCount, LastCitedAt: f.LastCitedAt}
	if f.AssetID != nil {
		row.Hostname = names[*f.AssetID]
	}
	return row
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if auth.From(r.Context()).Role != "admin" {
		http.Error(w, "只有平台管理员能修改权威事实", http.StatusForbidden)
		return false
	}
	return true
}

// IntentStatus 登记错误对应的 HTTP 状态
func IntentStatus(err error) int {
	var bad facts.ErrInvalid
	switch {
	case errors.As(err, &bad):
		return http.StatusBadRequest
	case errors.Is(err, facts.ErrNotOwner), errors.Is(err, facts.ErrForbiddenHost):
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
}
