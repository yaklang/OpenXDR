package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/ent/changerecord"
	"openxdr/server/ent/changerecordasset"
	"openxdr/server/ent/changesource"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/changerecords"
	"openxdr/server/internal/hostimport"
	integrationapi "openxdr/server/internal/integration"
)

type changeSourceInput struct {
	Provider   string `json:"provider"`
	Name       string `json:"name"`
	Repo       string `json:"repo"`
	Branch     string `json:"branch"`
	Token      string `json:"token"`
	ClearToken bool   `json:"clearToken"`
	Enabled    bool   `json:"enabled"`
}

type changeSourceRow struct {
	ID              uuid.UUID  `json:"id"`
	Provider        string     `json:"provider"`
	Name            string     `json:"name"`
	Repo            string     `json:"repo"`
	Branch          string     `json:"branch"`
	HasToken        bool       `json:"hasToken"`
	TokenHint       string     `json:"tokenHint"`
	Enabled         bool       `json:"enabled"`
	SinceCursor     *time.Time `json:"sinceCursor"`
	LastSyncedAt    *time.Time `json:"lastSyncedAt"`
	LastAttemptedAt *time.Time `json:"lastAttemptedAt"`
	LastError       string     `json:"lastError"`
	RecordCount     int        `json:"recordCount"`
	CreatedBy       string     `json:"createdBy"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}

type assetChangeRecordRow struct {
	ID          uuid.UUID `json:"id"`
	Repo        string    `json:"repo"`
	SHA         string    `json:"sha"`
	ShortSHA    string    `json:"shortSha"`
	CommittedAt time.Time `json:"committedAt"`
	Author      string    `json:"author"`
	Title       string    `json:"title"`
	Body        string    `json:"body"`
	FileCount   int       `json:"fileCount"`
	Files       []string  `json:"files"`
	Clues       []string  `json:"clues"`
}

func toChangeSourceRow(s *ent.ChangeSource, count int) changeSourceRow {
	return changeSourceRow{
		ID:              s.ID,
		Provider:        s.Provider,
		Name:            s.Name,
		Repo:            s.Repo,
		Branch:          s.Branch,
		HasToken:        len(s.Secret) > 0,
		TokenHint:       s.TokenHint,
		Enabled:         s.Enabled,
		SinceCursor:     s.SinceCursor,
		LastSyncedAt:    s.LastSyncedAt,
		LastAttemptedAt: s.LastAttemptedAt,
		LastError:       s.LastError,
		RecordCount:     count,
		CreatedBy:       s.CreatedBy,
		CreatedAt:       s.CreatedAt,
		UpdatedAt:       s.UpdatedAt,
	}
}

// ChangeTokenCipher 将 hostimport.Vault 适配为 changerecords.TokenCipher（vault 为空时返回 nil）。
func ChangeTokenCipher(vault *hostimport.Vault) *changerecords.TokenCipher {
	if vault == nil {
		return nil
	}
	return &changerecords.TokenCipher{
		Seal: func(plain, binding string) ([]byte, error) {
			return vault.Seal(hostimport.Secret{Password: plain}, binding)
		},
		Open: func(ciphertext []byte, binding string) (string, error) {
			sec, err := vault.Open(ciphertext, binding)
			if err != nil {
				return "", err
			}
			return sec.Password, nil
		},
	}
}

// ChangeRecords 管理变更记录源（全局管理员）并按资产组作用域返回关联变更记录（只读 viewer）。
func ChangeRecords(db *ent.Client, vault *hostimport.Vault, syncer *changerecords.Syncer) http.Handler {
	cipher := ChangeTokenCipher(vault)
	adminMux := http.NewServeMux()

	adminMux.HandleFunc("GET /api/system-integrations/change-sources", func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.ChangeSource.Query().Order(ent.Desc(changesource.FieldCreatedAt)).All(r.Context())
		if integrationFailure(w, err) {
			return
		}
		counts := map[uuid.UUID]int{}
		if len(rows) > 0 {
			var agg []struct {
				SourceID uuid.UUID `json:"source_id"`
				Count    int       `json:"count"`
			}
			if err := db.ChangeRecord.Query().GroupBy(changerecord.FieldSourceID).Aggregate(ent.Count()).Scan(r.Context(), &agg); err == nil {
				for _, item := range agg {
					counts[item.SourceID] = item.Count
				}
			}
		}
		items := make([]changeSourceRow, 0, len(rows))
		for _, s := range rows {
			items = append(items, toChangeSourceRow(s, counts[s.ID]))
		}
		integrationapi.JSON(w, http.StatusOK, map[string]any{
			"vaultConfigured": vault != nil,
			"items":           items,
		})
	})

	save := func(w http.ResponseWriter, r *http.Request) {
		var body changeSourceInput
		if !integrationDecode(w, r, &body) {
			return
		}
		provider := strings.ToLower(strings.TrimSpace(body.Provider))
		if provider == "" {
			provider = changerecords.ProviderGitHub
		}
		if provider != changerecords.ProviderGitHub {
			integrationapi.Error(w, http.StatusBadRequest, "invalid_argument", "当前仅支持 github 变更记录源")
			return
		}
		repo, err := changerecords.CleanRepo(body.Repo)
		if err != nil {
			integrationapi.Error(w, http.StatusBadRequest, "invalid_argument", err.Error())
			return
		}
		branch, err := changerecords.CleanBranch(body.Branch)
		if err != nil {
			integrationapi.Error(w, http.StatusBadRequest, "invalid_argument", err.Error())
			return
		}
		name := strings.TrimSpace(body.Name)
		if utf8.RuneCountInString(name) > 100 {
			integrationapi.Error(w, http.StatusBadRequest, "invalid_argument", "名称长度不能超过 100 字符")
			return
		}
		token := strings.TrimSpace(body.Token)

		tx, err := db.Tx(r.Context())
		if integrationFailure(w, err) {
			return
		}
		defer tx.Rollback()

		var saved *ent.ChangeSource
		status := http.StatusOK
		if r.Method == http.MethodPost {
			id, err := uuid.NewV7()
			if integrationFailure(w, err) {
				return
			}
			var sealed []byte
			var hint string
			if token != "" {
				sealed, hint, err = changerecords.SealToken(cipher, id, token)
				if errors.Is(err, changerecords.ErrVaultUnavailable) {
					integrationapi.Error(w, http.StatusServiceUnavailable, "vault_unavailable", err.Error())
					return
				}
				if err != nil {
					integrationapi.Error(w, http.StatusBadRequest, "invalid_argument", err.Error())
					return
				}
			}
			create := tx.ChangeSource.Create().
				SetID(id).
				SetProvider(provider).
				SetName(name).
				SetRepo(repo).
				SetBranch(branch).
				SetTokenHint(hint).
				SetEnabled(body.Enabled).
				SetCreatedBy(audit.Actor(r.Context()))
			if len(sealed) > 0 {
				create.SetSecret(sealed)
			}
			saved, err = create.Save(r.Context())
			if ent.IsConstraintError(err) {
				integrationapi.Error(w, http.StatusConflict, "conflict", "该仓库已配置为变更记录源")
				return
			}
			if integrationFailure(w, err) {
				return
			}
			status = http.StatusCreated
		} else {
			id, err := uuid.Parse(r.PathValue("id"))
			if err != nil {
				integrationapi.Error(w, http.StatusNotFound, "not_found", "变更记录源不存在")
				return
			}
			cur, err := tx.ChangeSource.Query().
				Where(changesource.IDEQ(id)).
				Where(func(s *sql.Selector) { s.ForUpdate() }).
				Only(r.Context())
			if integrationFailure(w, err) {
				return
			}
			upd := tx.ChangeSource.UpdateOneID(id).
				SetName(name).
				SetRepo(repo).
				SetBranch(branch).
				SetEnabled(body.Enabled)
			if cur.Repo != repo || cur.Branch != branch {
				upd.ClearSinceCursor().SetLastError("")
			}
			if token != "" {
				sealed, hint, err := changerecords.SealToken(cipher, id, token)
				if errors.Is(err, changerecords.ErrVaultUnavailable) {
					integrationapi.Error(w, http.StatusServiceUnavailable, "vault_unavailable", err.Error())
					return
				}
				if err != nil {
					integrationapi.Error(w, http.StatusBadRequest, "invalid_argument", err.Error())
					return
				}
				upd.SetSecret(sealed).SetTokenHint(hint)
			} else if body.ClearToken {
				upd.ClearSecret().SetTokenHint("")
			}
			saved, err = upd.Save(r.Context())
			if ent.IsConstraintError(err) {
				integrationapi.Error(w, http.StatusConflict, "conflict", "该仓库已配置为变更记录源")
				return
			}
			if integrationFailure(w, err) {
				return
			}
		}

		auditDetail, _ := json.Marshal(map[string]any{
			"provider":   provider,
			"name":       name,
			"repo":       repo,
			"branch":     branch,
			"enabled":    body.Enabled,
			"hasToken":   len(saved.Secret) > 0,
			"clearToken": body.ClearToken,
		})
		if integrationFailure(w, audit.Checked(r.Context(), tx.AuditLog.Create(), audit.Actor(r.Context()), audit.RemoteAddr(r), "change_source_saved", saved.ID.String(), string(auditDetail))) {
			return
		}
		if integrationFailure(w, tx.Commit()) {
			return
		}
		cnt, _ := db.ChangeRecord.Query().Where(changerecord.SourceIDEQ(saved.ID)).Count(r.Context())
		integrationapi.JSON(w, status, toChangeSourceRow(saved, cnt))
	}
	adminMux.HandleFunc("POST /api/system-integrations/change-sources", save)
	adminMux.HandleFunc("PUT /api/system-integrations/change-sources/{id}", save)

	adminMux.HandleFunc("DELETE /api/system-integrations/change-sources/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			integrationapi.Error(w, http.StatusNotFound, "not_found", "变更记录源不存在")
			return
		}
		tx, err := db.Tx(r.Context())
		if integrationFailure(w, err) {
			return
		}
		defer tx.Rollback()
		src, err := tx.ChangeSource.Get(r.Context(), id)
		if integrationFailure(w, err) {
			return
		}
		recIDs, err := tx.ChangeRecord.Query().Where(changerecord.SourceIDEQ(id)).IDs(r.Context())
		if integrationFailure(w, err) {
			return
		}
		if len(recIDs) > 0 {
			if _, err := tx.ChangeRecordAsset.Delete().Where(changerecordasset.ChangeRecordIDIn(recIDs...)).Exec(r.Context()); integrationFailure(w, err) {
				return
			}
			if _, err := tx.ChangeRecord.Delete().Where(changerecord.SourceIDEQ(id)).Exec(r.Context()); integrationFailure(w, err) {
				return
			}
		}
		if err := tx.ChangeSource.DeleteOneID(id).Exec(r.Context()); integrationFailure(w, err) {
			return
		}
		if integrationFailure(w, audit.Checked(r.Context(), tx.AuditLog.Create(), audit.Actor(r.Context()), audit.RemoteAddr(r), "change_source_deleted", id.String(), src.Repo)) {
			return
		}
		if integrationFailure(w, tx.Commit()) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	adminMux.HandleFunc("POST /api/system-integrations/change-sources/{id}/sync", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			integrationapi.Error(w, http.StatusNotFound, "not_found", "变更记录源不存在")
			return
		}
		src, err := db.ChangeSource.Get(r.Context(), id)
		if integrationFailure(w, err) {
			return
		}
		if syncer == nil {
			integrationapi.Error(w, http.StatusServiceUnavailable, "unavailable", "变更记录同步器未就绪")
			return
		}
		added, syncErr := syncer.SyncSource(r.Context(), src.ID)
		if syncErr == nil {
			_ = syncer.RelinkRecent(r.Context(), time.Now().Add(-changerecords.RelinkWindow))
		}
		_ = audit.Checked(r.Context(), db.AuditLog.Create(), audit.Actor(r.Context()), audit.RemoteAddr(r), "change_source_synced", id.String(), src.Repo)
		fresh, err := db.ChangeSource.Get(r.Context(), id)
		if integrationFailure(w, err) {
			return
		}
		cnt, _ := db.ChangeRecord.Query().Where(changerecord.SourceIDEQ(id)).Count(r.Context())
		if syncErr != nil {
			if errors.Is(syncErr, changerecords.ErrVaultUnavailable) {
				integrationapi.Error(w, http.StatusServiceUnavailable, "vault_unavailable", syncErr.Error())
				return
			}
			integrationapi.Error(w, http.StatusBadGateway, "sync_failed", syncErr.Error())
			return
		}
		integrationapi.JSON(w, http.StatusOK, map[string]any{
			"added":  added,
			"source": toChangeSourceRow(fresh, cnt),
		})
	})

	adminGuard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", uuid.NewString())
		w.Header().Set("Cache-Control", "no-store")
		u := auth.From(r.Context())
		if u == nil || u.Role != "admin" {
			integrationapi.Error(w, http.StatusForbidden, "forbidden", "仅全局管理员可管理变更记录源")
			return
		}
		adminMux.ServeHTTP(w, r)
	})

	mux := http.NewServeMux()
	mux.Handle("/api/system-integrations/change-sources", adminGuard)
	mux.Handle("/api/system-integrations/change-sources/", adminGuard)
	mux.HandleFunc("GET /api/assets/{id}/change-records", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的资产 id", http.StatusBadRequest)
			return
		}
		if !assetInScope(w, r, db, id, "viewer") {
			return
		}
		exists, err := db.Asset.Query().Where(entasset.IDEQ(id)).Exist(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !exists {
			http.NotFound(w, r)
			return
		}
		limit := 20
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 100 {
				limit = n
			}
		}
		records, err := changerecords.LookupAssetRecent(r.Context(), db, id, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]assetChangeRecordRow, 0, len(records))
		for _, rec := range records {
			files := rec.Files
			if files == nil {
				files = []string{}
			}
			clues := rec.Clues
			if clues == nil {
				clues = []string{}
			}
			out = append(out, assetChangeRecordRow{
				ID:          rec.ID,
				Repo:        rec.Repo,
				SHA:         rec.SHA,
				ShortSHA:    rec.ShortSHA,
				CommittedAt: rec.CommittedAt,
				Author:      rec.Author,
				Title:       rec.Title,
				Body:        rec.Body,
				FileCount:   rec.FileCount,
				Files:       files,
				Clues:       clues,
			})
		}
		writeJSON(w, out)
	})
	return mux
}
