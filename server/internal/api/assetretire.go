package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/assetretire"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
)

// retireAsset 下线或恢复主机：资产所在组的 admin 才能做，下线必须写原因
func retireAsset(db *ent.Client, retire bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ok := getByPath(w, r, "id", "asset", db.Asset.Get)
		if !ok || !assetInScope(w, r, db, a.ID, "admin") {
			return
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if r.ContentLength != 0 && json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		actor := auth.From(r.Context()).Username
		var out *ent.Asset
		var err error
		action := "asset_retired"
		if retire {
			out, err = assetretire.Retire(r.Context(), db, a, actor, body.Reason, time.Now())
		} else {
			action = "asset_restored"
			out, err = assetretire.Restore(r.Context(), db, a)
		}
		switch {
		case errors.Is(err, assetretire.ErrRetired), errors.Is(err, assetretire.ErrNotRetired):
			http.Error(w, err.Error(), http.StatusConflict)
			return
		case errors.Is(err, assetretire.ErrNoReason):
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, action, a.ID.String(), a.Hostname+" "+body.Reason)
		writeJSON(w, map[string]any{"id": out.ID, "hostname": out.Hostname, "retiredAt": out.RetiredAt, "retiredBy": out.RetiredBy, "retiredReason": out.RetiredReason})
	}
}
