package api

import (
	"net/http"

	"openxdr/server/ent"
	"openxdr/server/internal/notify"
)

// NotifyHealth 通知渠道健康，供总览与全局横幅轮询。渠道状态是全局的，积压数按用户可见范围计
func NotifyHealth(db *ent.Client, settings *notify.Settings) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/notify/health", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		h, err := settings.Health(r.Context(), s.incident()...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, h)
	})
	return mux
}
