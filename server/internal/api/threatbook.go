package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"openxdr/server/ent"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/threatbook"
	"time"
)

func ThreatBookLookup(db *ent.Client, service *threatbook.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := auth.From(r.Context())
		if u == nil || !auth.Allowed(u.Role, "analyst") {
			http.Error(w, "需要分析员权限", http.StatusForbidden)
			return
		}
		var body struct {
			IP string `json:"ip"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil {
			http.Error(w, "需要 IP 参数", http.StatusBadRequest)
			return
		}
		ip, err := threatbook.PublicIP(body.IP)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		result, err := service.Lookup(ctx, ip)
		if err != nil {
			status := http.StatusBadGateway
			if errors.Is(err, threatbook.ErrDisabled) {
				status = http.StatusServiceUnavailable
			}
			if errors.Is(err, threatbook.ErrQuota) {
				status = http.StatusTooManyRequests
				w.Header().Set("Retry-After", "60")
			}
			audit.Log(r.Context(), db, r, "intel.threatbook.lookup_failed", ip, err.Error())
			http.Error(w, err.Error(), status)
			return
		}
		audit.Log(r.Context(), db, r, "intel.threatbook.lookup", ip, "threatbook")
		writeJSON(w, result)
	})
}
