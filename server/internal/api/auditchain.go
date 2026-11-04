package api

import (
	"database/sql"
	"net/http"

	"openxdr/server/internal/auditchain"
	"openxdr/server/internal/auth"
)

// AuditChain 平台 admin 手动核对审计链：完整走一遍，返回已封存的最大编号与第一处断开。key 为 nil 表示没配签名私钥、没启用审计链
func AuditChain(db *sql.DB, key []byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/audit/chain", func(w http.ResponseWriter, r *http.Request) {
		if u := auth.From(r.Context()); u == nil || u.Role != "admin" {
			http.Error(w, "需要平台管理员", http.StatusForbidden)
			return
		}
		if key == nil {
			writeJSON(w, map[string]any{"enabled": false})
			return
		}
		broken, why, err := auditchain.Verify(r.Context(), db, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var unsealed int
		if err := db.QueryRowContext(r.Context(), `SELECT count(*) FROM audit_logs WHERE seq IS NULL`).Scan(&unsealed); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"enabled": true, "sealedSeq": int64(auditchain.SealedSeq(r.Context(), db)),
			"unsealed": unsealed, "ok": broken == 0, "brokenAt": broken, "reason": why})
	})
	return mux
}
