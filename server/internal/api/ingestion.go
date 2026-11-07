package api

import (
	"net/http"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/syslog"
)

// SyslogStatus 仅管理员可读全局监听地址与收包计数，不返回日志内容。
func SyslogStatus(receiver *syslog.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := auth.From(r.Context())
		if u == nil || u.Role != "admin" {
			http.Error(w, "需要管理员权限", http.StatusForbidden)
			return
		}
		writeJSON(w, receiver.Status())
	})
}
