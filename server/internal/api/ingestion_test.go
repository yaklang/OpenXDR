package api

import (
	"net/http"
	"net/http/httptest"
	"openxdr/server/ent"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/syslog"
	"testing"
)

func TestSyslogStatusAccess(t *testing.T) {
	handler := SyslogStatus(&syslog.Server{Addr: ":514"})
	for _, role := range []string{"", "viewer", "analyst", "admin"} {
		r := httptest.NewRequest("GET", "/api/ingestion/syslog", nil)
		if role != "" {
			r = r.WithContext(auth.WithUser(r.Context(), &ent.User{Role: role}))
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		want := http.StatusForbidden
		if role == "admin" {
			want = http.StatusOK
		}
		if w.Code != want {
			t.Fatalf("角色 %q: %d，预期 %d", role, w.Code, want)
		}
	}
}
