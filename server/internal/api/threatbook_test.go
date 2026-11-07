package api

import (
	"net/http/httptest"
	"openxdr/server/ent"
	"openxdr/server/internal/auth"
	"strings"
	"testing"
)

func TestThreatBookRequestGate(t *testing.T) {
	for _, test := range []struct {
		role, body string
		status     int
	}{
		{"viewer", `{"ip":"8.8.8.8"}`, 403},
		{"analyst", `{"ip":"10.0.0.1"}`, 400},
		{"admin", `{"ip":"169.254.169.254"}`, 400},
		{"admin", `invalid`, 400},
	} {
		r := httptest.NewRequest("POST", "/api/intel/threatbook/lookup", strings.NewReader(test.body))
		r = r.WithContext(auth.WithUser(r.Context(), &ent.User{Role: test.role}))
		w := httptest.NewRecorder()
		ThreatBookLookup(nil, nil).ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%+v: status=%d", test, w.Code)
		}
	}
}
