package integration

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"openxdr/server/ent"
	"openxdr/server/internal/flowinput"
	"strings"
	"testing"
)

func TestFlowAcknowledgement(t *testing.T) {
	group, observer := uuid.New(), uuid.New()
	p := principal{Integration: &ent.Integration{ID: observer}, Groups: []uuid.UUID{group}}
	body := `{"IPV4_SRC_ADDR":"192.0.2.1","IPV4_DST_ADDR":"198.51.100.2","L4_SRC_PORT":1,"L4_DST_PORT":443,"PROTOCOL":6,"FIRST_SWITCHED":1794000000,"group_id":"spoofed"}`
	for _, failure := range []bool{false, true} {
		called := false
		s := &Service{Flows: func(_ context.Context, o flowinput.Origin, e flowinput.Event) error {
			called = true
			if o.GroupID != group || o.Observer != observer.String() || o.Received.IsZero() || e.Source != "ntopng" {
				t.Fatalf("来源不可信: %+v", o)
			}
			if failure {
				return errors.New("queue unavailable")
			}
			return nil
		}}
		mux := http.NewServeMux()
		mux.HandleFunc("POST /api/integration/v1/flows/{source}/events", s.flowEvents)
		request := httptest.NewRequest("POST", "/api/integration/v1/flows/ntopng/events", strings.NewReader(body))
		request = request.WithContext(context.WithValue(request.Context(), principalKey{}, p))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, request)
		want := 202
		if failure {
			want = 503
		}
		if !called || w.Code != want {
			t.Fatalf("队列确认状态: called=%v status=%d want=%d", called, w.Code, want)
		}
	}
}
