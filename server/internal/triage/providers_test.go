package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"openxdr/server/internal/modelroute"
	"testing"
	"time"
)

func TestProviderFailoverBindsCredentials(t *testing.T) {
	for _, status := range []int{402, 429, 503, 401, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			first, second := 0, 0
			a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				first++
				if r.Header.Get("Authorization") != "Bearer key-a" {
					t.Error("主服务凭据错配")
				}
				w.WriteHeader(status)
			}))
			defer a.Close()
			b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				second++
				if r.Header.Get("Authorization") != "Bearer key-b" {
					t.Error("备用服务凭据错配")
				}
				var v map[string]any
				json.NewDecoder(r.Body).Decode(&v)
				if v["model"] != "model-b" {
					t.Error("模型错配")
				}
				w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`))
			}))
			defer b.Close()
			l := NewLLM(a.URL, "model-a", "key-a", time.Second)
			l.FallbackModels = func() string { return "model-a2" }
			l.FallbackEndpoints = func() []modelroute.Endpoint {
				return []modelroute.Endpoint{{BaseURL: b.URL, APIKey: "key-b", Model: "model-b"}}
			}
			if _, err := l.Chat(context.Background(), nil, nil); err != nil {
				t.Fatal(err)
			}
			want := 2
			if status == 401 || status == 403 {
				want = 1
			}
			if first != want || second != 1 {
				t.Fatalf("调用次数 %d %d", first, second)
			}
		})
	}
}

func TestProviderConnectionFailureAndBadRequest(t *testing.T) {
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":"OK"}}]}`))
	}))
	defer backup.Close()
	failed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) }))
	failed.Close()
	l := NewLLM(failed.URL, "model", "", time.Second)
	l.FallbackEndpoints = func() []modelroute.Endpoint { return []modelroute.Endpoint{{BaseURL: backup.URL, Model: "backup"}} }
	if _, err := l.Chat(context.Background(), nil, nil); err != nil {
		t.Fatal("连接失败应切服务")
	}
}
