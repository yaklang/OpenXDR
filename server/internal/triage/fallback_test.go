package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestModelFallbackCooldownAndUsage(t *testing.T) {
	var calls, usage []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model string `json:"model"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		calls = append(calls, body.Model)
		if body.Model == "primary" {
			w.WriteHeader(429)
			return
		}
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"}}],"usage":{"prompt_tokens":3}}`))
	}))
	defer srv.Close()
	l := NewLLM(srv.URL, "primary", "", time.Second)
	l.FallbackModels = func() string { return "backup" }
	l.OnUsage = func(m string, _, _ int) { usage = append(usage, m) }
	for range 2 {
		if _, err := l.Chat(context.Background(), []Message{{Role: "user", Content: "test"}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(calls, []string{"primary", "backup", "backup"}) || !reflect.DeepEqual(usage, []string{"backup", "backup"}) {
		t.Fatalf("调用=%v 用量=%v", calls, usage)
	}
}

func TestModelFallbackDoesNotRetryUnsafeFailures(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 200} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(status)
				w.Write([]byte(`invalid json`))
			}))
			defer srv.Close()
			l := NewLLM(srv.URL, "primary", "", time.Second)
			l.FallbackModels = func() string { return "backup" }
			if _, err := l.Chat(context.Background(), nil, nil); err == nil {
				t.Fatal("应当失败")
			}
			if calls != 1 {
				t.Fatalf("不应重试，调用=%d", calls)
			}
		})
	}
}

func TestModelFallbackSkipsImagesAndCancellation(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(429) }))
	defer srv.Close()
	l := NewLLM(srv.URL, "primary", "", time.Second)
	l.FallbackModels = func() string { return "backup" }
	_, _ = l.Chat(context.Background(), []Message{{Role: "user", Parts: []ContentPart{{Type: "image_url", ImageURL: &ImageURL{URL: "data:image/png;base64,AA=="}}}}}, nil)
	if calls != 1 {
		t.Fatal("图像请求不应切换")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := l.Chat(ctx, nil, nil)
	if err != context.Canceled || calls != 1 {
		t.Fatalf("取消后仍发请求: %v %d", err, calls)
	}
}
