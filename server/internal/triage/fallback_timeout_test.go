package triage

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 推理服务连上了但迟迟不回：报「推理超时」并提示调大超时，不报成连接失败
func TestSlowInferenceIsReportedAsTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	l := NewLLM(srv.URL, "m", "", 100*time.Millisecond)
	_, err := l.chatOnce(context.Background(), srv.URL, "m", "", []Message{{Role: "user", Content: "x"}}, nil)
	var transport *LLMTransportError
	if !errors.As(err, &transport) || transport.Timeout != 100*time.Millisecond || !strings.Contains(err.Error(), "AI_TIMEOUT_SECONDS") {
		t.Fatalf("应报推理超时：%v", err)
	}
	close(release)
	srv.Close()
	_, err = l.chatOnce(context.Background(), srv.URL, "m", "", []Message{{Role: "user", Content: "x"}}, nil)
	if !errors.As(err, &transport) || transport.Timeout != 0 || err.Error() != "连接推理服务失败" {
		t.Fatalf("连不上应报连接失败：%v", err)
	}
}
