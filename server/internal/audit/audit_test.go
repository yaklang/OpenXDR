package audit

import (
	"context"
	"net/http"
	"testing"
)

func TestActor(t *testing.T) {
	if got := Actor(context.Background()); got != "api" {
		t.Errorf("空上下文 Actor() = %q, want \"api\"", got)
	}

	ctx := WithActor(context.Background(), "alice")
	if got := Actor(ctx); got != "alice" {
		t.Errorf("WithActor 后 Actor() = %q, want \"alice\"", got)
	}

	// 非字符串 value 不应 panic，仍回落默认值
	weird := context.WithValue(context.Background(), actorKey{}, 42)
	if got := Actor(weird); got != "api" {
		t.Errorf("非字符串 actor Actor() = %q, want \"api\"", got)
	}
}

func TestRemoteAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"带端口取主机", "203.0.113.7:8080", "203.0.113.7"},
		{"IPv6 带端口", "[2001:db8::1]:443", "2001:db8::1"},
		{"仅地址原样返回", "203.0.113.7", "203.0.113.7"},
		{"空地址", "", ""},
		{"colon 分隔拆主机", "not-an-addr:port", "not-an-addr"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{RemoteAddr: tc.addr}
			if got := remoteAddr(req); got != tc.want {
				t.Errorf("remoteAddr(%q) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}
