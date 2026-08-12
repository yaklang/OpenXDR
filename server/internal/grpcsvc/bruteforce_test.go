package grpcsvc

import (
	"testing"
)

func TestAuthStatus(t *testing.T) {
	cases := []struct {
		raw  map[string]any
		want int
	}{
		// 登录成功与失败正是按 status_id 区分的
		{map[string]any{"status_id": float64(1)}, 1},
		{map[string]any{"status_id": float64(5)}, 5},
		// 报文没带 status_id：默认 0，不 panic
		{map[string]any{}, 0},
		// 字段类型不对（不是 float64）：按 0 处理
		{map[string]any{"status_id": "1"}, 0},
	}
	for _, c := range cases {
		if got := authStatus(c.raw); got != c.want {
			t.Errorf("authStatus(%v) = %d, want %d", c.raw, got, c.want)
		}
	}
}
