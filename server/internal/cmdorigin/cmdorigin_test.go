package cmdorigin

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTag(t *testing.T) {
	id := uuid.New()
	if got, ok := Tag(map[string]any{"platform_command": map[string]any{"uid": id.String()}}); !ok || got != id {
		t.Fatalf("合法标记应解析出指令 ID: %v %v", got, ok)
	}
	bad := map[string]map[string]any{
		"无标记":        {},
		"nil 事件体":    nil,
		"标记不是对象":     {"platform_command": id.String()},
		"缺 uid":      {"platform_command": map[string]any{}},
		"uid 非字符串":   {"platform_command": map[string]any{"uid": 42}},
		"uid 非 UUID": {"platform_command": map[string]any{"uid": "rm -rf /"}},
		"uid 为空":     {"platform_command": map[string]any{"uid": ""}},
		// 标记必须嵌在 platform_command 里，平铺在顶层不算
		"放错位置": {"uid": id.String()},
	}
	for name, raw := range bad {
		if _, ok := Tag(raw); ok {
			t.Errorf("%s 不应认出标记", name)
		}
	}
}

// failQuerier 被调用即失败：用来证明前置条件不满足时根本不查库
type failQuerier struct{ t *testing.T }

func (f failQuerier) QueryRowContext(context.Context, string, ...any) *sql.Row {
	f.t.Fatal("前置条件不满足时不应查库")
	return nil
}

// 没有标记、没有资产或没有查询入口时直接当作没有指令，不报错
func TestOfShortCircuit(t *testing.T) {
	ctx := context.Background()
	asset := uuid.New()
	tagged := map[string]any{"platform_command": map[string]any{"uid": uuid.NewString()}}
	q := failQuerier{t}

	for name, call := range map[string]func() (*uuid.UUID, error){
		"无标记": func() (*uuid.UUID, error) { return Of(ctx, q, map[string]any{}, &asset, time.Now()) },
		"伪造标记": func() (*uuid.UUID, error) {
			return Of(ctx, q, map[string]any{"platform_command": map[string]any{"uid": "x"}}, &asset, time.Now())
		},
		"无资产":   func() (*uuid.UUID, error) { return Of(ctx, q, tagged, nil, time.Now()) },
		"无查询入口": func() (*uuid.UUID, error) { return Of(ctx, nil, tagged, &asset, time.Now()) },
	} {
		if got, err := call(); got != nil || err != nil {
			t.Errorf("%s: 应返回 nil, nil，实际 %v %v", name, got, err)
		}
	}
}

func TestShellLine(t *testing.T) {
	agent := map[string]any{"file": map[string]any{"path": "/usr/local/bin/openxdr-agent"}}
	if line, ok := shellLine(map[string]any{"cmd_line": "sh -c uptime; df -P"}, agent); !ok || line != "uptime; df -P" {
		t.Fatalf("agent 拉起的 sh -c 应取出原文: %q %v", line, ok)
	}
	for name, c := range map[string]struct{ proc, parent map[string]any }{
		"不是 sh -c":    {map[string]any{"cmd_line": "bash -c uptime"}, agent},
		"sh -c 后为空":   {map[string]any{"cmd_line": "sh -c "}, agent},
		"父进程不是 agent": {map[string]any{"cmd_line": "sh -c uptime"}, map[string]any{"file": map[string]any{"path": "/usr/sbin/sshd"}}},
		"没有父进程":       {map[string]any{"cmd_line": "sh -c uptime"}, nil},
		"没有命令行":       {map[string]any{}, agent},
	} {
		if _, ok := shellLine(c.proc, c.parent); ok {
			t.Errorf("%s 不应认作指令的 sh", name)
		}
	}
}

// 宿主机观测但不是指令 sh、又没有父进程 guid 的事件，不该查库
func TestOfHostObservedNoShellNoQuery(t *testing.T) {
	asset := uuid.New()
	raw := map[string]any{"observed_by": map[string]any{"asset_id": uuid.NewString()}, "process": map[string]any{"cmd_line": "uptime"}}
	if got, err := Of(context.Background(), failQuerier{t}, raw, &asset, time.Now()); got != nil || err != nil {
		t.Fatalf("应返回 nil, nil，实际 %v %v", got, err)
	}
}
