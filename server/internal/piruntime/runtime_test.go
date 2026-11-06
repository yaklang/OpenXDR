package piruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"openxdr/server/internal/modelroute"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// 用测试二进制模拟损坏或失控的子进程，验证 Go 管理器而非模型行为。
func TestPiProcess(t *testing.T) {
	if os.Getenv("OPENXDR_PI_TEST_CHILD") != "1" {
		return
	}
	var request Request
	decoder := json.NewDecoder(os.Stdin)
	if decoder.Decode(&request) != nil {
		os.Exit(2)
	}
	send := func(value string) { fmt.Println(value) }
	tool := `{"type":"tool_request","call_id":"1","name":"query","args":{"sql":"select 1"}}`
	switch request.Prompt {
	case "roundtrip", "tool_error":
		send(tool)
		var reply struct {
			Success bool
			Output  string
		}
		if decoder.Decode(&reply) != nil {
			os.Exit(3)
		}
		if request.Prompt == "roundtrip" && (!reply.Success || reply.Output != "1") {
			os.Exit(4)
		}
		if request.Prompt == "tool_error" && (reply.Success || reply.Output != "拒绝") {
			os.Exit(5)
		}
		send(`{"type":"result","response":"完成","stop_reason":"stop","turns":2}`)
	case "parallel":
		// 两个调用一起发出，结果按完成顺序回来
		send(`{"type":"tool_request","call_id":"a","name":"query","args":{}}`)
		send(`{"type":"tool_request","call_id":"b","name":"query","args":{}}`)
		got := map[string]bool{}
		for range 2 {
			var reply struct {
				CallID  string `json:"call_id"`
				Success bool
			}
			if decoder.Decode(&reply) != nil || !reply.Success {
				os.Exit(3)
			}
			got[reply.CallID] = true
		}
		if !got["a"] || !got["b"] {
			os.Exit(4)
		}
		send(`{"type":"result","response":"完成","stop_reason":"stop","turns":1}`)
	case "duplicate":
		send(tool)
		var reply any
		_ = decoder.Decode(&reply)
		send(tool)
	case "unknown_tool":
		send(`{"type":"tool_request","call_id":"1","name":"bash","args":{}}`)
	case "malformed":
		send("not json")
	case "missing":
	case "crash":
		os.Exit(7)
	case "timeout":
		time.Sleep(time.Minute)
	case "observe_failure":
		send(tool)
		time.Sleep(time.Minute)
	case "nested_secret":
		send(`{"type":"event","event":{"type":"message_end","message":{"role":"assistant","errorMessage":"test-secret"}}}`)
		send(`{"type":"error","error":"test-secret"}`)
	case "secret":
		send(`{"type":"error","error":"test-secret"}`)
	case "after_result":
		send(`{"type":"result","stop_reason":"stop"}`)
		send(tool)
	}
	os.Exit(0)
}

func testRuntime(t *testing.T) Runtime {
	t.Helper()
	t.Setenv("OPENXDR_PI_TEST_CHILD", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return Runtime{Node: executable, Runner: "-test.run=^TestPiProcess$", Timeout: 3 * time.Second}
}

func TestRuntime(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		calls      int
	}{
		{"roundtrip", "", 1}, {"tool_error", "", 1},
		{"duplicate", "重复", 1}, {"unknown_tool", "未注册", 0},
		{"malformed", "JSONL", 0}, {"missing", "未返回结果", 0},
		{"crash", "子进程失败", 0}, {"observe_failure", "记录 Pi 事件失败", 0},
		{"nested_secret", "已隐藏", 0}, {"secret", "已隐藏", 0}, {"after_result", "最终结果后", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime := testRuntime(t)
			calls := 0
			result, err := runtime.Run(context.Background(), Request{Prompt: tc.name, APIKey: "different-primary-key", FallbackEndpoints: []modelroute.Endpoint{{APIKey: "test-secret"}},
				Tools: []Tool{{Name: "query", Parameters: json.RawMessage(`{"type":"object"}`)}}},
				func(ctx context.Context, name string, args json.RawMessage) (string, error) {
					calls++
					if tc.name == "tool_error" {
						return "", errors.New("拒绝")
					}
					return "1", nil
				}, func(ctx context.Context, event Event) error {
					if tc.name == "observe_failure" {
						return errors.New("数据库不可用")
					}
					data, _ := json.Marshal(event)
					if strings.Contains(string(data), "test-secret") {
						t.Error("记录器收到原始密钥")
					}
					return nil
				})
			if calls != tc.calls {
				t.Fatalf("工具调用次数 %d，预期 %d", calls, tc.calls)
			}
			if tc.want == "" {
				if err != nil || result.Response != "完成" {
					t.Fatalf("result=%+v err=%v", result, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("预期 %q，实际 %v", tc.want, err)
			}
		})
	}
}

// 一次发出的多个工具调用并发处理：一条在等审批或跑长命令，另一条不该排在它后面
func TestRuntimeParallelTools(t *testing.T) {
	runtime := testRuntime(t)
	var calls, active, peak atomic.Int32
	result, err := runtime.Run(context.Background(), Request{Prompt: "parallel", Tools: []Tool{{Name: "query", Parameters: json.RawMessage(`{"type":"object"}`)}}},
		func(ctx context.Context, name string, args json.RawMessage) (string, error) {
			calls.Add(1)
			n := active.Add(1)
			defer active.Add(-1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			time.Sleep(300 * time.Millisecond)
			return "1", nil
		}, func(context.Context, Event) error { return nil })
	if err != nil || result.Response != "完成" || calls.Load() != 2 {
		t.Fatalf("result=%+v err=%v calls=%d", result, err, calls.Load())
	}
	if peak.Load() != 2 {
		t.Fatalf("两个调用应同时在处理，最多只有 %d 个", peak.Load())
	}
}

func TestRuntimeTimeout(t *testing.T) {
	runtime := testRuntime(t)
	runtime.Timeout = 50 * time.Millisecond
	_, err := runtime.Run(context.Background(), Request{Prompt: "timeout"}, nil, func(context.Context, Event) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("预期超时，实际 %v", err)
	}
}

func TestRuntimeRequiresObserver(t *testing.T) {
	_, err := (Runtime{Runner: "unused"}).Run(context.Background(), Request{}, nil, nil)
	if err == nil {
		t.Fatal("不能无记录器运行")
	}
}

func TestRedactJSONPreservesEvidence(t *testing.T) {
	raw := json.RawMessage(`{"n":9007199254740993,"content":[{"errorMessage":"prefix a\\b\"c suffix"}]}`)
	got := redactJSON(raw, "a\\b\"c")
	if !strings.Contains(string(got), "9007199254740993") || !strings.Contains(string(got), "[已隐藏]") {
		t.Fatalf("脱敏改变数值或泄漏凭据: %s", got)
	}
	if strings.Contains(string(raw), "[已隐藏]") {
		t.Fatal("脱敏不得修改原始工具参数")
	}
}
