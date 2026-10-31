package agentchat

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"
	"openxdr/server/ent"
)

func TestUnknownCommandIsNotSuccessfulToolResult(t *testing.T) {
	id := uuid.New()
	output, err := (&Service{}).waitCommand(context.Background(), &ent.Command{ID: id, Status: "unknown"}, 1)
	if err == nil || output != "" || !strings.Contains(err.Error(), id.String()) || !strings.Contains(err.Error(), "禁止自动重试") {
		t.Fatalf("未知结果被当作成功: %q %v", output, err)
	}
}

func TestCommandOutputBoundedWithoutChangingReceipt(t *testing.T) {
	stdout, stderr := strings.Repeat("中", 30000), strings.Repeat("e", 20000)
	original := &ent.Command{ID: uuid.New(), Status: "succeeded", Stdout: &stdout, Stderr: &stderr}
	output, err := (&Service{}).waitCommand(context.Background(), original, 1)
	if err != nil {
		t.Fatal(err)
	}
	var got ent.Command
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || len(*got.Stdout) > modelOutputLimit || len(*got.Stderr) > modelOutputLimit || !utf8.ValidString(*got.Stdout) {
		t.Fatalf("模型回执未正确裁剪: %+v", got)
	}
	if original.Truncated || len(*original.Stdout) != 90000 || len(*original.Stderr) != 20000 {
		t.Fatal("完整命令回执被修改")
	}
	short := "完整输出"
	original.Stdout, original.Stderr = &short, nil
	output, err = (&Service{}).waitCommand(context.Background(), original, 1)
	if err != nil {
		t.Fatal(err)
	}
	got = ent.Command{}
	if err = json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatal(err)
	}
	if got.Truncated || *got.Stdout != short || got.Stderr != nil {
		t.Fatal("短输出不应截断或填充")
	}
}

func TestTurnBudget(t *testing.T) {
	cases := [][3]int{{0, 0, 32}, {1, 0, 52}, {2, 0, 72}, {2, 5, 77}, {50, 0, 256}}
	for _, c := range cases {
		if got := turnBudget(c[0], c[1]); got != c[2] {
			t.Errorf("turnBudget(%d, %d) = %d, want %d", c[0], c[1], got, c[2])
		}
	}
}

func TestCommandReceiptsDoNotClaimEffectOrRetry(t *testing.T) {
	for _, status := range []string{"succeeded", "failed", "unsupported"} {
		id := uuid.New()
		out, err := (&Service{}).waitCommand(context.Background(), &ent.Command{ID: id, Status: status}, 1)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			ID                    uuid.UUID
			Status, Effect, Retry string
		}
		if err := json.Unmarshal([]byte(out), &result); err != nil || result.ID != id || result.Status != status || result.Effect != "not_assessed_by_this_tool" || result.Retry != "not_authorized_by_this_tool" {
			t.Fatalf("回执语义错误: %s %v", out, err)
		}
	}
	for _, status := range []string{"pending", "sent", "unknown"} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		id := uuid.New()
		out, err := (&Service{}).waitCommand(ctx, &ent.Command{ID: id, Status: status}, 1)
		if err == nil || out != "" || !strings.Contains(err.Error(), id.String()) || !strings.Contains(err.Error(), "command_status") || !strings.Contains(err.Error(), "禁止自动重试") {
			t.Fatalf("丢失追溯入口: %q %v", out, err)
		}
	}
}

func TestStorableJSONSanitizesNulForPostgresJSONB(t *testing.T) {
	clean := json.RawMessage(`{"role":"toolResult","content":[{"type":"text","text":"normal output"}]}`)
	if got := storableJSON(clean); string(got) != string(clean) {
		t.Fatalf("干净 JSON 不应被改动: %s", got)
	}

	raw := json.RawMessage("{\"role\":\"toolResult\",\"text\":\"a\\u0000b\\U0000c\\\\u0000d\\\\\\u0000e\x00f\"}")
	got := storableJSON(raw)
	if strings.Contains(string(got), `\u0000`) && !strings.Contains(string(got), `\\u0000`) {
		t.Fatalf("未转义的 \\u0000 应被替换: %s", got)
	}
	var parsed struct {
		Role string `json:"role"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("清理后仍应是合法 JSON: %v (%s)", err, got)
	}
	want := `a␀b␀c\u0000d\␀e␀f`
	if parsed.Text != want {
		t.Fatalf("parsed.Text = %q, want %q", parsed.Text, want)
	}
}
