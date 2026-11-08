package findingreview

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/findings"
)

func TestFindingReviewGroundedProofs(t *testing.T) {
	id := uuid.New()
	cmd, out := "systemctl show app.service -p ActiveState -p SubState", "ActiveState=active\nSubState=running\n"
	c := &ent.Command{ID: id, Cmd: &cmd, Stdout: &out}
	good := fmt.Sprintf(`{"approve":true,"reason":"原失败服务已恢复运行","proofs":[{"command_id":"%s","quote":"ActiveState=active"}]}`, id)
	if ok, reason, err := validate(good, []*ent.Command{c}); err != nil || !ok || !strings.Contains(reason, "ActiveState=active") {
		t.Fatalf("%v %s %v", ok, reason, err)
	}
	for _, bad := range []string{
		`{"approve":true,"reason":"looks good","proofs":[]}`,
		strings.Replace(good, "ActiveState=active", "ActiveState=failed", 1),
		strings.Replace(good, id.String(), uuid.NewString(), 1),
		strings.Replace(good, "ActiveState=active", "active", 1),
		good + ` {"approve":true}`,
		strings.Replace(good, `"reason":`, `"extra":1,"reason":`, 1),
	} {
		if ok, _, err := validate(bad, []*ent.Command{c}); err == nil && ok {
			t.Errorf("accepted %s", bad)
		}
	}
	date := "/usr/bin/date"
	c.Cmd = &date
	if ok, _, err := validate(good, []*ent.Command{c}); err == nil || ok {
		t.Fatal("host metadata accepted")
	}
}

func TestFindingReviewerRealModelAndIndependentContext(t *testing.T) {
	now := time.Now()
	asset := uuid.New()
	id := uuid.New()
	cmd, out := "df -P /", "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/root 100000 60000 40000 60% /\n"
	code := int32(0)
	c := &ent.Command{ID: id, AssetID: asset, Kind: "exec", Status: "succeeded", Cmd: &cmd, Stdout: &out, ExitCode: &code, CreatedAt: now, CompletedAt: &now}
	f := &ent.Finding{ID: uuid.New(), AssetID: asset, Key: "disk-full", Title: "本轮模型改写为正常", Detail: "无异常", Work: json.RawMessage(`{"original_title":"根分区96%","original_problem":"根分区空间不足"}`)}
	session := &ent.AgentSession{CreatedAt: now, Model: "stale-model"}
	current := "real-model-a"
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Model != current || len(body.Messages) != 2 || !strings.Contains(body.Messages[1].Content, "根分区96%") || !strings.Contains(body.Messages[1].Content, cmd) {
			t.Errorf("incorrect review material %+v", body)
		}
		calls++
		reply := fmt.Sprintf(`{"approve":true,"reason":"根分区使用率已降为60%%，有40%%余量","proofs":[{"command_id":"%s","quote":"/dev/root 100000 60000 40000 60%% /"}]}`, id)
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": reply}, "finish_reason": "stop"}}})
	}))
	defer server.Close()
	reviewer := &Reviewer{Endpoint: func() (string, string, string) { return server.URL, "", current }}
	for _, model := range []string{"real-model-a", "real-model-b"} {
		current = model
		ok, _, err := reviewer.Review(context.Background(), session, f, []*ent.Command{c}, findings.Resolution{})
		if err != nil || !ok {
			t.Fatalf("%v %v", ok, err)
		}
	}
	c.Status = "unknown"
	if ok, _, err := reviewer.Review(context.Background(), session, f, []*ent.Command{c}, findings.Resolution{}); err == nil || ok {
		t.Fatal("unknown proof accepted")
	}
	if calls != 2 {
		t.Fatalf("invalid proof reached model, calls %d", calls)
	}
	current = ""
	c.Status = "succeeded"
	if ok, _, err := reviewer.Review(context.Background(), session, f, []*ent.Command{c}, findings.Resolution{}); err == nil || ok {
		t.Fatal("empty model accepted")
	}
}
