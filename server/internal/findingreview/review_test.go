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
	"openxdr/server/internal/clockskew"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/modelroute"
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
	// 按列对齐的输出：引文空格数与原文不同仍算命中，换了内容不算
	ss, listen := "ss -tlnH", "LISTEN 0      4096               *:80               *:*    users:((\"caddy\",pid=1,fd=68))\n"
	col := &ent.Command{ID: id, Cmd: &ss, Stdout: &listen}
	spaced := fmt.Sprintf(`{"approve":true,"reason":"80 端口由 caddy 监听","proofs":[{"command_id":"%s","quote":"LISTEN 0 4096 *:80 *:*"}]}`, id)
	if ok, _, err := validate(spaced, []*ent.Command{col}); err != nil || !ok {
		t.Fatalf("空白数量不同的连续原文应命中：%v %v", ok, err)
	}
	if ok, _, err := validate(strings.Replace(spaced, "*:80", "*:8080", 1), []*ent.Command{col}); err == nil && ok {
		t.Fatal("内容不同的引文不应命中")
	}
	// 一条指令的输出里取两段引文是常态（一条 systemctl show 同时证明两个单元）
	twice := fmt.Sprintf(`{"approve":true,"reason":"服务恢复","proofs":[{"command_id":"%s","quote":"ActiveState=active"},{"command_id":"%s","quote":"SubState=running"}]}`, id, id)
	if ok, _, err := validate(twice, []*ent.Command{c}); err != nil || !ok {
		t.Fatalf("同一条指令的两段引文应被接受：%v %v", ok, err)
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
	// 时钟偏斜容差内（session.CreatedAt - 2s）放行，超出容差（session.CreatedAt - 10s）在调用模型前拒绝。
	c.CreatedAt = session.CreatedAt.Add(-2 * time.Second)
	if ok, _, err := reviewer.Review(context.Background(), session, f, []*ent.Command{c}, findings.Resolution{}); err != nil || !ok || calls != 3 {
		t.Fatalf("容差内复查指令被拒: ok=%v calls=%d err=%v", ok, calls, err)
	}
	c.CreatedAt = session.CreatedAt.Add(-clockskew.Max - 5*time.Second)
	if ok, _, err := reviewer.Review(context.Background(), session, f, []*ent.Command{c}, findings.Resolution{}); err == nil || ok || calls != 3 {
		t.Fatalf("超出容差下界的复查指令未被拒绝: ok=%v calls=%d err=%v", ok, calls, err)
	}
	c.CreatedAt = now
	c.Status = "unknown"
	if ok, _, err := reviewer.Review(context.Background(), session, f, []*ent.Command{c}, findings.Resolution{}); err == nil || ok {
		t.Fatal("unknown proof accepted")
	}
	if calls != 3 {
		t.Fatalf("invalid proof reached model, calls %d", calls)
	}
	current = ""
	c.Status = "succeeded"
	if ok, _, err := reviewer.Review(context.Background(), session, f, []*ent.Command{c}, findings.Resolution{}); err == nil || ok {
		t.Fatal("empty model accepted")
	}
}

func TestFindingReviewerFallbackEndpointsAndTimeout(t *testing.T) {
	now := time.Now()
	asset := uuid.New()
	id := uuid.New()
	cmd, out := "df -P /", "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/root 100000 60000 40000 60% /\n"
	code := int32(0)
	c := &ent.Command{ID: id, AssetID: asset, Kind: "exec", Status: "succeeded", Cmd: &cmd, Stdout: &out, ExitCode: &code, CreatedAt: now, CompletedAt: &now}
	f := &ent.Finding{ID: uuid.New(), AssetID: asset, Key: "disk-full", Title: "根分区满", Detail: "根分区 96%"}
	session := &ent.AgentSession{CreatedAt: now, Model: "primary"}

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream 503", http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer backup-key" {
			t.Errorf("备用端点密钥错误: %q", r.Header.Get("Authorization"))
		}
		reply := fmt.Sprintf(`{"approve":true,"reason":"根分区使用率已降为60%%","proofs":[{"command_id":"%s","quote":"/dev/root 100000 60000 40000 60%% /"}]}`, id)
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": reply}, "finish_reason": "stop"}}})
	}))
	defer backup.Close()

	reviewer := &Reviewer{
		Endpoint: func() (string, string, string) { return primary.URL, "primary-key", "primary-model" },
		FallbackEndpoints: func() []modelroute.Endpoint {
			return []modelroute.Endpoint{{BaseURL: backup.URL, APIKey: "backup-key", Model: "backup-model"}}
		},
		Timeout: 5 * time.Second,
	}
	ok, _, err := reviewer.Review(context.Background(), session, f, []*ent.Command{c}, findings.Resolution{})
	if err != nil || !ok {
		t.Fatalf("主端点 503 后应回退备用端点并通过: ok=%v err=%v", ok, err)
	}

	// 可配置 Timeout 生效
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()
	slowReviewer := &Reviewer{
		Endpoint: func() (string, string, string) { return slow.URL, "", "slow-model" },
		Timeout:  50 * time.Millisecond,
	}
	if ok, _, err := slowReviewer.Review(context.Background(), session, f, []*ent.Command{c}, findings.Resolution{}); err == nil || ok {
		t.Fatal("超时配置未生效")
	}
}
