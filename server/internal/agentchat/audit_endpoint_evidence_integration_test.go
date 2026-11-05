//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent/commandpolicy"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/commandreview"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
	"openxdr/server/internal/triage"
	"openxdr/server/pb"
)

func TestAuditEndpointEvidenceUsesConfiguredReviewerAndTaskContext(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("reviewer-endpoint").SaveX(ctx)
	if err := commandgate.SeedDefaults(ctx, db, g.ID); err != nil {
		t.Fatal(err)
	}
	agent := uuid.New()
	a := db.Asset.Create().SetHostname("reviewed-linux").SetGroupID(g.ID).SetOs("linux").SetAgentID(agent).SaveX(ctx)
	inc := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(a.ID).SetRuleID("audit-endpoint").SetTs(time.Now().Add(-time.Minute)).SetSeverity(3).SaveX(ctx)
	db.CommandPolicy.Create().SetGroupID(g.ID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern(`\bjournalctl\b`).SaveX(ctx)
	const configuredModel = "configured-review-model"
	var reviewerCalled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reviewerCalled.Store(true)
		var req struct {
			Model    string           `json:"model"`
			Messages []triage.Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			http.Error(w, "bad", 400)
			return
		}
		valid := true
		if req.Model != configuredModel {
			t.Errorf("真实Reviewer请求了未配置模型 %q，预期 %q", req.Model, configuredModel)
			valid = false
		}
		material := ""
		for _, m := range req.Messages {
			if m.Role == "user" {
				material += m.Content
			}
		}
		for _, fact := range []string{inc.ID.String(), g.ID.String(), triage.TemplateLinuxAuthJournal} {
			if !strings.Contains(material, fact) {
				t.Errorf("真实Reviewer没有平台任务上下文 %q: %s", fact, material)
				valid = false
			}
		}
		if !valid {
			http.Error(w, "unknown model or missing task context", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": `{"approve":true,"reason":"平台固定只读补证任务与事件调查直接相关"}`}, "finish_reason": "stop"}}})
	}))
	defer srv.Close()
	hub := response.NewHub(db, true)
	inbox := hub.Attach(agent)
	defer hub.Detach(agent, inbox)
	gate := &commandgate.Gate{DB: db, Hub: hub}
	reviewer := &commandreview.Reviewer{DB: db, Endpoint: func() (string, string) { return srv.URL, "" }}
	gate.Reviewer = reviewer.Review
	svc := &Service{DB: db, Gate: gate, AI: func() (string, string, string) { return srv.URL, "", configuredModel }}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case cmd := <-inbox:
			if cmd != nil {
				_ = hub.Complete(work, agent, &pb.CommandResult{CommandId: cmd.Id, Status: pb.CommandResult_SUCCEEDED, Stdout: "authorized read-only journal data"})
			}
		case <-work.Done():
		}
	}()
	defer func() { cancel(); <-done }()
	res, err := svc.CollectEndpointEvidence(ctx, triage.EndpointEvidenceRequest{IncidentID: inc.ID, EvidenceKey: triage.IncidentEvidenceKey(inc), GroupID: g.ID, AssetID: a.ID, Template: triage.TemplateLinuxAuthJournal, Command: "journalctl --no-pager --utc -n 40", Coverage: "固定只读模板"})
	if !reviewerCalled.Load() {
		t.Fatal("未经过真实commandreview.Reviewer调用链")
	}
	if err != nil || res == nil || res.Status != "succeeded" || res.Stdout != "authorized read-only journal data" {
		t.Fatalf("配置正确且审计通过的固定只读补证无法执行: %+v %v", res, err)
	}
	if db.Command.Query().CountX(ctx) != 1 {
		t.Fatal("未按预期下发恰好一条取证命令")
	}
}

func TestAuditEndpointEvidenceFullTriageGateReviewerReceiptLoop(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("end-to-end-evidence").SaveX(ctx)
	if err := commandgate.SeedDefaults(ctx, db, g.ID); err != nil {
		t.Fatal(err)
	}
	agent := uuid.New()
	a := db.Asset.Create().SetHostname("e2e-linux").SetGroupID(g.ID).SetOs("linux").SetAgentID(agent).SaveX(ctx)
	inc := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(a.ID).SetRuleID("audit-full-loop").SetTs(time.Now().Add(-time.Minute)).SetSeverity(3).SaveX(ctx)
	db.CommandPolicy.Create().SetGroupID(g.ID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern(`\bjournalctl\b`).SaveX(ctx)
	sawReceipt := make(chan struct{}, 1)
	reviewCalls := make(chan struct{}, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model    string           `json:"model"`
			Messages []triage.Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			http.Error(w, "bad", 400)
			return
		}
		msg := triage.Message{Role: "assistant"}
		if req.Model == "review-e2e" {
			select {
			case reviewCalls <- struct{}{}:
			default:
			}
			msg.Content = `{"approve":true,"reason":"平台关联事件的固定只读补证"}`
		} else if req.Model == "triage-e2e" {
			returned := ""
			for _, m := range req.Messages {
				if m.Role == "tool" {
					returned = m.Content
				}
			}
			if returned == "" {
				var call triage.ToolCall
				call.ID, call.Type, call.Function.Name = "endpoint-read", "function", "collect_endpoint_evidence"
				args, _ := json.Marshal(map[string]string{"asset_id": a.ID.String(), "template": triage.TemplateLinuxAuthJournal})
				call.Function.Arguments = string(args)
				msg.ToolCalls = []triage.ToolCall{call}
			} else {
				if strings.Contains(returned, "independent-e2e-journal") && strings.Contains(returned, `"status":"succeeded"`) {
					select {
					case sawReceipt <- struct{}{}:
					default:
					}
				}
				msg.Content = `{"verdict":"suspicious","confidence":65,"summary":"端点认证日志已取回，原始活动授权仍未知。","kill_chain":[],"action_codes":["monitor"],"evidence_claims":[{"evidence_id":"query-1","field":"status","value":"succeeded"},{"evidence_id":"query-1","field":"template","value":"linux_auth_journal"}]}`
			}
		} else {
			t.Errorf("错误模型 %q", req.Model)
			http.Error(w, "model", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": msg, "finish_reason": "stop"}}})
	}))
	defer srv.Close()
	hub := response.NewHub(db, true)
	inbox := hub.Attach(agent)
	defer hub.Detach(agent, inbox)
	gate := &commandgate.Gate{DB: db, Hub: hub}
	gate.Reviewer = (&commandreview.Reviewer{DB: db, Endpoint: func() (string, string) { return srv.URL, "" }}).Review
	svc := &Service{DB: db, Gate: gate, AI: func() (string, string, string) { return srv.URL, "", "review-e2e" }}
	run, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		select {
		case cmd := <-inbox:
			if cmd != nil {
				if cmd.Kind != pb.CommandKind_EXEC || !strings.HasPrefix(cmd.Cmd, "journalctl --no-pager --utc -n 40 --since '") {
					t.Error("未下发固定模板", cmd.Cmd)
				}
				_ = hub.Complete(run, agent, &pb.CommandResult{CommandId: cmd.Id, Status: pb.CommandResult_SUCCEEDED, Stdout: "independent-e2e-journal"})
			}
		case <-run.Done():
		}
	}()
	eng := &triage.Engine{DB: db, LLM: triage.NewLLM(srv.URL, "triage-e2e", "", time.Second), Interval: 20 * time.Millisecond, EndpointEvidence: svc.CollectEndpointEvidence}
	engineDone := make(chan struct{})
	go func() { defer close(engineDone); eng.Run(run) }()
	defer func() { cancel(); <-agentDone; <-engineDone }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-run.Done():
			t.Fatal("完整研判-真实审核-Gate-Hub-回执-研判落库链没有完成")
		case <-ticker.C:
			got, err := db.Incident.Get(ctx, inc.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != "triaged" {
				continue
			}
			if len(sawReceipt) == 0 || len(reviewCalls) != 1 || db.Command.Query().CountX(ctx) != 1 {
				t.Fatalf("链路未串通或重复执行: receipt=%d reviews=%d commands=%d", len(sawReceipt), len(reviewCalls), db.Command.Query().CountX(ctx))
			}
			if !strings.Contains(string(got.AiVerdict), "succeeded") {
				t.Fatal("研判没有保存真实工具证据", string(got.AiVerdict))
			}
			return
		}
	}
}
