//go:build integration

package triage

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
	"openxdr/server/internal/testdb"
)

func TestCollectEndpointEvidenceToolAndTriageConsumption(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("triage-ev-group").SaveX(ctx)
	host := db.Asset.Create().SetHostname("linux-ssh-1").SetGroupID(g.ID).SetOs("linux").SetAgentID(uuid.New()).SaveX(ctx)
	inc := db.Incident.Create().SetTitle("SSH 登录核实").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	alertTs := time.Date(2026, 11, 5, 6, 0, 0, 0, time.UTC)
	db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host.ID).SetRuleID("ssh.login").SetSeverity(3).SetTs(alertTs).SaveX(ctx)

	var readerCalls int
	var capturedReq EndpointEvidenceRequest
	reader := func(_ context.Context, req EndpointEvidenceRequest) (*EndpointEvidenceResult, error) {
		readerCalls++
		capturedReq = req
		exitZero := int32(0)
		return &EndpointEvidenceResult{
			CommandID:  EndpointEvidenceCommandID(req.IncidentID, req.EvidenceKey, req.EvidenceVersion, req.AssetID, req.Template).String(),
			AssetID:    req.AssetID.String(),
			Template:   req.Template,
			Status:     "succeeded",
			ExitCode:   &exitZero,
			Stdout:     "Nov 05 06:00:01 linux-ssh-1 sshd[99]: Accepted publickey for deploy\n" + strings.Repeat("X", 5000),
			ObservedAt: alertTs.Add(2 * time.Minute),
			Coverage:   req.Coverage,
		}, nil
	}

	var turns int
	var toolResult string
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		turns++
		switch turns {
		case 1:
			w.Write([]byte(fmt.Sprintf(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"ev-call-1","type":"function","function":{"name":"collect_endpoint_evidence","arguments":%q}}]}}]}`,
				fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal"}`, host.ID))))
		default:
			for _, m := range req.Messages {
				if m.Role == "tool" && m.ToolCallID == "ev-call-1" {
					toolResult = m.Content
				}
			}
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"verdict\":\"suspicious\",\"confidence\":65,\"summary\":\"linux-ssh-1 存在公钥登录记录但缺工单验证\\n受控只读认证日志片段已返回（正文被截断，且当前端点快照不是事发完整历史），待核实变更授权。\",\"kill_chain\":[],\"action_codes\":[\"verify_source\",\"monitor\"],\"evidence_claims\":[{\"evidence_id\":\"query-1\",\"field\":\"status\",\"value\":\"succeeded\"},{\"evidence_id\":\"query-1\",\"field\":\"template\",\"value\":\"linux_auth_journal\"},{\"evidence_id\":\"query-1\",\"field\":\"truncated\",\"value\":true}]}"}}]}`))
		}
	}))
	defer llmSrv.Close()

	e := &Engine{
		DB:               db,
		investigationID:  inc.ID,
		EndpointEvidence: reader,
		LLM:              NewLLM(llmSrv.URL, "test-model", "", 10*time.Second),
	}
	members, err := e.investigationMembership(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e.investigationMembers = members

	answer, err := e.investigate(ctx, "# 事件：SSH 登录核实")
	if err != nil {
		t.Fatal(err)
	}
	if readerCalls != 1 {
		t.Fatalf("应调用 1 次受控取证回调，实际 %d", readerCalls)
	}
	if !strings.Contains(capturedReq.Command, "journalctl --no-pager --utc -n 40 --since '2026-11-05 05:45:00 UTC' --until '2026-11-05 06:15:00 UTC'") {
		t.Fatalf("时间窗口命令模板异常: %s", capturedReq.Command)
	}
	if !strings.Contains(toolResult, `"truncated":true`) || !strings.Contains(toolResult, "当前快照不是事发当时的历史完整状态") {
		t.Fatalf("工具返回缺少截断或覆盖说明: %s", toolResult)
	}
	if err := ValidateEvidenceSnapshots([]EvidenceSnapshot{{Tool: "collect_endpoint_evidence", Result: json.RawMessage(toolResult)}}); err != nil {
		t.Fatalf("离线快照白名单未接入 collect_endpoint_evidence: %v", err)
	}
	if !strings.Contains(answer, `"verdict":"suspicious"`) {
		t.Fatalf("同轮研判消费结论异常: %s", answer)
	}
}

func TestCollectEndpointEvidenceRejectsScopeAndParameterTampering(t *testing.T) {
	ctx, db := testdb.New(t)
	ga := db.Group.Create().SetName("ga").SaveX(ctx)
	gb := db.Group.Create().SetName("gb").SaveX(ctx)
	hostA := db.Asset.Create().SetHostname("host-a").SetGroupID(ga.ID).SetOs("linux").SetAgentID(uuid.New()).SaveX(ctx)
	peerA := db.Asset.Create().SetHostname("peer-a").SetGroupID(ga.ID).SetOs("linux").SetAgentID(uuid.New()).SaveX(ctx)
	hostB := db.Asset.Create().SetHostname("host-b").SetGroupID(gb.ID).SetOs("linux").SetAgentID(uuid.New()).SaveX(ctx)

	inc := db.Incident.Create().SetTitle("scope-test").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(hostA.ID).SetRuleID("r1").SetSeverity(3).SetTs(time.Now().UTC()).SaveX(ctx)

	called := false
	e := &Engine{
		DB:              db,
		investigationID: inc.ID,
		EndpointEvidence: func(_ context.Context, _ EndpointEvidenceRequest) (*EndpointEvidenceResult, error) {
			called = true
			return nil, nil
		},
	}

	for _, bad := range []string{
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal","cmd":"id"}`, hostA.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal","path":"/etc/shadow"}`, hostA.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal","group_id":%q}`, hostA.ID, gb.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal","since":"2020-01-01"}`, hostA.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"read_file"}`, hostA.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal"}`, peerA.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal"}`, hostB.ID),
	} {
		out := e.execTool(ctx, "collect_endpoint_evidence", bad)
		if !strings.Contains(out, `"status":"error"`) || called {
			t.Fatalf("越权或篡改参数应被拦截且不触发回调: args=%s out=%s called=%v", bad, out, called)
		}
	}
}
