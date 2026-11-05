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

func TestCollectEndpointEvidenceEventAnchorAndLXCAuthJournal(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("anchor-lxc-group").SaveX(ctx)
	termix := db.Asset.Create().SetHostname("termix").SetGroupID(g.ID).SetOs("linux").SetAgentID(uuid.New()).SaveX(ctx)
	pve := db.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SetOs("linux").SetAgentID(uuid.New()).SaveX(ctx)

	// 1. termix 跨 24h 混合事件：早期失败登录（2026-11-02 18:49:16Z）+ 次日健康检查（2026-11-03 18:21:26Z）
	incTermix := db.Incident.Create().SetTitle("termix 跨天混合告警").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	loginTs := time.Date(2026, 11, 2, 18, 49, 16, 0, time.UTC)
	hcTs := time.Date(2026, 11, 3, 18, 21, 26, 0, time.UTC)
	evLogin := db.Event.Create().SetAssetID(termix.ID).SetSource("agent").SetClassUID(3002).SetTs(loginTs).
		SetRaw(json.RawMessage(`{"user":{"name":"root"},"src_endpoint":{"ip":"10.1.1.170"}}`)).SaveX(ctx)
	evHC := db.Event.Create().SetAssetID(termix.ID).SetSource("agent").SetClassUID(1007).SetTs(hcTs).
		SetRaw(json.RawMessage(`{"container":{"runtime":"docker","uid":"978b4e7c6f53"},"process":{"cmd_line":"nc -z 127.0.0.1 4822"}}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incTermix.ID).SetAssetID(termix.ID).SetEventID(evLogin.ID).SetRuleID("ssh.failed").SetSeverity(3).SetTs(loginTs).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incTermix.ID).SetAssetID(termix.ID).SetEventID(evHC.ID).SetRuleID("netcat.exec").SetSeverity(4).SetTs(hcTs).SaveX(ctx)

	var lastReq EndpointEvidenceRequest
	eTermix := &Engine{
		DB:              db,
		investigationID: incTermix.ID,
		EndpointEvidence: func(_ context.Context, req EndpointEvidenceRequest) (*EndpointEvidenceResult, error) {
			lastReq = req
			exitZero := int32(0)
			return &EndpointEvidenceResult{
				CommandID:  EndpointEvidenceCommandIDWithAnchor(req.IncidentID, req.EvidenceKey, req.EvidenceVersion, req.AssetID, req.Template, req.AnchorEventID, req.Command).String(),
				AssetID:    req.AssetID.String(),
				Template:   req.Template,
				Status:     "succeeded",
				ExitCode:   &exitZero,
				Stdout:     "Nov 02 18:49:16 UTC termix sshd[88]: Failed password for root from 10.1.1.170",
				ObservedAt: hcTs.Add(time.Minute),
				Coverage:   req.Coverage,
			}, nil
		},
	}
	if members, err := eTermix.investigationMembership(ctx); err != nil {
		t.Fatal(err)
	} else {
		eTermix.investigationMembers = members
	}

	// 混合宿主机 + 容器告警在未传 event_id 时拒绝猜测认证日志目标
	unanchoredOut := eTermix.execTool(ctx, "collect_endpoint_evidence", fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal"}`, termix.ID))
	if !strings.Contains(unanchoredOut, `"status":"error"`) || !strings.Contains(unanchoredOut, "event_id") {
		t.Fatalf("混合宿主机与容器告警未传 event_id 时应 fail-closed: %s", unanchoredOut)
	}

	// 传入失败登录 event_id 锚定：精确取 2026-11-02 18:34:16 UTC ~ 19:04:16 UTC 宿主机认证日志
	anchoredOut := eTermix.execTool(ctx, "collect_endpoint_evidence",
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal","event_id":%q}`, termix.ID, evLogin.ID))
	if !strings.Contains(anchoredOut, `"status":"succeeded"`) ||
		!strings.Contains(anchoredOut, `"anchor_event_id":"`+evLogin.ID.String()+`"`) ||
		!strings.Contains(anchoredOut, `"anchor_ts":"2026-11-02T18:49:16Z"`) {
		t.Fatalf("按 event_id 锚定返回异常: %s", anchoredOut)
	}
	wantLoginCmd := "journalctl --no-pager --utc -n 40 --since '2026-11-02 18:34:16 UTC' --until '2026-11-02 19:04:16 UTC' -u ssh -u sshd -t sshd -t sudo -t su"
	if lastReq.Command != wantLoginCmd || !strings.Contains(lastReq.Coverage, "-u 与 -t 为 AND 组合过滤") {
		t.Fatalf("宿主机锚定认证日志命令或覆盖说明错误: cmd=%q cov=%q", lastReq.Command, lastReq.Coverage)
	}
	if err := ValidateEvidenceSnapshots([]EvidenceSnapshot{{Tool: "collect_endpoint_evidence", Result: json.RawMessage(anchoredOut)}}); err != nil {
		t.Fatalf("带 anchor_event_id/anchor_ts 的快照校验失败: %v", err)
	}

	// ps 模板拒绝 event_id，非本事件 event_id 被拒绝，Docker 事件拒绝 linux_auth_journal
	for _, bad := range []string{
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_process_snapshot","event_id":%q}`, termix.ID, evLogin.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal","event_id":%q}`, termix.ID, uuid.New()),
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal","event_id":""}`, termix.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal","event_id":%q}`, termix.ID, evHC.ID),
	} {
		if out := eTermix.execTool(ctx, "collect_endpoint_evidence", bad); !strings.Contains(out, `"status":"error"`) {
			t.Fatalf("非法 event_id 或不支持的容器类型必须被拒绝: args=%s out=%s", bad, out)
		}
	}

	// 2. pve1 单 LXC 容器（vmid=203）：linux_auth_journal 自动进入容器且仅使用 -u ssh -u sshd（不混用 -t）
	incPVE := db.Incident.Create().SetTitle("pve1 LXC203 SSH 会话核实").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	lxcTs := time.Date(2026, 11, 2, 16, 48, 39, 0, time.UTC)
	evLXC := db.Event.Create().SetAssetID(pve.ID).SetSource("agent").SetClassUID(1007).SetTs(lxcTs).
		SetRaw(json.RawMessage(`{"container":{"runtime":"lxc","uid":"203","name":"gateway"},"process":{"cmd_line":"sshd: root [priv]"}}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incPVE.ID).SetAssetID(pve.ID).SetEventID(evLXC.ID).SetRuleID("lxc.ssh").SetSeverity(4).SetTs(lxcTs).SaveX(ctx)

	ePVE := &Engine{
		DB:               db,
		investigationID:  incPVE.ID,
		EndpointEvidence: eTermix.EndpointEvidence,
	}
	if members, err := ePVE.investigationMembership(ctx); err != nil {
		t.Fatal(err)
	} else {
		ePVE.investigationMembers = members
	}
	lxcOut := ePVE.execTool(ctx, "collect_endpoint_evidence", fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal"}`, pve.ID))
	wantLXCCmd := "pct exec 203 -- journalctl --no-pager --utc -n 40 --since '2026-11-02 16:33:39 UTC' --until '2026-11-02 17:03:39 UTC' -u ssh -u sshd"
	if !strings.Contains(lxcOut, `"status":"succeeded"`) || lastReq.Command != wantLXCCmd ||
		strings.Contains(lastReq.Command, "-t ") || !strings.Contains(lastReq.Coverage, "vmid=203") {
		t.Fatalf("单 LXC 容器 linux_auth_journal 生成命令或覆盖范围异常: cmd=%q cov=%q out=%s", lastReq.Command, lastReq.Coverage, lxcOut)
	}
}
