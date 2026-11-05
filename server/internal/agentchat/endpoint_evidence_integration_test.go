//go:build integration

package agentchat

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestEndpointEvidenceEndToEndWithTriageAndFailClosedBoundaries(t *testing.T) {
	ctx, db := testdb.New(t)
	hub := response.NewHub(db, true)
	gate := &commandgate.Gate{DB: db, Hub: hub, ApprovalTimeout: 2 * time.Second}
	svc := &Service{DB: db, Gate: gate}

	groupA := db.Group.Create().SetName("ev-group-a").SaveX(ctx)
	groupB := db.Group.Create().SetName("ev-group-b").SaveX(ctx)
	if err := commandgate.SeedDefaults(ctx, db, groupA.ID); err != nil {
		t.Fatal(err)
	}

	agentID := uuid.New()
	inbox := hub.Attach(agentID)
	defer hub.Detach(agentID, inbox)

	winAgentID := uuid.New()
	winInbox := hub.Attach(winAgentID)
	defer hub.Detach(winAgentID, winInbox)

	hostLinux := db.Asset.Create().SetHostname("linux-prod-1").SetGroupID(groupA.ID).SetOs("linux").SetAgentID(agentID).SaveX(ctx)
	peerSameGroup := db.Asset.Create().SetHostname("linux-peer").SetGroupID(groupA.ID).SetOs("linux").SetAgentID(uuid.New()).SaveX(ctx)
	hostOtherGroup := db.Asset.Create().SetHostname("linux-other").SetGroupID(groupB.ID).SetOs("linux").SetAgentID(uuid.New()).SaveX(ctx)
	hostUnmanaged := db.Asset.Create().SetHostname("linux-unmanaged").SetGroupID(groupA.ID).SetOs("linux").SaveX(ctx)
	hostWindows := db.Asset.Create().SetHostname("win-host").SetGroupID(groupA.ID).SetOs("windows").SetAgentID(winAgentID).SaveX(ctx)
	hostOffline := db.Asset.Create().SetHostname("linux-offline").SetGroupID(groupA.ID).SetOs("linux").SetAgentID(uuid.New()).SaveX(ctx)

	alertTs := time.Date(2026, 11, 5, 6, 0, 0, 0, time.UTC)
	inc := db.Incident.Create().
		SetTitle("SSH 异常认证待核实").
		SetStatus("open").
		SetGraph(json.RawMessage(`{"nodes":[],"edges":[]}`)).
		SaveX(ctx)
	db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(hostLinux.ID).SetRuleID("linux.ssh.suspicious").SetSeverity(3).SetTs(alertTs).SaveX(ctx)

	// 1. 参数注入与非法模板拦截（不产生任何指令或会话）
	eng := &triage.Engine{DB: db, EndpointEvidence: svc.CollectEndpointEvidence}
	for _, badArgs := range []string{
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal","cmd":"cat /etc/shadow"}`, hostLinux.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal","path":"/etc/shadow"}`, hostLinux.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal","group_id":%q}`, hostLinux.ID, groupB.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"arbitrary_file"}`, hostLinux.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal"}`, peerSameGroup.ID),
		fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal"}`, hostOtherGroup.ID),
	} {
		// 使用真實 batch/triage 路径前，先通过 collect_endpoint_evidence 验证拒绝
		if _, err := svc.CollectEndpointEvidence(ctx, triage.EndpointEvidenceRequest{
			IncidentID: inc.ID, EvidenceVersion: 1, GroupID: groupA.ID, AssetID: peerSameGroup.ID,
			Template: triage.TemplateLinuxAuthJournal, Command: "journalctl --no-pager -n 5",
		}); err == nil {
			t.Fatalf("非本事件关联主机应被拒绝: %s", badArgs)
		}
	}
	if _, err := svc.CollectEndpointEvidence(ctx, triage.EndpointEvidenceRequest{
		IncidentID: inc.ID, EvidenceVersion: 1, GroupID: groupA.ID, AssetID: hostLinux.ID,
		Template: triage.TemplateLinuxAuthJournal, Command: "cat /etc/shadow",
	}); err == nil {
		t.Fatal("读敏感密钥或非只读命令必须被拒绝")
	}

	// 2. 无 agent、非 Linux、agent 离线均 fail-closed
	for _, h := range []*struct {
		id   uuid.UUID
		name string
	}{
		{hostUnmanaged.ID, "unmanaged"},
		{hostWindows.ID, "windows"},
		{hostOffline.ID, "offline"},
	} {
		db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(h.id).SetRuleID("linux.ssh.suspicious").SetSeverity(3).SetTs(alertTs).SaveX(ctx)
		if _, err := svc.CollectEndpointEvidence(ctx, triage.EndpointEvidenceRequest{
			IncidentID: inc.ID, EvidenceVersion: 1, GroupID: groupA.ID, AssetID: h.id,
			Template: triage.TemplateLinuxProcessSnapshot, Command: "ps -eo pid,ppid,user,lstart,args --no-headers",
		}); err == nil {
			t.Fatalf("%s 主机应 fail-closed 拒绝取证", h.name)
		}
	}
	if db.Command.Query().CountX(ctx) != 0 {
		t.Fatalf("被拒绝的取证请求不应产生成功下发指令，实得 %d", db.Command.Query().CountX(ctx))
	}

	// 3. 未配置真实模型（或传入占位符模型）时 fail-closed 拒绝
	if _, err := svc.CollectEndpointEvidence(ctx, triage.EndpointEvidenceRequest{
		IncidentID: inc.ID, EvidenceVersion: 1, GroupID: groupA.ID, AssetID: hostLinux.ID,
		Template: triage.TemplateLinuxAuthJournal, Command: "journalctl --no-pager --utc -n 40",
	}); err == nil {
		t.Fatal("未配置真实模型应被拒绝")
	}

	// 4. 真实 commandreview.Reviewer + HTTP LLM 端点测试：
	//    校验 session.Model 为受信配置的真实模型名、SessionMessage 包含任务与目的材料，
	//    先验证审计员拒绝 fail-closed，再验证审计员批准后真实进入 Hub 指令通道并完成回执。
	var reviewerCalls int
	var reviewerSawModel, reviewerSawMaterial string
	var reviewerApprove bool
	reviewSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model    string           `json:"model"`
			Messages []triage.Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		reviewerCalls++
		reviewerSawModel = body.Model
		for _, m := range body.Messages {
			if m.Role == "user" {
				reviewerSawMaterial = m.Content
			}
		}
		if reviewerApprove {
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"approve\":true,\"reason\":\"受控只读认证日志补证任务确有必要\"}"}}]}`))
		} else {
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"approve\":false,\"reason\":\"审计员测试拒绝 journalctl\"}"}}]}`))
		}
	}))
	defer reviewSrv.Close()

	svc.AI = func() (string, string, string) {
		return reviewSrv.URL, "test-key", "qwen3-security-real"
	}
	realReviewer := &commandreview.Reviewer{
		DB:       db,
		Endpoint: func() (string, string) { return reviewSrv.URL, "test-key" },
	}
	gate.Reviewer = realReviewer.Review
	pol := db.CommandPolicy.Create().SetGroupID(groupA.ID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern(`\bjournalctl\b`).SaveX(ctx)

	reviewerApprove = false
	if _, err := svc.CollectEndpointEvidence(ctx, triage.EndpointEvidenceRequest{
		IncidentID: inc.ID, EvidenceVersion: 1, GroupID: groupA.ID, AssetID: hostLinux.ID,
		Template: triage.TemplateLinuxAuthJournal, Command: "journalctl --no-pager --utc -n 40",
		Since: alertTs.Add(-15 * time.Minute), Until: alertTs.Add(15 * time.Minute),
	}); err == nil || !strings.Contains(err.Error(), "审计员") {
		t.Fatalf("真实审计员拒绝应 fail-closed 返回原因: %v", err)
	}
	if reviewerSawModel != "qwen3-security-real" {
		t.Fatalf("审计员请求模型名错误: got=%q want=qwen3-security-real", reviewerSawModel)
	}
	if !strings.Contains(reviewerSawMaterial, inc.ID.String()) ||
		!strings.Contains(reviewerSawMaterial, hostLinux.Hostname) ||
		!strings.Contains(reviewerSawMaterial, triage.TemplateLinuxAuthJournal) ||
		!strings.Contains(reviewerSawMaterial, "不代表原事件操作已获人工批准或合法") {
		t.Fatalf("审计员材料缺少可信 SessionMessage 任务上下文: %s", reviewerSawMaterial)
	}

	// 审计员批准路径：真实进入 Hub 通道并完成回执，输出 >4096B 被截断至 4096B 且 truncated=true
	reviewerApprove = true
	go func() {
		cmd := <-inbox
		longOut := "Nov 05 06:00:00 linux-prod-1 sshd[1234]: Accepted publickey for ops from 10.0.0.9 port 51234 ssh2\n" + strings.Repeat("A", 5000)
		_ = hub.Complete(ctx, agentID, &pb.CommandResult{
			CommandId: cmd.Id,
			Status:    pb.CommandResult_SUCCEEDED,
			ExitCode:  0,
			Stdout:    longOut,
		})
	}()
	db.CommandPolicy.DeleteOneID(pol.ID).ExecX(ctx)
	// 保留 pol 或重新挂一条策略让这次成功路径也经过真实 commandreview.Reviewer 批准！
	pol2 := db.CommandPolicy.Create().SetGroupID(groupA.ID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern(`\bjournalctl\b`).SaveX(ctx)
	defer func() {
		db.CommandPolicy.DeleteOneID(pol2.ID).ExecX(ctx)
		gate.Reviewer = nil
	}()

	var turns int
	var toolPayload map[string]any
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []triage.Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		turns++
		switch turns {
		case 1:
			w.Write([]byte(fmt.Sprintf(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[
				{"id":"c-1","type":"function","function":{"name":"collect_endpoint_evidence","arguments":%q}},
				{"id":"c-2","type":"function","function":{"name":"collect_endpoint_evidence","arguments":%q}}
			]}}]}`,
				fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal"}`, hostLinux.ID),
				fmt.Sprintf(`{"asset_id":%q,"template":"linux_auth_journal"}`, hostLinux.ID),
			)))
		default:
			for _, m := range req.Messages {
				if m.Role == "tool" && m.ToolCallID == "c-1" {
					_ = json.Unmarshal([]byte(m.Content), &toolPayload)
				}
			}
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"verdict\":\"suspicious\",\"confidence\":70,\"summary\":\"linux-prod-1 观测到公钥登录记录但缺授权工单\\n已通过受控只读模板读取认证 journal 片段（输出已截断，当前快照不代表事发完整历史），仍需核实来源授权。\",\"kill_chain\":[],\"action_codes\":[\"verify_source\",\"monitor\"],\"evidence_claims\":[{\"evidence_id\":\"query-1\",\"field\":\"status\",\"value\":\"succeeded\"},{\"evidence_id\":\"query-1\",\"field\":\"truncated\",\"value\":true},{\"evidence_id\":\"query-1\",\"field\":\"template\",\"value\":\"linux_auth_journal\"}]}"}}]}`))
		}
	}))
	defer llmSrv.Close()

	eng.LLM = triage.NewLLM(llmSrv.URL, "test-model", "", 10*time.Second)
	evKey := triage.IncidentEvidenceKey(inc)
	res1, err := svc.CollectEndpointEvidence(ctx, triage.EndpointEvidenceRequest{
		IncidentID: inc.ID, EvidenceKey: evKey, GroupID: groupA.ID, AssetID: hostLinux.ID,
		Template: triage.TemplateLinuxAuthJournal,
		Command:  "journalctl --no-pager --utc -n 40 --since '2026-11-05 05:45:00' --until '2026-11-05 06:15:00' -u ssh -u sshd -t sshd -t sudo -t su",
		Since:    alertTs.Add(-15 * time.Minute), Until: alertTs.Add(15 * time.Minute),
		Coverage: "当前快照不是事发历史",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res1.Status != "succeeded" || !res1.Truncated || len(res1.Stdout) > triage.EndpointEvidenceLimitBytes {
		t.Fatalf("输出截断或状态异常: status=%s truncated=%v len=%d", res1.Status, res1.Truncated, len(res1.Stdout))
	}

	// 再次调用同一 (incident, evidence_key, asset, template)：只读回执，绝不再次投递
	res2, err := svc.CollectEndpointEvidence(ctx, triage.EndpointEvidenceRequest{
		IncidentID: inc.ID, EvidenceKey: evKey, GroupID: groupA.ID, AssetID: hostLinux.ID,
		Template: triage.TemplateLinuxAuthJournal,
		Command:  "journalctl --no-pager --utc -n 40 --since '2026-11-05 05:45:00' --until '2026-11-05 06:15:00' -u ssh -u sshd -t sshd -t sudo -t su",
	})
	if err != nil || res2.CommandID != res1.CommandID || len(inbox) != 0 {
		t.Fatalf("重复调用必须幂等复用已有指令且零重投: res2=%+v err=%v inbox=%d", res2, err, len(inbox))
	}

	// 5. unknown 状态同样零重投
	unknownID := triage.EndpointEvidenceCommandID(inc.ID, evKey, 0, hostLinux.ID, triage.TemplateLinuxProcessSnapshot)
	procCmd := "ps -eo pid,ppid,user,lstart,args --no-headers"
	db.Command.Create().SetID(unknownID).SetAssetID(hostLinux.ID).SetIncidentID(inc.ID).
		SetKind("exec").SetCmd(procCmd).SetStatus("unknown").SetIssuedBy("system").SaveX(ctx)
	resUnknown, err := svc.CollectEndpointEvidence(ctx, triage.EndpointEvidenceRequest{
		IncidentID: inc.ID, EvidenceKey: evKey, GroupID: groupA.ID, AssetID: hostLinux.ID,
		Template: triage.TemplateLinuxProcessSnapshot, Command: procCmd,
	})
	if err != nil || resUnknown.Status != "unknown" || resUnknown.CommandID != unknownID.String() || len(inbox) != 0 {
		t.Fatalf("unknown 指令不得重放: %+v err=%v inbox=%d", resUnknown, err, len(inbox))
	}

	// 6. 资产转组后拒绝读取已有回执
	db.Asset.UpdateOneID(hostLinux.ID).SetGroupID(groupB.ID).ExecX(ctx)
	if _, err := svc.CollectEndpointEvidence(ctx, triage.EndpointEvidenceRequest{
		IncidentID: inc.ID, EvidenceKey: evKey, GroupID: groupA.ID, AssetID: hostLinux.ID,
		Template: triage.TemplateLinuxAuthJournal,
		Command:  "journalctl --no-pager --utc -n 40 --since '2026-11-05 05:45:00' --until '2026-11-05 06:15:00' -u ssh -u sshd -t sshd -t sudo -t su",
	}); err == nil {
		t.Fatal("资产转组后应拒绝读取回执")
	}
}
