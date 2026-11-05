//go:build integration

package agentchat

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

func TestEndpointEvidencePackageAndContainerTemplatesAndFailClosedBoundaries(t *testing.T) {
	ctx, db := testdb.New(t)
	hub := response.NewHub(db, true)
	gate := &commandgate.Gate{DB: db, Hub: hub, ApprovalTimeout: 2 * time.Second}
	svc := &Service{DB: db, Gate: gate}

	group := db.Group.Create().SetName("ev-template-group").SaveX(ctx)
	if err := commandgate.SeedDefaults(ctx, db, group.ID); err != nil {
		t.Fatal(err)
	}

	agentID := uuid.New()
	inbox := hub.Attach(agentID)
	defer hub.Detach(agentID, inbox)

	host := db.Asset.Create().SetHostname("pve1").SetGroupID(group.ID).SetOs("linux").SetAgentID(agentID).SaveX(ctx)
	peerHost := db.Asset.Create().SetHostname("peer-linux").SetGroupID(group.ID).SetOs("linux").SetAgentID(uuid.New()).SaveX(ctx)

	var reviewerCalls int
	reviewSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model    string           `json:"model"`
			Messages []triage.Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		reviewerCalls++
		if body.Model != "qwen3-template-reviewer" {
			http.Error(w, "wrong model", http.StatusBadRequest)
			return
		}
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"approve\":true,\"reason\":\"受控只读包管理与单容器Web日志模板核验通过\"}"}}]}`))
	}))
	defer reviewSrv.Close()

	svc.AI = func() (string, string, string) {
		return reviewSrv.URL, "test-key", "qwen3-template-reviewer"
	}
	gate.Reviewer = (&commandreview.Reviewer{
		DB:       db,
		Endpoint: func() (string, string) { return reviewSrv.URL, "test-key" },
	}).Review
	db.CommandPolicy.Create().SetGroupID(group.ID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern(`\b(?:journalctl|docker)\b`).SaveX(ctx)

	alertTs := time.Date(2026, 11, 5, 7, 0, 0, 0, time.UTC)

	// 1. 容器模板负例：合成告警（无 event_id）、缺失原始事件、伪造 source（非 agent）、跨资产事件、混合多容器、容器+宿主机混合、注入 UID/VMID 全部 fail-closed
	badCases := []struct {
		name  string
		setup func() uuid.UUID
	}{
		{
			name: "synthetic_alert_without_event",
			setup: func() uuid.UUID {
				inc := db.Incident.Create().SetTitle("合成告警").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
				db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host.ID).SetRuleID("synth.rule").SetSeverity(3).SetTs(alertTs).SaveX(ctx)
				return inc.ID
			},
		},
		{
			name: "missing_raw_event_row",
			setup: func() uuid.UUID {
				inc := db.Incident.Create().SetTitle("缺失原始事件").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
				db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host.ID).SetEventID(uuid.New()).SetRuleID("missing.ev").SetSeverity(3).SetTs(alertTs).SaveX(ctx)
				return inc.ID
			},
		},
		{
			name: "forged_non_agent_source",
			setup: func() uuid.UUID {
				inc := db.Incident.Create().SetTitle("伪造syslog来源").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
				ev := db.Event.Create().SetAssetID(host.ID).SetSource("syslog").SetClassUID(4001).SetTs(alertTs).
					SetRaw(json.RawMessage(`{"container":{"runtime":"lxc","uid":"203","name":"gateway"}}`)).SaveX(ctx)
				db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host.ID).SetEventID(ev.ID).SetRuleID("forged.src").SetSeverity(3).SetTs(alertTs).SaveX(ctx)
				return inc.ID
			},
		},
		{
			name: "cross_asset_event_mismatch",
			setup: func() uuid.UUID {
				inc := db.Incident.Create().SetTitle("跨资产事件").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
				ev := db.Event.Create().SetAssetID(peerHost.ID).SetSource("agent").SetClassUID(4001).SetTs(alertTs).
					SetRaw(json.RawMessage(`{"container":{"runtime":"lxc","uid":"203","name":"gateway"}}`)).SaveX(ctx)
				db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host.ID).SetEventID(ev.ID).SetRuleID("cross.asset").SetSeverity(3).SetTs(alertTs).SaveX(ctx)
				return inc.ID
			},
		},
		{
			name: "mixed_two_docker_containers",
			setup: func() uuid.UUID {
				inc := db.Incident.Create().SetTitle("混合双容器歧义").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
				ev1 := db.Event.Create().SetAssetID(host.ID).SetSource("agent").SetClassUID(1007).SetTs(alertTs).
					SetRaw(json.RawMessage(`{"container":{"runtime":"docker","uid":"978b4e7c6f53","name":"ctf0-web"}}`)).SaveX(ctx)
				ev2 := db.Event.Create().SetAssetID(host.ID).SetSource("agent").SetClassUID(4001).SetTs(alertTs).
					SetRaw(json.RawMessage(`{"container":{"runtime":"docker","uid":"fabb985cea91","name":"ctf0-player"}}`)).SaveX(ctx)
				db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host.ID).SetEventID(ev1.ID).SetRuleID("mix.1").SetSeverity(4).SetTs(alertTs).SaveX(ctx)
				db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host.ID).SetEventID(ev2.ID).SetRuleID("mix.2").SetSeverity(4).SetTs(alertTs).SaveX(ctx)
				return inc.ID
			},
		},
		{
			name: "mixed_container_and_host_event",
			setup: func() uuid.UUID {
				inc := db.Incident.Create().SetTitle("容器与宿主机混合").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
				ev1 := db.Event.Create().SetAssetID(host.ID).SetSource("agent").SetClassUID(1007).SetTs(alertTs).
					SetRaw(json.RawMessage(`{"container":{"runtime":"docker","uid":"978b4e7c6f53","name":"ctf0-web"}}`)).SaveX(ctx)
				ev2 := db.Event.Create().SetAssetID(host.ID).SetSource("agent").SetClassUID(1007).SetTs(alertTs).
					SetRaw(json.RawMessage(`{"process":{"name":"bash"}}`)).SaveX(ctx)
				db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host.ID).SetEventID(ev1.ID).SetRuleID("mix.c").SetSeverity(4).SetTs(alertTs).SaveX(ctx)
				db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host.ID).SetEventID(ev2.ID).SetRuleID("mix.h").SetSeverity(4).SetTs(alertTs).SaveX(ctx)
				return inc.ID
			},
		},
		{
			name: "injected_container_uid",
			setup: func() uuid.UUID {
				inc := db.Incident.Create().SetTitle("注入容器ID").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
				ev := db.Event.Create().SetAssetID(host.ID).SetSource("agent").SetClassUID(4001).SetTs(alertTs).
					SetRaw(json.RawMessage(`{"container":{"runtime":"lxc","uid":"203; id","name":"gateway"}}`)).SaveX(ctx)
				db.Alert.Create().SetIncidentID(inc.ID).SetAssetID(host.ID).SetEventID(ev.ID).SetRuleID("inj.uid").SetSeverity(3).SetTs(alertTs).SaveX(ctx)
				return inc.ID
			},
		},
	}

	for _, tc := range badCases {
		incID := tc.setup()
		var gotToolResp map[string]any
		turns := 0
		llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Messages []triage.Message `json:"messages"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			turns++
			if turns == 1 {
				w.Write([]byte(fmt.Sprintf(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[{"id":"call-bad","type":"function","function":{"name":"collect_endpoint_evidence","arguments":%q}}]}}]}`,
					fmt.Sprintf(`{"asset_id":%q,"template":"linux_container_web_logs"}`, host.ID))))
				return
			}
			for _, m := range req.Messages {
				if m.Role == "tool" && m.ToolCallID == "call-bad" {
					_ = json.Unmarshal([]byte(m.Content), &gotToolResp)
				}
			}
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"verdict\":\"suspicious\",\"confidence\":60,\"summary\":\"容器日志取证因边界不满足被拒绝\\n保留人工补证边界。\",\"kill_chain\":[],\"action_codes\":[\"collect_original_records\"],\"evidence_claims\":[{\"evidence_id\":\"query-1\",\"field\":\"status\",\"value\":\"error\"}]}"}}]}`))
		}))
		eng := &triage.Engine{
			DB:               db,
			LLM:              triage.NewLLM(llmSrv.URL, "triage-model", "", 5*time.Second),
			Interval:         20 * time.Millisecond,
			EndpointEvidence: svc.CollectEndpointEvidence,
		}
		runCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		done := make(chan struct{})
		go func() { defer close(done); eng.Run(runCtx) }()
		for {
			if db.Incident.GetX(ctx, incID).Status == "triaged" {
				break
			}
			select {
			case <-runCtx.Done():
				t.Fatalf("case %s timeout", tc.name)
			case <-time.After(15 * time.Millisecond):
			}
		}
		cancel()
		<-done
		llmSrv.Close()
		if gotToolResp["status"] != "error" || len(inbox) != 0 || db.Command.Query().CountX(ctx) != 0 {
			t.Fatalf("case %s 应 fail-closed 且零下发: resp=%+v commands=%d", tc.name, gotToolResp, db.Command.Query().CountX(ctx))
		}
	}

	// 2. 正例 A：pve1 单 LXC 容器（同时含 1007 进程与 4001 网络事件，container={runtime:lxc,uid:203}）Web 日志模板
	//    + 包管理模板 linux_package_history 返回非零退出码与 EPERM stderr（验证绝不吞掉 stderr 和退出码）
	incOK := db.Incident.Create().SetTitle("pve1 LXC203 gateway 流量与包管理核实").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	evLXC1 := db.Event.Create().SetAssetID(host.ID).SetSource("agent").SetClassUID(1007).SetTs(alertTs).
		SetRaw(json.RawMessage(`{"container":{"runtime":"lxc","uid":"203","name":"gateway"},"process":{"executable":"/usr/bin/caddy"}}`)).SaveX(ctx)
	evLXC2 := db.Event.Create().SetAssetID(host.ID).SetSource("agent").SetClassUID(4001).SetTs(alertTs.Add(2 * time.Minute)).
		SetRaw(json.RawMessage(`{"container":{"runtime":"lxc","uid":"203","name":"gateway"}}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incOK.ID).SetAssetID(host.ID).SetEventID(evLXC1.ID).SetRuleID("lxc.proc").SetSeverity(3).SetTs(alertTs).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incOK.ID).SetAssetID(host.ID).SetEventID(evLXC2.ID).SetRuleID("lxc.net").SetSeverity(3).SetTs(alertTs).SetLastTs(alertTs.Add(2 * time.Minute)).SaveX(ctx)

	agentCtx, stopAgent := context.WithCancel(ctx)
	agentDone := make(chan struct{})
	var seenCmds []string
	go func() {
		defer close(agentDone)
		for {
			select {
			case <-agentCtx.Done():
				return
			case cmd := <-inbox:
				if cmd == nil {
					continue
				}
				seenCmds = append(seenCmds, cmd.Cmd)
				if strings.HasPrefix(cmd.Cmd, "pct exec 203 -- journalctl ") {
					_ = hub.Complete(agentCtx, agentID, &pb.CommandResult{
						CommandId: cmd.Id,
						Status:    pb.CommandResult_SUCCEEDED,
						ExitCode:  0,
						Stdout:    "Nov 05 07:01:00 gateway caddy[101]: 27.18.40.154 GET / HTTP/3.0 200",
					})
				} else if strings.Contains(cmd.Cmd, "/var/log/dpkg.log") {
					_ = hub.Complete(agentCtx, agentID, &pb.CommandResult{
						CommandId: cmd.Id,
						Status:    pb.CommandResult_FAILED,
						ExitCode:  1,
						Stdout:    "-- No entries --",
						Stderr:    "tail: cannot open '/var/log/apt/history.log' for reading: Permission denied",
					})
				}
			}
		}
	}()
	defer func() { stopAgent(); <-agentDone }()

	var webToolResp, pkgToolResp map[string]any
	turns := 0
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []triage.Message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		turns++
		if turns == 1 {
			w.Write([]byte(fmt.Sprintf(`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[
				{"id":"call-web","type":"function","function":{"name":"collect_endpoint_evidence","arguments":%q}},
				{"id":"call-pkg","type":"function","function":{"name":"collect_endpoint_evidence","arguments":%q}}
			]}}]}`,
				fmt.Sprintf(`{"asset_id":%q,"template":"linux_container_web_logs"}`, host.ID),
				fmt.Sprintf(`{"asset_id":%q,"template":"linux_package_history"}`, host.ID),
			)))
			return
		}
		for _, m := range req.Messages {
			if m.Role == "tool" && m.ToolCallID == "call-web" {
				_ = json.Unmarshal([]byte(m.Content), &webToolResp)
			}
			if m.Role == "tool" && m.ToolCallID == "call-pkg" {
				_ = json.Unmarshal([]byte(m.Content), &pkgToolResp)
			}
		}
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"verdict\":\"suspicious\",\"confidence\":70,\"summary\":\"LXC203 读取到 Caddy 日志但包管理日志权限拒绝\\n容器日志不证明业务授权，包管理日志读取返回 Permission denied。\",\"kill_chain\":[],\"action_codes\":[\"collect_original_records\"],\"evidence_claims\":[{\"evidence_id\":\"query-1\",\"field\":\"status\",\"value\":\"succeeded\"},{\"evidence_id\":\"query-1\",\"field\":\"template\",\"value\":\"linux_container_web_logs\"},{\"evidence_id\":\"query-2\",\"field\":\"status\",\"value\":\"failed\"}]}"}}]}`))
	}))
	defer llmSrv.Close()

	eng := &triage.Engine{
		DB:               db,
		LLM:              triage.NewLLM(llmSrv.URL, "triage-model", "", 5*time.Second),
		Interval:         20 * time.Millisecond,
		EndpointEvidence: svc.CollectEndpointEvidence,
	}
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	done := make(chan struct{})
	go func() { defer close(done); eng.Run(runCtx) }()
	for {
		if db.Incident.GetX(ctx, incOK.ID).Status == "triaged" {
			break
		}
		select {
		case <-runCtx.Done():
			t.Fatal("LXC + package history 完整研判超时")
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	<-done

	if len(seenCmds) != 2 || reviewerCalls != 2 {
		t.Fatalf("应恰好下发 2 条受控模板命令并经真实 Reviewer 审核 2 次: cmds=%v reviewerCalls=%d", seenCmds, reviewerCalls)
	}
	if webToolResp["status"] != "succeeded" || !strings.Contains(fmt.Sprint(webToolResp["stdout"]), "HTTP/3.0 200") ||
		!strings.Contains(fmt.Sprint(webToolResp["coverage"]), "不证明业务授权") {
		t.Fatalf("LXC 容器 Web 日志返回异常: %+v", webToolResp)
	}
	if pkgToolResp["status"] != "failed" || pkgToolResp["exit_code"] != float64(1) ||
		!strings.Contains(fmt.Sprint(pkgToolResp["stderr"]), "Permission denied") ||
		!strings.Contains(fmt.Sprint(pkgToolResp["coverage"]), "不等同完整事发时间窗口") {
		t.Fatalf("包管理模板必须原样保留失败退出码与 stderr: %+v", pkgToolResp)
	}

	// 3. 正例 B：单 Docker 容器（1007+4001 同 uid 978b4e7c6f53）生成宿主机 docker logs --timestamps，且重复或 unknown 状态零重放
	incDocker := db.Incident.Create().SetTitle("单Docker容器日志核实").SetStatus("open").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	evD1 := db.Event.Create().SetAssetID(host.ID).SetSource("agent").SetClassUID(1007).SetTs(alertTs).
		SetRaw(json.RawMessage(`{"container":{"runtime":"docker","uid":"978b4e7c6f53","name":"ctf0-web"}}`)).SaveX(ctx)
	evD2 := db.Event.Create().SetAssetID(host.ID).SetSource("agent").SetClassUID(4001).SetTs(alertTs).
		SetRaw(json.RawMessage(`{"container":{"runtime":"docker","uid":"978b4e7c6f53","name":"ctf0-web"}}`)).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incDocker.ID).SetAssetID(host.ID).SetEventID(evD1.ID).SetRuleID("dk.1").SetSeverity(3).SetTs(alertTs).SaveX(ctx)
	db.Alert.Create().SetIncidentID(incDocker.ID).SetAssetID(host.ID).SetEventID(evD2.ID).SetRuleID("dk.2").SetSeverity(3).SetTs(alertTs).SaveX(ctx)

	dockerKey := triage.IncidentEvidenceKey(incDocker)
	dockerCmd := "docker logs --timestamps --since '2026-11-05T06:45:00Z' --until '2026-11-05T07:15:00Z' --tail 40 978b4e7c6f53"
	dockerCmdID := triage.EndpointEvidenceCommandID(incDocker.ID, dockerKey, 0, host.ID, triage.TemplateLinuxContainerWebLogs)
	db.Command.Create().SetID(dockerCmdID).SetAssetID(host.ID).SetIncidentID(incDocker.ID).
		SetKind("exec").SetCmd(dockerCmd).SetStatus("unknown").SetIssuedBy("system").SaveX(ctx)

	resDockerUnknown, err := svc.CollectEndpointEvidence(ctx, triage.EndpointEvidenceRequest{
		IncidentID: incDocker.ID, EvidenceKey: dockerKey, GroupID: group.ID, AssetID: host.ID,
		Template: triage.TemplateLinuxContainerWebLogs, Command: dockerCmd,
	})
	if err != nil || resDockerUnknown.Status != "unknown" || len(seenCmds) != 2 {
		t.Fatalf("Docker 模板 unknown 状态必须零重放: res=%+v err=%v seenCmds=%d", resDockerUnknown, err, len(seenCmds))
	}
}
