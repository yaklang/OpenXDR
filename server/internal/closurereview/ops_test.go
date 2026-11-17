package closurereview

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/decoy"
	"openxdr/server/internal/sigma"
)

func TestParsePublickeySession(t *testing.T) {
	const fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	raw, _ := json.Marshal(map[string]any{
		"login_session": map[string]any{
			"uid":         "sess-1",
			"user":        "root",
			"src_ip":      "::ffff:10.1.1.3",
			"auth_method": "publickey",
			"key_fp":      fp,
		},
	})
	u, ip, gotFP, uid, ok := parsePublickeySession(raw)
	if !ok || u != "root" || ip != "10.1.1.3" || gotFP != fp || uid != "sess-1" {
		t.Fatalf("解析失败: ok=%v u=%q ip=%q fp=%q uid=%q", ok, u, ip, gotFP, uid)
	}

	bad := []map[string]any{
		{},
		{"login_session": map[string]any{"user": "root", "src_ip": "10.1.1.3", "auth_method": "password", "key_fp": fp}},
		{"login_session": map[string]any{"user": "root", "src_ip": "10.1.1.3", "key_fp": "MD5:aa:bb"}},
		{"login_session": map[string]any{"user": "", "src_ip": "10.1.1.3", "key_fp": fp}},
		{"login_session": map[string]any{"user": "root", "src_ip": "not-ip", "key_fp": fp}},
	}
	for _, m := range bad {
		b, _ := json.Marshal(m)
		if _, _, _, _, ok := parsePublickeySession(b); ok {
			t.Fatalf("不应通过解析: %s", b)
		}
	}
}

func TestOpsAlertAllowed(t *testing.T) {
	rules := []*sigma.Rule{
		{ID: "tmp-exec", Severity: 4, Tactics: []string{"execution"}, Techniques: []string{"T1059.004"}},
		{ID: "crit-deploy", Severity: 5, Tactics: []string{"execution"}, Techniques: []string{"T1204.002"}},
		{ID: "cred-dump", Severity: 3, Tactics: []string{"credential-access"}, Techniques: []string{"T1003.008"}},
		{ID: "log-clear", Severity: 3, Tactics: []string{"defense-evasion"}, Techniques: []string{"T1070.002"}},
		{ID: "impair-def", Severity: 2, Tactics: []string{"defense-evasion"}, Techniques: []string{"T1562.001"}},
		{ID: "data-wipe", Severity: 4, Tactics: []string{"impact"}, Techniques: []string{"T1485"}},
		{ID: "ssh-authkey", Severity: 3, Tactics: []string{"persistence"}, Techniques: []string{"T1098.004"}},
	}
	triagedAt := time.Now()
	evID := uuid.New()
	assetID := uuid.New()
	mk := func(ruleID string, sev int16) *ent.Alert {
		al := &ent.Alert{
			Ts:       triagedAt.Add(-2 * time.Hour),
			Severity: sev,
			RuleID:   ruleID,
			EventID:  &evID,
			AssetID:  &assetID,
		}
		al.Edges.Asset = &ent.Asset{ID: assetID, Hostname: "gateway"}
		return al
	}

	for _, id := range []string{"tmp-exec", "crit-deploy", sigma.RuleNewProcess} {
		if !opsAlertAllowed(mk(id, 4), triagedAt, rules) {
			t.Fatalf("非高危例外规则 %s 应允许进入运维会话核验", id)
		}
	}
	for _, id := range []string{
		"cred-dump",
		"log-clear",
		"impair-def",
		"data-wipe",
		"ssh-authkey",
		sigma.RuleNewSSHKey,
		sigma.RuleControlPlaneChange,
		sigma.RuleAuditTamper,
		"intel:ip:1.2.3.4",
		"unknown-unlisted-rule",
		decoy.ObservationRulePrefix + "ssh",
	} {
		if opsAlertAllowed(mk(id, 3), triagedAt, rules) {
			t.Fatalf("高危或排除规则 %s 不应进入运维会话核验", id)
		}
	}

	after := mk("tmp-exec", 3)
	last := triagedAt.Add(time.Second)
	after.LastTs = &last
	if opsAlertAllowed(after, triagedAt, rules) {
		t.Fatal("研判后仍有新命中的告警不应放行")
	}
}

func TestValidateOpsSessionCitationsAndRouting(t *testing.T) {
	ev1 := uuid.New()
	ev2 := uuid.New()
	assetID := uuid.New()
	m := &material{
		OpsSession: &opsEvidence{
			Sessions: []opsSessionBasis{
				{AssetID: assetID, Hostname: "gateway", KeyFacts: []string{"F-00000001"}, Intents: []string{"I-00000011"}},
				{AssetID: assetID, Hostname: "gateway", KeyFacts: []string{"F-00000002"}, Intents: []string{"I-00000022"}},
			},
			Hosts: []benignHost{{ID: assetID, Hostname: "gateway"}},
		},
		Events: []*ent.Event{
			{ID: ev1, Raw: json.RawMessage(`{"process":{"cmd_line":"/tmp/deploy-1.sh"}}`)},
			{ID: ev2, Raw: json.RawMessage(`{"process":{"cmd_line":"/tmp/deploy-2.sh"}}`)},
		},
	}

	raw, _ := json.Marshal(m)
	if closurePrompt(string(raw)) != opsPrompt+feedbackRule {
		t.Fatal("含 ops_session 的材料应路由到 opsPrompt")
	}
	if s, ok := missingSubject(MissingFact{Kind: "owner", SubjectKind: "asset", Subject: "gateway"}, m, string(raw)); !ok || s != assetID.String() {
		t.Fatalf("ops_session 主机名应解析为资产 ID: ok=%v s=%q", ok, s)
	}

	mkDecision := func(reason string) Decision {
		return Decision{
			Approve:          true,
			Reason:           reason,
			PositiveEvidence: "两条命令均属于已登记部署会话在临时目录执行的部署脚本",
			EventIDs:         []uuid.UUID{ev1, ev2},
			Claims: []Claim{
				{EventID: ev1, Field: "process.cmd_line", Value: "/tmp/deploy-1.sh"},
				{EventID: ev2, Field: "process.cmd_line", Value: "/tmp/deploy-2.sh"},
			},
		}
	}

	if rejection(mkDecision("已核对会话钥匙 F-00000001、F-00000002 与部署意图 I-00000011、I-00000022，行为吻合"), m) != "" {
		t.Fatal("完整引用所有会话钥匙与意图的决定应通过校验")
	}
	for _, badReason := range []string{
		"已核对意图 I-00000011、I-00000022，行为吻合常规部署",
		"已核对钥匙 F-00000001、F-00000002，行为吻合常规部署",
		"已核对会话一钥匙 F-00000001 与意图 I-00000011，行为吻合",
		"已核对钥匙 F-00000001、F-00000002 与意图 I-00000011，漏引第二个意图",
	} {
		if rejection(mkDecision(badReason), m) == "" {
			t.Fatalf("漏引编号的理由不应通过校验: %s", badReason)
		}
	}
}
