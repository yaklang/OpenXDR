//go:build integration

package closurereview

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/question"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/decoy"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
)

const (
	opsKeyFP  = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	opsKeyFP2 = "SHA256:2jmj7l5rSw0yVb/vlWAYkK/YBwk2jmj7l5rSw0yVb/s"
	opsSrcIP  = "10.1.1.3"
	opsHolder = "integration:kei-wsl"
)

type opsFixture struct {
	ctx       context.Context
	db        *ent.Client
	group     *ent.Group
	asset     *ent.Asset
	otherHost *ent.Asset
	keyFact   *ent.Fact
	intent    *ent.Intent
	sshdEv    *ent.Event
	parentEv  *ent.Event
	childEv   *ent.Event
	alParent  *ent.Alert
	alChild   *ent.Alert
	inc       *ent.Incident
	rules     []*sigma.Rule
	r         *Reviewer
	calls     int
	lastMat   string
}

func testOpsRules() []*sigma.Rule {
	return []*sigma.Rule{
		{ID: "tmp-script-exec", Severity: 4, Tactics: []string{"execution"}, Techniques: []string{"T1059.004"}},
		{ID: "tmp-bin-run", Severity: 5, Tactics: []string{"execution"}, Techniques: []string{"T1204.002"}},
		{ID: "cred-dump", Severity: 3, Tactics: []string{"credential-access"}, Techniques: []string{"T1003.008"}},
		{ID: "log-clear", Severity: 3, Tactics: []string{"defense-evasion"}, Techniques: []string{"T1070.002"}},
		{ID: "impair-def", Severity: 2, Tactics: []string{"defense-evasion"}, Techniques: []string{"T1562.001"}},
		{ID: "data-wipe", Severity: 4, Tactics: []string{"impact"}, Techniques: []string{"T1485"}},
		{ID: "ssh-authkey-add", Severity: 3, Tactics: []string{"persistence"}, Techniques: []string{"T1098.004"}},
	}
}

// setupOpsSession 构造真实的每机非共享钥匙 + 会话登录前登记意图 + 核心资产 /tmp 临时脚本执行后删除场景：
//   - sshd 守护进程（无 login_session）拉起会话首进程 bash（带公钥 login_session，触发高危告警）；
//   - bash 拉起子进程 /tmp/kei-deploy.sh（自身无顶层 login_session，须沿 parent_process_guid 追回父进程会话，触发严重级告警）；
//   - 因 /tmp 脚本执行后已删除无法回看内容，研判标为 suspicious + observe。
func setupOpsSession(t *testing.T) *opsFixture {
	t.Helper()
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	intentAt := now.Add(-3*time.Hour - 20*time.Minute)
	loginAt := now.Add(-3*time.Hour - 10*time.Minute)
	execAt := now.Add(-3 * time.Hour)
	triagedAt := execAt.Add(2 * time.Minute)

	g := db.Group.Create().SetName("infra").SaveX(ctx)
	asset := db.Asset.Create().SetHostname("gateway").SetGroupID(g.ID).SetResponseTier("core").SaveX(ctx)
	otherHost := db.Asset.Create().SetHostname("cache").SetGroupID(g.ID).SaveX(ctx)

	kf := db.Fact.Create().
		SetCreatedAt(intentAt.Add(-24 * time.Hour)).
		SetKind("key").
		SetSubject(opsKeyFP).
		SetGroupID(g.ID).
		SetHolder(opsHolder).
		SetShared(false).
		SetContent("Bifrost WSL 专用运维钥匙 kei_ed25519").
		SetCreatedBy("admin").
		SaveX(ctx)

	in := db.Intent.Create().
		SetCreatedAt(intentAt).
		SetCreatedBy(opsHolder).
		SetKeyFingerprint(opsKeyFP).
		SetSourceAddr(opsSrcIP).
		SetAssetIds([]uuid.UUID{asset.ID}).
		SetCategory("deploy").
		SetNote("更新网关 Caddy 反向代理配置并重载").
		SetStartsAt(intentAt).
		SetExpiresAt(intentAt.Add(2 * time.Hour)).
		SetLate(false).
		SaveX(ctx)

	db.SSHLogin.Create().
		SetID(uuid.New()).
		SetTs(loginAt).
		SetAssetID(asset.ID).
		SetGroupID(g.ID).
		SetLoginUser("root").
		SetSrcIP(opsSrcIP).
		SetAuthMethod("publickey").
		SetKeyFp(opsKeyFP).
		SaveX(ctx)

	sshdGUID := uuid.New()
	bashGUID := uuid.New()
	scriptGUID := uuid.New()

	sshdRaw, _ := json.Marshal(map[string]any{
		"activity_id": 1,
		"process":     map[string]any{"cmd_line": "sshd: root [priv]", "pid": 1001, "executable": "/usr/sbin/sshd"},
	})
	sshdEv := db.Event.Create().
		SetTs(loginAt).
		SetAssetID(asset.ID).
		SetSource("agent").
		SetClassUID(1007).
		SetProcessGUID(sshdGUID).
		SetRaw(sshdRaw).
		SaveX(ctx)

	parentCmd := "bash -c /tmp/kei-deploy.sh --reload && rm -f /tmp/kei-deploy.sh"
	parentRaw, _ := json.Marshal(map[string]any{
		"activity_id": 1,
		"process":     map[string]any{"cmd_line": parentCmd, "pid": 1020, "executable": "/usr/bin/bash"},
		"login_session": map[string]any{
			"uid":         "ssh-42",
			"user":        "root",
			"src_ip":      opsSrcIP,
			"auth_method": "publickey",
			"key_fp":      opsKeyFP,
		},
	})
	parentEv := db.Event.Create().
		SetTs(execAt).
		SetAssetID(asset.ID).
		SetSource("agent").
		SetClassUID(1007).
		SetProcessGUID(bashGUID).
		SetParentProcessGUID(sshdGUID).
		SetRaw(parentRaw).
		SaveX(ctx)

	childCmd := "/bin/sh /tmp/kei-deploy.sh --reload"
	childRaw, _ := json.Marshal(map[string]any{
		"activity_id": 1,
		"process":     map[string]any{"cmd_line": childCmd, "pid": 1021, "executable": "/tmp/kei-deploy.sh"},
	})
	childEv := db.Event.Create().
		SetTs(execAt.Add(time.Second)).
		SetAssetID(asset.ID).
		SetSource("agent").
		SetClassUID(1007).
		SetProcessGUID(scriptGUID).
		SetParentProcessGUID(bashGUID).
		SetRaw(childRaw).
		SaveX(ctx)

	inc := db.Incident.Create().
		SetCreatedAt(execAt).
		SetEvidenceAt(execAt.Add(time.Second)).
		SetGraph(json.RawMessage(`{}`)).
		SetStatus("triaged").
		SetTriagedAt(triagedAt).
		SetAiVerdict(json.RawMessage(`{"verdict":"suspicious","response_tier":"observe","action_codes":["review_closure","monitor"]}`)).
		SaveX(ctx)

	alParent := db.Alert.Create().
		SetTs(parentEv.Ts).
		SetAssetID(asset.ID).
		SetEventID(parentEv.ID).
		SetIncidentID(inc.ID).
		SetSeverity(4).
		SetRuleID("tmp-script-exec").
		SaveX(ctx)

	alChild := db.Alert.Create().
		SetTs(childEv.Ts).
		SetAssetID(asset.ID).
		SetEventID(childEv.ID).
		SetIncidentID(inc.ID).
		SetSeverity(5).
		SetRuleID("tmp-bin-run").
		SaveX(ctx)

	rules := testOpsRules()
	f := &opsFixture{
		ctx:       ctx,
		db:        db,
		group:     g,
		asset:     asset,
		otherHost: otherHost,
		keyFact:   kf,
		intent:    in,
		sshdEv:    sshdEv,
		parentEv:  parentEv,
		childEv:   childEv,
		alParent:  alParent,
		alChild:   alChild,
		inc:       inc,
		rules:     rules,
	}
	f.r = &Reviewer{
		DB:    db,
		Rules: func() []*sigma.Rule { return f.rules },
		Model: func() string { return "test-auditor" },
		Judge: func(_ context.Context, _, mat string) (Decision, error) {
			f.calls++
			f.lastMat = mat
			return Decision{
				Approve: true,
				Reason: "发起会话核验匹配专用钥匙 " + facts.Ref("F", f.keyFact.ID) +
					" 与登录前登记的部署意图 " + facts.Ref("I", f.intent.ID) + "，临时脚本执行后清理由部署流程产生",
				PositiveEvidence: "父进程 bash -c /tmp/kei-deploy.sh --reload 与子进程均由已登记 SSH 部署会话直接拉起，无攻击特征",
				EventIDs:         []uuid.UUID{f.parentEv.ID, f.childEv.ID},
				Claims: []Claim{
					{EventID: f.parentEv.ID, Field: "raw.process.cmd_line", Value: parentCmd},
					{EventID: f.childEv.ID, Field: "raw.process.cmd_line", Value: childCmd},
				},
			}, nil
		},
	}
	return f
}

func TestOpsSessionCloseWithLineageAndTmpScript(t *testing.T) {
	f := setupOpsSession(t)
	var usedPrompt string
	origJudge := f.r.Judge
	f.r.Judge = func(ctx context.Context, model, mat string) (Decision, error) {
		usedPrompt = closurePrompt(mat)
		return origJudge(ctx, model, mat)
	}

	ok, err := f.r.Review(f.ctx, f.inc.ID)
	if err != nil || !ok {
		t.Fatalf("期望运维会话审计通过结案: ok=%v err=%v", ok, err)
	}
	if usedPrompt != opsPrompt {
		t.Fatal("应使用运维会话专用审计提示词 opsPrompt")
	}
	if !strings.Contains(f.lastMat, facts.Ref("F", f.keyFact.ID)) || !strings.Contains(f.lastMat, facts.Ref("I", f.intent.ID)) {
		t.Fatalf("审计材料应包含钥匙事实与意图编号: %s", f.lastMat)
	}

	inc := f.db.Incident.GetX(f.ctx, f.inc.ID)
	if inc.Status != "closed" {
		t.Fatalf("运维会话必须按 closed 结案（禁止标 false_positive），实际 status=%s", inc.Status)
	}
	if inc.ResolvedBy == nil || *inc.ResolvedBy != "system" {
		t.Fatalf("resolved_by 应为 system: %v", inc.ResolvedBy)
	}
	if inc.ResolutionSource == nil || *inc.ResolutionSource != OpsSessionSource {
		t.Fatalf("resolution_source 应为 %q: %v", OpsSessionSource, inc.ResolutionSource)
	}
	if inc.Resolution == nil ||
		!strings.Contains(*inc.Resolution, facts.Ref("F", f.keyFact.ID)) ||
		!strings.Contains(*inc.Resolution, facts.Ref("I", f.intent.ID)) ||
		!strings.Contains(*inc.Resolution, "root@gateway") {
		t.Fatalf("结案说明应写明钥匙编号、意图编号与会话主机: %v", inc.Resolution)
	}

	kf := f.db.Fact.GetX(f.ctx, f.keyFact.ID)
	if kf.CitedCount != 1 || kf.LastCitedAt == nil {
		t.Fatalf("结案应累计所引钥匙事实的引用计数: cited=%d last=%v", kf.CitedCount, kf.LastCitedAt)
	}
	if !f.db.AuditLog.Query().Where(
		auditlog.ActionEQ("incident_closure_ai_reviewed"),
		auditlog.TargetEQ(f.inc.ID.String()),
		auditlog.DetailContains("approved=true mechanism=ops_session"),
	).ExistX(f.ctx) {
		t.Fatal("应写入 mechanism=ops_session 的结案审计日志")
	}

	// 幂等：已结案事件再次调用不重审
	if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil || f.calls != 1 {
		t.Fatalf("已结案事件不应重复调用模型: ok=%v err=%v calls=%d", ok, err, f.calls)
	}

	// 验证已遏制威胁重开检查（ReopenContained）不会误把 ops_session 已关闭事件重开
	laterEv := f.db.Event.Create().
		SetTs(time.Now().UTC()).
		SetAssetID(f.asset.ID).
		SetSource("agent").
		SetClassUID(1007).
		SetRaw(json.RawMessage(`{"process":{"cmd_line":"/usr/bin/bash -l","executable":"/usr/bin/bash"}}`)).
		SaveX(f.ctx)
	f.db.Alert.Create().
		SetTs(laterEv.Ts).
		SetAssetID(f.asset.ID).
		SetEventID(laterEv.ID).
		SetSeverity(3).
		SetRuleID("tmp-script-exec").
		SaveX(f.ctx)

	tx, err := f.db.Tx(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ReopenContained(f.ctx, tx); err != nil {
		_ = tx.Rollback()
		t.Fatalf("ReopenContained 执行失败: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := f.db.Incident.GetX(f.ctx, f.inc.ID).Status; got != "closed" {
		t.Fatalf("ops_session 结案事件不应被 ReopenContained 重开, got=%s", got)
	}
}

// 同一把钥匙两天前有过历史登录，今天先登记意图再新开 SSH 会话：历史旧登录记录不应误伤本次新会话
func TestOpsSessionHistoricalLoginDoesNotBlockFreshSession(t *testing.T) {
	f := setupOpsSession(t)
	f.db.SSHLogin.Create().
		SetID(uuid.New()).
		SetTs(f.intent.CreatedAt.Add(-48 * time.Hour)).
		SetAssetID(f.asset.ID).
		SetGroupID(f.group.ID).
		SetLoginUser("root").
		SetSrcIP(opsSrcIP).
		SetAuthMethod("publickey").
		SetKeyFp(opsKeyFP).
		SaveX(f.ctx)

	ok, err := f.r.Review(f.ctx, f.inc.ID)
	if err != nil || !ok {
		t.Fatalf("两天前的历史旧登录不应阻塞重新登录的新会话结案: ok=%v err=%v", ok, err)
	}
}

func TestOpsSessionDisqualifiers(t *testing.T) {
	cases := map[string]func(*opsFixture){
		"shared_key": func(f *opsFixture) {
			f.db.Fact.UpdateOneID(f.keyFact.ID).SetShared(true).ExecX(f.ctx)
		},
		"shared_key_global_override": func(f *opsFixture) {
			// 即使组内有一条未标 shared 的同指纹事实，只要可见域内存在任一条标为 shared=true 的同指纹事实，一律排除
			f.db.Fact.Create().
				SetKind("key").
				SetSubject(opsKeyFP).
				SetHolder(opsHolder).
				SetShared(true).
				SetContent("全局标记为多人共用的过渡管理钥匙").
				SetCreatedBy("admin").
				ExecX(f.ctx)
		},
		"unclaimed_key": func(f *opsFixture) {
			f.db.Fact.DeleteOneID(f.keyFact.ID).ExecX(f.ctx)
		},
		"retired_key_fact": func(f *opsFixture) {
			f.db.Fact.UpdateOneID(f.keyFact.ID).SetRetiredAt(time.Now().Add(-time.Hour)).SetRetiredBy("admin").ExecX(f.ctx)
		},
		"expired_key_fact": func(f *opsFixture) {
			f.db.Fact.UpdateOneID(f.keyFact.ID).SetExpiresAt(time.Now().Add(-time.Minute)).ExecX(f.ctx)
		},
		"holder_mismatch": func(f *opsFixture) {
			f.db.Fact.UpdateOneID(f.keyFact.ID).SetHolder("user:other").ExecX(f.ctx)
		},
		"no_intent": func(f *opsFixture) {
			f.db.Intent.DeleteOneID(f.intent.ID).ExecX(f.ctx)
		},
		"late_intent_flag": func(f *opsFixture) {
			f.db.Intent.UpdateOneID(f.intent.ID).SetLate(true).ExecX(f.ctx)
		},
		"intent_created_after_process_start": func(f *opsFixture) {
			// 即使 late=false，登记时间晚于会话进程时间也必须拒绝
			f.db.Intent.UpdateOneID(f.intent.ID).SetCreatedAt(f.parentEv.Ts.Add(time.Second)).ExecX(f.ctx)
		},
		"intent_created_after_ssh_login_on_long_lived_session": func(f *opsFixture) {
			// 长连接旧会话：没有追到 sshd 根进程，且 ssh_logins 记录早在意图登记之前就已登录
			f.db.Event.UpdateOneID(f.parentEv.ID).ClearParentProcessGUID().ExecX(f.ctx)
			f.db.SSHLogin.Delete().ExecX(f.ctx)
			f.db.SSHLogin.Create().
				SetID(uuid.New()).
				SetTs(f.intent.CreatedAt.Add(-15 * time.Minute)).
				SetAssetID(f.asset.ID).
				SetGroupID(f.group.ID).
				SetLoginUser("root").
				SetSrcIP(opsSrcIP).
				SetAuthMethod("publickey").
				SetKeyFp(opsKeyFP).
				SaveX(f.ctx)
		},
		"intent_wrong_asset": func(f *opsFixture) {
			f.db.Intent.UpdateOneID(f.intent.ID).SetAssetIds([]uuid.UUID{f.otherHost.ID}).ExecX(f.ctx)
		},
		"intent_wrong_source_ip": func(f *opsFixture) {
			f.db.Intent.UpdateOneID(f.intent.ID).SetSourceAddr("10.1.1.36").ExecX(f.ctx)
		},
		"intent_wrong_key_fp": func(f *opsFixture) {
			f.db.Intent.UpdateOneID(f.intent.ID).SetKeyFingerprint(opsKeyFP2).ExecX(f.ctx)
		},
		"intent_expired_before_event": func(f *opsFixture) {
			f.db.Intent.UpdateOneID(f.intent.ID).SetExpiresAt(f.parentEv.Ts.Add(-time.Minute)).ExecX(f.ctx)
		},
		"intent_ended_early_before_event": func(f *opsFixture) {
			f.db.Intent.UpdateOneID(f.intent.ID).SetEndedAt(f.parentEv.Ts.Add(-time.Minute)).SetEndedBy(opsHolder).ExecX(f.ctx)
		},
		"intent_starts_after_login": func(f *opsFixture) {
			f.db.Intent.UpdateOneID(f.intent.ID).SetStartsAt(f.parentEv.Ts.Add(-time.Minute)).ExecX(f.ctx)
		},
		"high_risk_credential_access": func(f *opsFixture) {
			f.db.Alert.UpdateOneID(f.alChild.ID).SetRuleID("cred-dump").SetSeverity(3).ExecX(f.ctx)
		},
		"high_risk_log_clear": func(f *opsFixture) {
			f.db.Alert.UpdateOneID(f.alChild.ID).SetRuleID("log-clear").SetSeverity(3).ExecX(f.ctx)
		},
		"high_risk_defense_impairment": func(f *opsFixture) {
			f.db.Alert.UpdateOneID(f.alChild.ID).SetRuleID("impair-def").SetSeverity(2).ExecX(f.ctx)
		},
		"high_risk_impact_wipe": func(f *opsFixture) {
			f.db.Alert.UpdateOneID(f.alChild.ID).SetRuleID("data-wipe").SetSeverity(4).ExecX(f.ctx)
		},
		"high_risk_add_authorized_key_sigma": func(f *opsFixture) {
			f.db.Alert.UpdateOneID(f.alChild.ID).SetRuleID("ssh-authkey-add").SetSeverity(3).ExecX(f.ctx)
		},
		"high_risk_new_ssh_key_builtin": func(f *opsFixture) {
			f.db.Alert.UpdateOneID(f.alChild.ID).SetRuleID(sigma.RuleNewSSHKey).SetSeverity(4).ExecX(f.ctx)
		},
		"high_risk_intel_hit": func(f *opsFixture) {
			f.db.Alert.UpdateOneID(f.alChild.ID).SetRuleID("intel:ip:198.51.100.9").SetSeverity(4).ExecX(f.ctx)
		},
		"decoy_observation": func(f *opsFixture) {
			f.db.Alert.UpdateOneID(f.alChild.ID).SetRuleID(decoy.ObservationRulePrefix + "ssh").SetSeverity(3).ExecX(f.ctx)
		},
		"partial_alerts_unattributed": func(f *opsFixture) {
			// 第 1 条满足运维会话，第 2 条既无 login_session 也追不到父进程 sshd 会话 → 整起事件不得放行
			f.db.Event.UpdateOneID(f.childEv.ID).ClearParentProcessGUID().ExecX(f.ctx)
		},
		"partial_alerts_shared_key": func(f *opsFixture) {
			// 第 1 条是专用钥匙，第 2 条来自另一把标了 shared=true 的共享钥匙 → 整起事件不得放行
			f.db.Fact.Create().
				SetKind("key").
				SetSubject(opsKeyFP2).
				SetGroupID(f.group.ID).
				SetHolder(opsHolder).
				SetShared(true).
				SetContent("共享管理钥匙").
				SetCreatedBy("admin").
				ExecX(f.ctx)
			f.db.Intent.Create().
				SetCreatedAt(f.intent.CreatedAt).
				SetCreatedBy(opsHolder).
				SetKeyFingerprint(opsKeyFP2).
				SetSourceAddr(opsSrcIP).
				SetAssetIds([]uuid.UUID{f.asset.ID}).
				SetCategory("deploy").
				SetStartsAt(f.intent.StartsAt).
				SetExpiresAt(f.intent.ExpiresAt).
				SetLate(false).
				ExecX(f.ctx)
			raw, _ := json.Marshal(map[string]any{
				"activity_id": 1,
				"process":     map[string]any{"cmd_line": "/bin/sh /tmp/kei-deploy.sh --reload", "pid": 1021},
				"login_session": map[string]any{
					"uid":         "ssh-99",
					"user":        "root",
					"src_ip":      opsSrcIP,
					"auth_method": "publickey",
					"key_fp":      opsKeyFP2,
				},
			})
			f.db.Event.UpdateOneID(f.childEv.ID).ClearParentProcessGUID().SetRaw(raw).ExecX(f.ctx)
		},
		"malicious_verdict": func(f *opsFixture) {
			f.db.Incident.UpdateOneID(f.inc.ID).
				SetAiVerdict(json.RawMessage(`{"verdict":"malicious","response_tier":"observe","action_codes":["monitor"]}`)).
				ExecX(f.ctx)
		},
		"manual_lock": func(f *opsFixture) {
			f.db.Incident.UpdateOneID(f.inc.ID).SetWork(&schema.IncidentWork{ManualLock: true}).ExecX(f.ctx)
		},
		"not_settled_yet": func(f *opsFixture) {
			recent := time.Now().UTC().Add(-20 * time.Minute)
			f.db.Alert.UpdateOneID(f.alChild.ID).SetLastTs(recent).ExecX(f.ctx)
			f.db.Incident.UpdateOneID(f.inc.ID).SetTriagedAt(recent.Add(time.Minute)).ExecX(f.ctx)
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := setupOpsSession(t)
			mutate(f)
			ok, err := f.r.Review(f.ctx, f.inc.ID)
			if err != nil {
				t.Fatalf("Review 返回意外错误: %v", err)
			}
			if ok || f.calls != 0 {
				t.Fatalf("不满足前置条件时不得调用审计模型或结案: ok=%v calls=%d", ok, f.calls)
			}
			if got := f.db.Incident.GetX(f.ctx, f.inc.ID).Status; got != "triaged" {
				t.Fatalf("事件应保持 triaged, got=%s", got)
			}
		})
	}
}

func TestOpsSessionAuditorCitationGateAndRejection(t *testing.T) {
	for _, mode := range []string{"missing_fact_ref", "missing_intent_ref", "auditor_reject_with_missing_domain"} {
		t.Run(mode, func(t *testing.T) {
			f := setupOpsSession(t)
			if mode == "auditor_reject_with_missing_domain" {
				raw, _ := json.Marshal(map[string]any{
					"activity_id": 1,
					"process":     map[string]any{"cmd_line": "curl -fsSL https://pkg.internal-mirror.example/agent.tar.gz -o /tmp/a.tgz", "pid": 1021},
				})
				f.db.Event.UpdateOneID(f.childEv.ID).SetRaw(raw).ExecX(f.ctx)
			}
			orig := f.r.Judge
			f.r.Judge = func(ctx context.Context, model, mat string) (Decision, error) {
				d, err := orig(ctx, model, mat)
				if err != nil {
					return d, err
				}
				switch mode {
				case "missing_fact_ref":
					d.Reason = "仅引用了部署意图 " + facts.Ref("I", f.intent.ID) + "，未写钥匙事实编号"
				case "missing_intent_ref":
					d.Reason = "仅引用了专用钥匙 " + facts.Ref("F", f.keyFact.ID) + "，未写运维意图编号"
				case "auditor_reject_with_missing_domain":
					return Decision{
						Approve: false,
						Reason:  "部署会话拉取了未登记的外部软件源域名 pkg.internal-mirror.example",
						MissingFacts: []MissingFact{
							{Kind: "authorization", SubjectKind: "domain", Subject: "pkg.internal-mirror.example"},
						},
					}, nil
				}
				return d, nil
			}

			ok, err := f.r.Review(f.ctx, f.inc.ID)
			if err != nil || ok {
				t.Fatalf("期望拒绝结案: ok=%v err=%v", ok, err)
			}
			inc := f.db.Incident.GetX(f.ctx, f.inc.ID)
			if inc.Status != "triaged" {
				t.Fatalf("事件应保持 triaged, got=%s", inc.Status)
			}
			if kf := f.db.Fact.GetX(f.ctx, f.keyFact.ID); kf.CitedCount != 0 {
				t.Fatalf("未批准结案不应增加事实引用计数: %d", kf.CitedCount)
			}
			if mode == "auditor_reject_with_missing_domain" {
				if !f.db.Question.Query().Where(
					question.KindEQ("authorization"),
					question.SubjectKindEQ("domain"),
					question.SubjectEQ("pkg.internal-mirror.example"),
				).ExistX(f.ctx) {
					t.Fatal("运维会话审计因超出登记范围拒绝时，缺失事实应写入总控待答问题")
				}
			}
		})
	}
}
