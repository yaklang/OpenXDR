//go:build integration

package closurereview

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/decoy"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/sigma"
)

const benignCmd = "/usr/bin/apt-get update -q"

// setupBenign 普通事件：没有平台指令来源、没有 Pi 提案，研判为良性且已安静三小时
func setupBenign(t *testing.T) *fixture {
	f := setup(t)
	old := time.Now().UTC().Truncate(time.Microsecond).Add(-3 * time.Hour)
	raw, _ := json.Marshal(map[string]any{"activity_id": 1, "process": map[string]any{"cmd_line": benignCmd, "pid": 42}})
	f.db.Event.UpdateOneID(f.ev.ID).SetTs(old).SetRaw(raw).ExecX(f.ctx)
	f.db.Alert.UpdateOneID(f.al.ID).SetTs(old).ClearCommandID().ExecX(f.ctx)
	f.db.Incident.UpdateOneID(f.inc.ID).SetCreatedAt(old).SetTriagedAt(old.Add(time.Minute)).ClearClosureProposal().
		SetAiVerdict(json.RawMessage(`{"verdict":"benign","response_tier":"observe","action_codes":["review_closure","monitor"]}`)).ExecX(f.ctx)
	f.inc = f.db.Incident.GetX(f.ctx, f.inc.ID)
	f.r.Judge = func(context.Context, string, string) (Decision, error) {
		f.calls++
		d := benignApproval(f.ev.ID, benignCmd)
		// 事件对象路径（含入库字段）与原文路径都按服务端数据逐字核对
		d.Claims = append(d.Claims, Claim{EventID: f.ev.ID, Field: "raw.process.cmd_line", Value: benignCmd}, Claim{EventID: f.ev.ID, Field: "source", Value: "agent"})
		return d, nil
	}
	return f
}

func benignApproval(id uuid.UUID, value string) Decision {
	return Decision{Approve: true, Reason: "命令行是系统包管理器刷新软件源，与告警规则针对的手法不符", PositiveEvidence: "process.cmd_line 为 /usr/bin/apt-get update -q，属于包管理器的正常软件源更新",
		EventIDs: []uuid.UUID{id}, Claims: []Claim{{EventID: id, Field: "process.cmd_line", Value: value}}}
}

func TestBenignCloseWithoutProposal(t *testing.T) {
	f := setupBenign(t)
	// 首次出现的新进程是唯一放行的合成检测
	f.db.Alert.UpdateOneID(f.al.ID).SetRuleID(sigma.RuleNewProcess).SetSeverity(2).ExecX(f.ctx)
	var prompt string
	judge := f.r.Judge
	f.r.Judge = func(ctx context.Context, model, material string) (Decision, error) {
		prompt = closurePrompt(material)
		return judge(ctx, model, material)
	}
	ok, err := f.r.Review(f.ctx, f.inc.ID)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if prompt != benignPrompt {
		t.Fatal("良性分支应使用良性审计提示词")
	}
	inc := f.db.Incident.GetX(f.ctx, f.inc.ID)
	if inc.Status != "false_positive" || inc.ResolutionSource == nil || *inc.ResolutionSource != "ai_review" || inc.ResolvedBy == nil || *inc.ResolvedBy != "system" {
		t.Fatalf("%+v", inc)
	}
	if !f.db.AuditLog.Query().Where(auditlog.ActionEQ("incident_closure_ai_reviewed"), auditlog.TargetEQ(f.inc.ID.String())).ExistX(f.ctx) {
		t.Fatal("缺审计")
	}
	if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil || f.calls != 1 {
		t.Fatal("已结案不应再次审计", ok, err, f.calls)
	}
}

// 被拒后资产心跳更新不算新材料：同一快照不重复送审
func TestBenignRejectedSnapshotStableAcrossAssetHeartbeat(t *testing.T) {
	f := setupBenign(t)
	f.r.Judge = func(context.Context, string, string) (Decision, error) {
		f.calls++
		return Decision{Reason: "命令行不足以证明这是授权运维行为"}, nil
	}
	if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil || f.calls != 1 {
		t.Fatal(ok, err, f.calls)
	}
	f.db.Asset.UpdateOneID(f.asset.ID).SetLastSeen(time.Now()).ExecX(f.ctx)
	if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil || f.calls != 1 {
		t.Fatal("资产心跳不应触发重复审计", ok, err, f.calls)
	}
}

// 任一门禁不满足都不调用模型
func TestBenignDisqualifiers(t *testing.T) {
	verdict := func(v string) func(*fixture) {
		return func(f *fixture) { f.db.Incident.UpdateOneID(f.inc.ID).SetAiVerdict(json.RawMessage(v)).ExecX(f.ctx) }
	}
	tests := map[string]func(*fixture){
		"high": func(f *fixture) { f.db.Alert.UpdateOneID(f.al.ID).SetSeverity(4).ExecX(f.ctx) },
		"critical_with_fact": func(f *fixture) {
			f.db.Fact.Create().SetKind("asset_role").SetAssetID(f.asset.ID).SetContent("构建机").SetCreatedBy("admin").ExecX(f.ctx)
			f.db.Alert.UpdateOneID(f.al.ID).SetSeverity(5).ExecX(f.ctx)
		},
		"high_expired_fact": func(f *fixture) {
			f.db.Fact.Create().SetKind("change").SetAssetID(f.asset.ID).SetContent("授权测试").SetCreatedBy("admin").SetExpiresAt(time.Now().Add(-time.Hour)).ExecX(f.ctx)
			f.db.Alert.UpdateOneID(f.al.ID).SetSeverity(4).ExecX(f.ctx)
		},
		"intel":     func(f *fixture) { f.db.Alert.UpdateOneID(f.al.ID).SetRuleID("intel:ip:1.2.3.4").ExecX(f.ctx) },
		"synthetic": func(f *fixture) { f.db.Alert.UpdateOneID(f.al.ID).SetRuleID("xdr:beacon").ExecX(f.ctx) },
		"decoy": func(f *fixture) {
			f.db.Alert.UpdateOneID(f.al.ID).SetRuleID(decoy.ObservationRulePrefix + "x").ExecX(f.ctx)
		},
		"suspicious":    verdict(`{"verdict":"suspicious","action_codes":["monitor"]}`),
		"verify_source": verdict(`{"verdict":"benign","action_codes":["verify_source","monitor"]}`),
		"no_codes":      verdict(`{"verdict":"benign"}`),
		"tier":          verdict(`{"verdict":"benign","response_tier":"contain","action_codes":["monitor"]}`),
		"core":          func(f *fixture) { f.db.Asset.UpdateOneID(f.asset.ID).SetResponseTier("core").ExecX(f.ctx) },
		"active": func(f *fixture) {
			f.db.Alert.UpdateOneID(f.al.ID).SetLastTs(time.Now().Add(-10 * time.Minute)).ExecX(f.ctx)
		},
		"after_triage": func(f *fixture) {
			f.db.Alert.UpdateOneID(f.al.ID).SetLastTs(f.inc.TriagedAt.Add(time.Minute)).ExecX(f.ctx)
		},
		"new_evidence": func(f *fixture) { f.db.Incident.UpdateOneID(f.inc.ID).SetEvidenceAt(time.Now()).ExecX(f.ctx) },
		"manual_owner": func(f *fixture) {
			f.db.Incident.UpdateOneID(f.inc.ID).SetWork(&schema.IncidentWork{ManualOwner: "analyst", Owner: "human"}).ExecX(f.ctx)
		},
		"manual_lock": func(f *fixture) {
			f.db.Incident.UpdateOneID(f.inc.ID).SetWork(&schema.IncidentWork{ManualLock: true}).ExecX(f.ctx)
		},
		"empty_event": func(f *fixture) { f.db.Event.UpdateOneID(f.ev.ID).SetRaw(json.RawMessage(`{}`)).ExecX(f.ctx) },
		"no_event":    func(f *fixture) { f.db.Alert.UpdateOneID(f.al.ID).ClearEventID().ExecX(f.ctx) },
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			f := setupBenign(t)
			edit(f)
			ok, err := f.r.Review(f.ctx, f.inc.ID)
			if ok || err != nil || f.calls != 0 {
				t.Fatal(ok, err, f.calls)
			}
			if f.db.Incident.GetX(f.ctx, f.inc.ID).Status != "triaged" {
				t.Fatal("不应结案")
			}
		})
	}
}

// 审计拒绝、出错、引用不存在的字段值或漏引事件，都保留事件
func TestBenignAuditorFailClosed(t *testing.T) {
	for _, mode := range []string{"reject", "error", "wrong_value", "missing_event", "unknown_field"} {
		t.Run(mode, func(t *testing.T) {
			f := setupBenign(t)
			f.r.Judge = func(context.Context, string, string) (Decision, error) {
				switch mode {
				case "error":
					return Decision{}, errors.New("模型不可用")
				case "wrong_value":
					return benignApproval(f.ev.ID, "/usr/bin/apt-get update"), nil
				case "unknown_field":
					d := benignApproval(f.ev.ID, benignCmd)
					d.Claims = []Claim{{EventID: f.ev.ID, Field: "raw.process.missing", Value: benignCmd}}
					return d, nil
				case "missing_event":
					d := benignApproval(f.ev.ID, benignCmd)
					d.EventIDs, d.Claims = []uuid.UUID{uuid.New()}, []Claim{{EventID: uuid.New(), Field: "process.cmd_line", Value: benignCmd}}
					return d, nil
				}
				return Decision{Reason: "命令行不足以证明这是授权运维行为"}, nil
			}
			if ok, _ := f.r.Review(f.ctx, f.inc.ID); ok {
				t.Fatal("不应批准")
			}
			if f.db.Incident.GetX(f.ctx, f.inc.ID).Status != "triaged" {
				t.Fatal("不应结案")
			}
		})
	}
}

// 审计员拿到服务端逐级取的祖先完整记录：多级、只认同资产、缺失如实标出
func TestBenignMaterialCarriesLineage(t *testing.T) {
	f := setupBenign(t)
	f.db.Alert.UpdateOneID(f.al.ID).SetRuleID(sigma.RuleNewProcess).SetSeverity(2).ExecX(f.ctx)
	parent, grand := uuid.New(), uuid.New()
	f.db.Event.UpdateOneID(f.ev.ID).SetParentProcessGUID(parent).ExecX(f.ctx)
	daily := "/bin/sh /usr/lib/apt/apt.systemd.daily update"
	raw, _ := json.Marshal(map[string]any{"activity_id": 1, "process": map[string]any{"cmd_line": daily, "pid": 41, "parent_process": map[string]any{"cmd_line": "/lib/systemd/systemd"}}})
	ts := f.db.Event.GetX(f.ctx, f.ev.ID).Ts.Add(-time.Second)
	f.db.Event.Create().SetTs(ts).SetAssetID(f.asset.ID).SetSource("agent").SetClassUID(1007).SetProcessGUID(parent).SetParentProcessGUID(grand).SetRaw(raw).ExecX(f.ctx)
	other := f.db.Asset.Create().SetHostname("other").SetGroupID(f.group.ID).SaveX(f.ctx)
	f.db.Event.Create().SetTs(ts).SetAssetID(other.ID).SetSource("agent").SetClassUID(1007).SetProcessGUID(grand).SetRaw(raw).ExecX(f.ctx)
	var got material
	judge := f.r.Judge
	f.r.Judge = func(ctx context.Context, model, m string) (Decision, error) {
		if err := json.Unmarshal([]byte(m), &got); err != nil {
			t.Fatal(err)
		}
		return judge(ctx, model, m)
	}
	if ok, err := f.r.Review(f.ctx, f.inc.ID); err != nil || !ok {
		t.Fatal(ok, err)
	}
	l := got.Lineage
	if l == nil || !l.Complete || len(l.Ancestors) != 2 {
		t.Fatalf("%+v", l)
	}
	var rec struct {
		Process map[string]any `json:"process"`
	}
	if json.Unmarshal(l.Ancestors[0].Record, &rec) != nil || rec.Process["cmd_line"] != daily || rec.Process["parent_process"] != nil || l.Ancestors[0].ProcessGUID != parent {
		t.Fatalf("父进程应给完整记录且不重复上一级：%s", l.Ancestors[0].Record)
	}
	if l.Ancestors[1].ProcessGUID != grand || !l.Ancestors[1].Missing {
		t.Fatalf("别的资产上的同 guid 记录不能顶替：%+v", l.Ancestors[1])
	}
}

// 高危告警凭主机事实交审计：材料列出覆盖它的事实编号，批准理由不引用就不算数
func TestBenignSevereNeedsHostFact(t *testing.T) {
	f := setupBenign(t)
	fact := f.db.Fact.Create().SetKind("asset_role").SetAssetID(f.asset.ID).SetContent("包管理更新是业务").SetCreatedBy("admin").SaveX(f.ctx)
	ref := facts.Ref("F", fact.ID)
	f.db.Alert.UpdateOneID(f.al.ID).SetSeverity(4).ExecX(f.ctx)
	var material string
	judge := f.r.Judge
	f.r.Judge = func(ctx context.Context, model, m string) (Decision, error) {
		material = m
		return judge(ctx, model, m)
	}
	if ok, err := f.r.Review(f.ctx, f.inc.ID); ok || err != nil || f.calls != 1 {
		t.Fatal("理由没引用事实编号不能结案", ok, err, f.calls)
	}
	if !strings.Contains(material, `"severe_hosts":[{"hostname":"`+f.asset.Hostname+`","facts":["`+ref+`"]}]`) {
		t.Fatal("材料应列出覆盖高危主机的事实编号", material)
	}
	f.r.Judge = func(context.Context, string, string) (Decision, error) {
		f.calls++
		d := benignApproval(f.ev.ID, benignCmd)
		d.Reason += "，属 " + ref + " 写明的业务"
		return d, nil
	}
	f.db.Fact.UpdateOneID(fact.ID).SetContent("包管理更新是本机业务").ExecX(f.ctx)
	if ok, err := f.r.Review(f.ctx, f.inc.ID); !ok || err != nil {
		t.Fatal("引用覆盖事实后应能结案", ok, err)
	}
}
