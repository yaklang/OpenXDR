//go:build integration

package closurereview

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/decoy"
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
		return benignApproval(f.ev.ID, benignCmd), nil
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

// 任一门禁不满足都不调用模型
func TestBenignDisqualifiers(t *testing.T) {
	verdict := func(v string) func(*fixture) {
		return func(f *fixture) { f.db.Incident.UpdateOneID(f.inc.ID).SetAiVerdict(json.RawMessage(v)).ExecX(f.ctx) }
	}
	tests := map[string]func(*fixture){
		"high":      func(f *fixture) { f.db.Alert.UpdateOneID(f.al.ID).SetSeverity(4).ExecX(f.ctx) },
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
	for _, mode := range []string{"reject", "error", "wrong_value", "missing_event"} {
		t.Run(mode, func(t *testing.T) {
			f := setupBenign(t)
			f.r.Judge = func(context.Context, string, string) (Decision, error) {
				switch mode {
				case "error":
					return Decision{}, errors.New("模型不可用")
				case "wrong_value":
					return benignApproval(f.ev.ID, "/usr/bin/apt-get update"), nil
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
