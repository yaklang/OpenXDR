//go:build integration

package closurereview

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/containment"
	"openxdr/server/ent/schema"
)

func setupContained(t *testing.T) (*fixture, *ent.Containment) {
	f := setup(t)
	old := time.Now().UTC().Truncate(time.Microsecond).Add(-8 * time.Hour)
	f.db.Event.UpdateOneID(f.ev.ID).SetTs(old).ExecX(f.ctx)
	f.db.Alert.UpdateOneID(f.al.ID).SetTs(old).ClearCommandID().ExecX(f.ctx)
	f.db.Incident.UpdateOneID(f.inc.ID).SetCreatedAt(old).SetTriagedAt(old.Add(time.Minute)).SetAiVerdict(json.RawMessage(`{"verdict":"malicious","response_tier":"contain","kill_chain":["execution"]}`)).ClearClosureProposal().SetWork(&schema.IncidentWork{Version: 1, Owner: "human", Stage: "escalated"}).ExecX(f.ctx)
	cmd := f.db.Command.Create().SetAssetID(f.asset.ID).SetKind("kill_process").SetStatus("succeeded").SetCompletedAt(old.Add(2 * time.Minute)).SaveX(f.ctx)
	c := f.db.Containment.Create().SetAssetID(f.asset.ID).SetAlertID(f.al.ID).SetIncidentID(f.inc.ID).SetCreatedAt(old.Add(time.Minute)).SetKind("kill_process").SetKey("test").SetSignal("rule").SetRole(containment.RoleHost).SetReason("已终止威胁进程").SetState(containment.StateExecuted).SetCommandID(cmd.ID).SaveX(f.ctx)
	return f, c
}
func TestContainedCloseAndReopen(t *testing.T) {
	f, c := setupContained(t)
	ok, err := f.r.Review(f.ctx, f.inc.ID)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	inc := f.db.Incident.GetX(f.ctx, f.inc.ID)
	if inc.Status != "closed" || inc.ResolutionSource == nil || *inc.ResolutionSource != "ai_review" {
		t.Fatal(inc)
	}
	if f.db.Containment.GetX(f.ctx, c.ID).State != containment.StateExecuted {
		t.Fatal("结案修改了处置")
	}
	f.db.Event.Create().SetTs(time.Now()).SetSource("agent").SetClassUID(1007).SetAssetID(f.asset.ID).SetRaw(f.ev.Raw).ExecX(f.ctx)
	tx, err := f.db.Tx(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ReopenContained(f.ctx, tx); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if f.db.Incident.GetX(f.ctx, f.inc.ID).Status != "open" {
		t.Fatal("新增实体证据未重开")
	}
}
func TestContainedDisqualifiers(t *testing.T) {
	tests := map[string]func(*fixture, *ent.Containment){
		"failed": func(f *fixture, c *ent.Containment) {
			f.db.Containment.UpdateOneID(c.ID).SetState(containment.StateFailed).ExecX(f.ctx)
		},
		"pending": func(f *fixture, c *ent.Containment) {
			f.db.Containment.UpdateOneID(c.ID).SetState(containment.StatePending).ExecX(f.ctx)
		},
		"skipped": func(f *fixture, c *ent.Containment) {
			f.db.Containment.UpdateOneID(c.ID).SetState(containment.StateSkipped).ExecX(f.ctx)
		},
		"held": func(f *fixture, c *ent.Containment) {
			f.db.Containment.UpdateOneID(c.ID).SetState(containment.StateHeld).ExecX(f.ctx)
		},
		"receipt": func(f *fixture, c *ent.Containment) {
			f.db.Command.UpdateOneID(*c.CommandID).SetStatus("failed").ExecX(f.ctx)
		},
		"missing_receipt": func(f *fixture, c *ent.Containment) { f.db.Containment.UpdateOneID(c.ID).ClearCommandID().ExecX(f.ctx) },
		"uncovered": func(f *fixture, c *ent.Containment) {
			f.db.Alert.Create().SetAssetID(f.asset.ID).SetIncidentID(f.inc.ID).SetEventID(f.ev.ID).SetTs(f.ev.Ts).SetRuleID("other").SetSeverity(4).ExecX(f.ctx)
		},
		"core": func(f *fixture, c *ent.Containment) {
			f.db.Asset.UpdateOneID(f.asset.ID).SetResponseTier("core").ExecX(f.ctx)
		},
		"recent": func(f *fixture, c *ent.Containment) {
			f.db.Containment.UpdateOneID(c.ID).SetCreatedAt(time.Now()).ExecX(f.ctx)
		},
		"new_alert": func(f *fixture, c *ent.Containment) {
			f.db.Alert.UpdateOneID(f.al.ID).SetLastTs(time.Now()).ExecX(f.ctx)
		},
		"new_evidence": func(f *fixture, c *ent.Containment) {
			f.db.Event.Create().SetTs(time.Now()).SetAssetID(f.asset.ID).SetSource("agent").SetClassUID(1007).SetRaw(f.ev.Raw).ExecX(f.ctx)
		},
		"stale_triage": func(f *fixture, c *ent.Containment) {
			f.db.Incident.UpdateOneID(f.inc.ID).SetEvidenceAt(time.Now()).ExecX(f.ctx)
		},
		"manual_owner": func(f *fixture, c *ent.Containment) {
			f.db.Incident.UpdateOneID(f.inc.ID).SetWork(&schema.IncidentWork{ManualOwner: "analyst", Owner: "human", Stage: "escalated"}).ExecX(f.ctx)
		},
		"manual_lock": func(f *fixture, c *ent.Containment) {
			f.db.Incident.UpdateOneID(f.inc.ID).SetWork(&schema.IncidentWork{ManualLock: true}).ExecX(f.ctx)
		},
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			f, c := setupContained(t)
			edit(f, c)
			ok, err := f.r.Review(f.ctx, f.inc.ID)
			if ok || err != nil || f.calls != 0 {
				t.Fatal(ok, err, f.calls)
			}
		})
	}
}
func TestContainedAuditorFailClosed(t *testing.T) {
	for _, mode := range []string{"reject", "error", "invalid", "concurrent"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := setupContained(t)
			f.r.Judge = func(context.Context, string, string) (Decision, error) {
				switch mode {
				case "error":
					return Decision{}, errors.New("模型不可用")
				case "invalid":
					return Decision{Approve: true}, nil
				case "concurrent":
					f.db.Incident.UpdateOneID(f.inc.ID).SetEvidenceAt(time.Now()).ExecX(f.ctx)
					return approved(f.ev.ID), nil
				}
				return Decision{Reason: "处置无法完整覆盖全部攻击链，保留人工复核"}, nil
			}
			ok, _ := f.r.Review(f.ctx, f.inc.ID)
			if ok || f.db.Incident.GetX(f.ctx, f.inc.ID).Status != "triaged" {
				t.Fatal("失败时结案")
			}
		})
	}
}

func TestContainedSuccessfulStates(t *testing.T) {
	for _, state := range []containment.State{containment.StateActive, containment.StateExecuted, containment.StateExpired, containment.StateLifted} {
		t.Run(string(state), func(t *testing.T) {
			f, c := setupContained(t)
			f.db.Containment.UpdateOneID(c.ID).SetState(state).SetExpiresAt(time.Now().Add(time.Hour)).ExecX(f.ctx)
			ok, err := f.r.Review(f.ctx, f.inc.ID)
			if !ok || err != nil {
				t.Fatal(ok, err)
			}
			if f.db.Containment.GetX(f.ctx, c.ID).State != state {
				t.Fatal("结案不应改变租约")
			}
		})
	}
}
