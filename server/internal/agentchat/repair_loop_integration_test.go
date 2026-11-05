//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/testdb"
)

func TestPolicyBlockerUsesServerScopeWithoutUnsafeCommand(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("capacity").SetTitle("capacity").SetWorkAttempts(10).SaveX(ctx)
	svc := &Service{DB: db}
	if err := svc.saveFindingPlan(ctx, session, f, "request bounded maintenance policy", "policy_required", nil); err == nil {
		t.Fatal("missing trusted scope query accepted")
	}
	svc.FindingRepairAvailable = func(context.Context, *ent.AgentSession, *ent.Finding) (bool, error) { return false, nil }
	if err := svc.saveFindingPlan(ctx, session, f, "request bounded maintenance policy", "policy_required", nil); err != nil {
		t.Fatal(err)
	}
	got := db.Finding.GetX(ctx, f.ID)
	var w findings.Work
	_ = json.Unmarshal(got.Work, &w)
	if got.WorkOwner != "ai" || w.RepairAttempts != 0 || w.Blocker != "policy_required" || db.Command.Query().CountX(ctx) != 0 {
		t.Fatalf("invented permissions or command: %+v", w)
	}
	if err := svc.saveFindingPlan(ctx, session, got, "", "", nil); err != nil {
		t.Fatal(err)
	}
	got = db.Finding.GetX(ctx, f.ID)
	_ = json.Unmarshal(got.Work, &w)
	if w.Plan != "request bounded maintenance policy" || w.Blocker != "policy_required" {
		t.Fatalf("lost precise plan: %+v", w)
	}
	svc.FindingRepairAvailable = func(context.Context, *ent.AgentSession, *ent.Finding) (bool, error) { return true, nil }
	if err := svc.saveFindingPlan(ctx, session, got, "", "policy_required", nil); err == nil {
		t.Fatal("ignored existing grant")
	}
}

func TestStalePlanCannotEraseReservationOrHumanDecision(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	old := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("service").SetTitle("service").SetWork(findings.EncodeWork(findings.Work{Plan: "before"})).SaveX(ctx)
	db.Finding.UpdateOneID(old.ID).SetWork(findings.EncodeWork(findings.Work{Plan: "reserved", RepairAttempts: 1})).ExecX(ctx)
	if err := (&Service{DB: db}).saveFindingPlan(ctx, session, old, "stale", "", nil); err == nil {
		t.Fatal("stale plan erased repair reservation")
	}
	db.Finding.UpdateOneID(old.ID).SetStatus("ignored").ExecX(ctx)
	if err := (&Service{DB: db}).saveFindingPlan(ctx, session, old, "stale", "", nil); err == nil {
		t.Fatal("overwrote human terminal")
	}
}

func TestBusinessBlockerNeedsFreshActualDiagnostic(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("legacy").SetTitle("legacy service").SaveX(ctx)
	now := time.Now()
	code := int32(0)
	c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("systemctl show --property=Id,ActiveState,UnitFileState -- legacy.service").SetStatus("succeeded").SetExitCode(code).SetStdout("Id=legacy.service\nActiveState=failed\nUnitFileState=disabled").SetCompletedAt(now).SaveX(ctx)
	// 保存指令的created_at不能晚于完成时间，明确设为本轮开始之后。
	db.Command.UpdateOneID(c.ID).SetCreatedAt(session.CreatedAt).ExecX(ctx)
	svc := &Service{DB: db}
	if err := svc.saveFindingPlan(ctx, session, f, "confirm replacement before decommission", "legacy_decommission_confirm", []uuid.UUID{c.ID}); err != nil {
		t.Fatal(err)
	}
	got := db.Finding.GetX(ctx, f.ID)
	if got.WorkOwner != "ai" {
		t.Fatal("candidate business blocker unnecessarily handed to human")
	}
	db.Command.UpdateOneID(c.ID).SetCmd("date").SetStdout("2026-11-06 UTC").ExecX(ctx)
	if err := svc.saveFindingPlan(ctx, session, got, "confirm", "manual_business_decision", []uuid.UUID{c.ID}); err == nil {
		t.Fatal("basic host data treated as business blocker proof")
	}
}
