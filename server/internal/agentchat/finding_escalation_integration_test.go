//go:build integration

package agentchat

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/testdb"
)

func TestSustainedRiskEscalatesOnceAndRetainsAIWork(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	now := time.Now()
	prior := now.Add(-11 * time.Minute)
	session := db.AgentSession.Create().SetKind("chat").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SetCreatedAt(prior).SaveX(ctx)
	work := findings.Work{Version: 2, OriginalTitle: "根分区空间不足", OriginalProblem: "root filesystem capacity", Plan: "inspect precise artifacts", RiskTarget: &findings.RiskTarget{Kind: "disk_root", Mount: "/", AssetID: a.ID}, RiskKind: "disk_pressure", RiskSince: &prior, RiskObservedAt: &prior}
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("capacity").SetTitle("root capacity").SetWork(findings.EncodeWork(work)).SaveX(ctx)
	c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("df -P /").SetStatus("succeeded").SetExitCode(0).SetCreatedAt(now.Add(-time.Second)).SetCompletedAt(now).SetStdout("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100000 96000 4000 96% /\n").SaveX(ctx)
	svc := &Service{DB: db}
	if err := svc.saveFindingPlan(ctx, session, f, "plan", "", []uuid.UUID{c.ID}); err != nil {
		t.Fatal(err)
	}
	got := db.Finding.GetX(ctx, f.ID)
	var w findings.Work
	_ = json.Unmarshal(got.Work, &w)
	if w.EscalatedAt == nil || got.WorkOwner != "ai" || w.Plan != "plan" {
		t.Fatalf("risk lost ownership or did not escalate: %+v", w)
	}
	if db.AuditLog.Query().CountX(ctx) != 1 {
		t.Fatal("no durable escalation audit")
	}
	if err := svc.saveFindingPlan(ctx, session, got, "plan", "", []uuid.UUID{c.ID}); err != nil {
		t.Fatal(err)
	}
	if db.AuditLog.Query().CountX(ctx) != 1 {
		t.Fatal("duplicate escalation")
	}
}

func TestSingleRiskObservationDoesNotPretendPersistentEmergency(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	now := time.Now()
	session := db.AgentSession.Create().SetKind("chat").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SetCreatedAt(now.Add(-time.Minute)).SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("capacity").SetTitle("根分区空间不足").SetWork(findings.EncodeWork(findings.Work{OriginalTitle: "根分区空间不足"})).SaveX(ctx)
	c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("df -P /").SetStatus("succeeded").SetExitCode(0).SetCreatedAt(now.Add(-time.Second)).SetCompletedAt(now).SetStdout("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100000 96000 4000 96% /\n").SaveX(ctx)
	if err := (&Service{DB: db}).saveFindingPlan(ctx, session, f, "confirm persistence", "", []uuid.UUID{c.ID}); err != nil {
		t.Fatal(err)
	}
	got := db.Finding.GetX(ctx, f.ID)
	var w findings.Work
	_ = json.Unmarshal(got.Work, &w)
	if w.RiskSince == nil || w.EscalatedAt != nil || got.WorkNextCheckAt == nil || got.WorkNextCheckAt.After(now.Add(16*time.Minute)) {
		t.Fatalf("single sample wrongly escalated or not scheduled: %+v", w)
	}
}
