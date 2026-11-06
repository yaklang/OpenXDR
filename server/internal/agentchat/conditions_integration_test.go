//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"openxdr/server/ent"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/testdb"
	"testing"
	"time"
)

func TestPreciseBlockerCannotBeInventedAndCanBeReevaluated(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SetOs("linux").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("disk-full").SetTitle("disk full").SetWork(findings.EncodeWork(findings.Work{Version: 3, Plan: "preserve this plan", Blocker: "policy_required"})).SaveX(ctx)
	retry := time.Now().Add(2 * time.Hour)
	status := "cooldown"
	svc := &Service{DB: db, FindingRepairCapabilities: func(context.Context, *ent.AgentSession, *ent.Finding, string, string) (findings.RepairCapabilities, error) {
		v := findings.RepairCapabilities{Status: status, Reason: "trusted reason", PolicyFingerprint: "v1"}
		if status != "ready" {
			v.RetryAt = &retry
		}
		return v, nil
	}}
	opts := findingPlanOptions{RepairCommand: "apt-get clean", RepairMount: "/"}
	if err := svc.saveFindingPlan(ctx, session, f, "", "policy_required", nil, opts); err == nil {
		t.Fatal("cooldown mislabeled as missing authorization")
	}
	if err := svc.recordRepairBlocker(ctx, session, f, opts.RepairCommand, &findings.RepairError{State: findings.RepairCapabilities{Status: "cooldown"}}); err != nil {
		t.Fatal(err)
	}
	f = db.Finding.GetX(ctx, f.ID)
	var w findings.Work
	json.Unmarshal(f.Work, &w)
	if w.Blocker != "cooldown" || w.BlockerDetail != "trusted reason" || w.Plan != "preserve this plan" || w.RetryAt == nil || f.WorkNextCheckAt.After(retry.Add(time.Second)) || w.RepairAttempts != 0 {
		t.Fatal(w)
	}
	status = "ready"
	if err := svc.saveFindingPlan(ctx, session, f, "", "none", nil, opts); err != nil {
		t.Fatal(err)
	}
	f = db.Finding.GetX(ctx, f.ID)
	json.Unmarshal(f.Work, &w)
	// 反序列化到新值，省略字段不能沿用上一份快照。
	w = findings.Work{}
	json.Unmarshal(f.Work, &w)
	if w.Blocker != "" || w.BlockerDetail != "" || w.RetryAt != nil || w.RepairAttempts != 0 || f.Status != "open" {
		t.Fatal(w)
	}
	f = f.Update().SetWork(findings.EncodeWork(findings.Work{Blocker: "manual_business_decision"})).SaveX(ctx)
	if err := svc.saveFindingPlan(ctx, session, f, "", "none", nil, opts); err == nil {
		t.Fatal("model cleared business decision")
	}
}

func TestMachineClassificationCannotEraseBusinessOrHumanResponsibility(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SaveX(ctx)
	for _, blocker := range []string{"manual_business_decision", "legacy_decommission_confirm", "external_dependency"} {
		f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey(blocker).SetTitle(blocker).SetWorkOwner("human").SetWork(findings.EncodeWork(findings.Work{Version: 3, Blocker: blocker})).SaveX(ctx)
		svc := &Service{DB: db, FindingRepairCapabilities: func(context.Context, *ent.AgentSession, *ent.Finding, string, string) (findings.RepairCapabilities, error) {
			return findings.RepairCapabilities{Status: "action_unsupported"}, nil
		}}
		if err := svc.saveFindingPlan(ctx, session, f, "", "action_unsupported", nil, findingPlanOptions{RepairCommand: "docker compose restart"}); err == nil {
			t.Fatal("机器分类覆盖受保护阻塞", blocker)
		}
		if err := svc.recordRepairBlocker(ctx, session, f, "docker compose restart", &findings.RepairError{State: findings.RepairCapabilities{Status: "action_unsupported"}}); err != nil {
			t.Fatal(err)
		}
		got := db.Finding.GetX(ctx, f.ID)
		var w findings.Work
		json.Unmarshal(got.Work, &w)
		if got.WorkOwner != "human" || w.Blocker != blocker {
			t.Fatal("拒绝分类改变了原责任或阻塞", got, w)
		}
	}
}

func TestPlanCASPreservesConcurrentHumanOwnership(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetGroupID(g.ID).SetKind("chat").SetInitiator("system").SetModel("m").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("service").SetTitle("service").SetWorkOwner("ai").SaveX(ctx)
	db.Finding.UpdateOneID(f.ID).SetWorkOwner("human").ExecX(ctx)
	if err := (&Service{DB: db}).saveFindingPlan(ctx, session, f, "stale plan", "", nil); err == nil {
		t.Fatal("旧计划覆盖了并发人工责任")
	}
	if db.Finding.GetX(ctx, f.ID).WorkOwner != "human" {
		t.Fatal("人工责任被提升为自动修复")
	}
}
