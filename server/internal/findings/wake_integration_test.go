//go:build integration

package findings

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
	"testing"
	"time"
)

func TestConditionWakePreservesOwnershipAndRepairBudget(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	host := db.Asset.Create().SetHostname("a").SetGroupID(group.ID).SaveX(ctx)
	now := time.Now()
	past := now.Add(-time.Minute)
	dep := db.Finding.Create().SetGroupID(group.ID).SetAssetID(host.ID).SetKey("upstream").SetTitle("upstream").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(group.ID).SetAssetID(host.ID).SetKey("client").SetTitle("client").SetWorkNextCheckAt(now.Add(72 * time.Hour)).SaveX(ctx)
	fp, _, err := DependencyState(ctx, db, group.ID, f.ID, []uuid.UUID{dep.ID})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, reason string
		work         Work
	}{
		{"policy", "authorization_changed", Work{Version: 3, Blocker: "policy_required", PolicyFingerprint: "old", RepairAttempts: 2}},
		{"cooldown", "cooldown_or_window_elapsed", Work{Version: 3, Blocker: "cooldown", PolicyFingerprint: "new", RetryAt: &past, RepairAttempts: 2}},
		{"window", "scheduled_review", Work{Version: 3, Blocker: "maintenance_window_required", PolicyFingerprint: "new", WakeAt: &past, RepairAttempts: 2}},
		{"dependency", "dependency_recovered", Work{Version: 3, Blocker: "external_dependency", PolicyFingerprint: "new", DependsOn: []uuid.UUID{dep.ID}, DependencyFingerprint: fp, RepairAttempts: 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db.Finding.UpdateOneID(f.ID).SetWorkOwner("human").SetWorkNextCheckAt(now.Add(72 * time.Hour)).SetWork(EncodeWork(tc.work)).ExecX(ctx)
			tc.work.Stage = "blocked"
			db.Finding.UpdateOneID(f.ID).SetWork(EncodeWork(tc.work)).ExecX(ctx)
			if tc.name == "dependency" {
				dep.Update().SetStatus("resolved").ExecX(ctx)
			}
			inspect := func(context.Context, *ent.Finding) (RepairCapabilities, error) {
				return RepairCapabilities{PolicyFingerprint: "new"}, nil
			}
			if err := RefreshWake(ctx, db, group.ID, now, inspect); err != nil {
				t.Fatal(err)
			}
			got := db.Finding.GetX(ctx, f.ID)
			var w Work
			json.Unmarshal(got.Work, &w)
			if got.Status != "open" || got.WorkOwner != "human" || w.RepairAttempts != 2 || w.Blocker != tc.work.Blocker || got.WorkNextCheckAt.After(now.Add(time.Second)) || w.LastWakeReason != tc.reason {
				t.Fatalf("unsafe wake: %+v %+v", got, w)
			}
			// 同一条件不反复唤醒：下一轮复查时间应保持，不消耗预算。
			future := now.Add(6 * time.Hour)
			db.Finding.UpdateOneID(f.ID).SetWorkNextCheckAt(future).ExecX(ctx)
			if err := RefreshWake(ctx, db, group.ID, now.Add(time.Second), inspect); err != nil {
				t.Fatal(err)
			}
			if got := db.Finding.GetX(ctx, f.ID); got.WorkNextCheckAt.Before(future.Add(-time.Second)) {
				t.Fatal("same condition woke repeatedly")
			}
		})
	}
}

func TestDependencyGraphRejectsCrossGroupAndCycles(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	b := db.Asset.Create().SetHostname("b").SetGroupID(other.ID).SaveX(ctx)
	first := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("a").SetTitle("a").SaveX(ctx)
	second := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("b").SetTitle("b").SetWork(EncodeWork(Work{DependsOn: []uuid.UUID{first.ID}})).SaveX(ctx)
	foreign := db.Finding.Create().SetGroupID(other.ID).SetAssetID(b.ID).SetKey("c").SetTitle("c").SaveX(ctx)
	for _, ids := range [][]uuid.UUID{{first.ID}, {second.ID}, {foreign.ID}, {second.ID, second.ID}} {
		if err := ValidateDependencies(ctx, db, g.ID, first.ID, ids); err == nil {
			t.Fatal("unsafe dependency accepted", ids)
		}
	}
}

func TestClaimPreservesConditionVersionAndActiveLease(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetGroupID(g.ID).SetKind("task").SetInitiator("system").SetModel("m").SaveX(ctx)
	now := time.Now()
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("disk").SetTitle("disk").SetWork(EncodeWork(Work{Version: 3, Blocker: "cooldown", Stage: "blocked", PolicyFingerprint: "old"})).SaveX(ctx)
	claimed, err := Claim(ctx, db, session, now)
	if err != nil || len(claimed) != 1 {
		t.Fatal(claimed, err)
	}
	var w Work
	json.Unmarshal(claimed[0].Work, &w)
	if w.Version != 3 {
		t.Fatal("领取降级版本会反复触发能力升级唤醒", w)
	}
	inspect := func(context.Context, *ent.Finding) (RepairCapabilities, error) {
		return RepairCapabilities{PolicyFingerprint: "new"}, nil
	}
	if err := RefreshWake(ctx, db, g.ID, now, inspect); err != nil {
		t.Fatal(err)
	}
	got := db.Finding.GetX(ctx, f.ID)
	w = Work{}
	json.Unmarshal(got.Work, &w)
	if w.PolicyFingerprint != "old" || got.WorkSessionID == nil || *got.WorkSessionID != session.ID {
		t.Fatal("唤醒覆盖了活跃任务租约")
	}
}
