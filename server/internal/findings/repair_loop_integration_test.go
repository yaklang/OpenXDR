//go:build integration

package findings

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
)

func TestInvestigationPreservesPlanAndDoesNotSpendRepairBudget(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("loop").SaveX(ctx)
	a := db.Asset.Create().SetHostname("host").SetGroupID(g.ID).SaveX(ctx)
	old := time.Now().Add(-2 * time.Hour)
	evidence := uuid.New()
	original := Work{Version: 2, OriginalTitle: "service", OriginalProblem: "service unavailable", Plan: "inspect upstream before restarting", Blocker: "external_dependency", EvidenceCommands: []uuid.UUID{evidence}, EvidenceAt: &old}
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("service").SetTitle("service").SetWork(EncodeWork(original)).SaveX(ctx)
	for i := 0; i < 4; i++ {
		now := time.Now().Add(time.Duration(i) * 48 * time.Hour)
		session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
		rows, err := Claim(ctx, db, session, now)
		if err != nil || len(rows) != 1 {
			t.Fatalf("claim %d: %v, %d", i, err, len(rows))
		}
		var w Work
		if err := json.Unmarshal(rows[0].Work, &w); err != nil {
			t.Fatal(err)
		}
		if w.RepairAttempts != 0 || w.InvestigationAttempts != i+1 || w.Plan != original.Plan || w.Blocker != original.Blocker || len(w.EvidenceCommands) != 1 || w.EvidenceCommands[0] != evidence || !w.EvidenceStale {
			t.Fatalf("lost state/spent repair budget: %+v", w)
		}
		if err := Release(ctx, db, session.ID, now, true); err != nil {
			t.Fatal(err)
		}
	}
	got := db.Finding.GetX(ctx, f.ID)
	var w Work
	_ = json.Unmarshal(got.Work, &w)
	if got.WorkAttempts != 4 || w.RepairAttempts != 0 || w.TransportFailures != 4 {
		t.Fatalf("mixed counters: %d %+v", got.WorkAttempts, w)
	}
}

func TestOldWorkSnapshotCannotEraseRepairReservation(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("host").SetGroupID(g.ID).SaveX(ctx)
	old := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("service").SetTitle("service").SetWork(EncodeWork(Work{Plan: "old"})).SaveX(ctx)
	db.Finding.UpdateOneID(old.ID).SetWork(EncodeWork(Work{Plan: "new", RepairAttempts: 1})).ExecX(ctx)
	n, err := db.Finding.Update().Where(Snapshot(old)).SetWork(old.Work).Save(ctx)
	if err != nil || n != 0 {
		t.Fatalf("stale plan overwrote reservation: %d %v", n, err)
	}
}
