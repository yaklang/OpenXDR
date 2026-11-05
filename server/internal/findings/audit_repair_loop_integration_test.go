//go:build integration

package findings

import (
	"encoding/json"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

func TestAuditReleasePreservesRiskAndEarlierFollowup(t *testing.T) {
	for _, mode := range []string{"risk", "earlier-plan"} {
		t.Run(mode, func(t *testing.T) {
			ctx, db := testdb.New(t)
			g := db.Group.Create().SetName("audit-release").SaveX(ctx)
			a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
			now := time.Now()
			session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
			work := Work{Version: 2, Plan: "keep precise follow-up", RepairAttempts: 1, InvestigationAttempts: 10, VerificationAttempts: 3, TransportFailures: 2}
			before := now.Add(5 * time.Minute)
			if mode == "risk" {
				observed := now.Add(-time.Minute)
				work.RiskSince = &observed
				work.RiskObservedAt = &observed
				work.RiskKind = "disk_pressure"
				before = now.Add(15 * time.Minute)
			}
			f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("capacity").SetTitle("capacity").SetSeverity("medium").SetWorkAttempts(10).SetWorkSessionID(session.ID).SetWorkLeaseUntil(now.Add(30 * time.Minute)).SetWorkNextCheckAt(before).SetWork(EncodeWork(work)).SaveX(ctx)
			if err := Release(ctx, db, session.ID, now, true); err != nil {
				t.Fatal(err)
			}
			got := db.Finding.GetX(ctx, f.ID)
			var next Work
			_ = json.Unmarshal(got.Work, &next)
			if got.WorkNextCheckAt == nil || got.WorkNextCheckAt.After(before) || !got.WorkNextCheckAt.After(now) || got.WorkSessionID != nil || got.WorkLeaseUntil != nil || next.RepairAttempts != 1 || next.VerificationAttempts != 3 || next.TransportFailures != 3 || next.Plan != work.Plan {
				t.Fatalf("release overwrote durable follow-up: %+v %+v", got, next)
			}
		})
	}
}
