//go:build integration

package findings

import (
	"encoding/json"
	"openxdr/server/internal/testdb"
	"testing"
	"time"
)

func TestReleaseBlockedBackoffAndRisk(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	g := db.Group.Create().SetName("阻塞退避").SaveX(ctx)
	a := db.Asset.Create().SetHostname("host").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetGroupID(g.ID).SetModel("m").SetKind("task").SetInitiator("system").SetStatus("running").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("blocked").SetTitle("权限阻塞").SetSeverity("high").SetWork(EncodeWork(Work{Blocker: "permission"})).SaveX(ctx)
	for _, hours := range []int{6, 12, 24, 48, 72, 72} {
		db.Finding.UpdateOneID(f.ID).SetWorkSessionID(session.ID).ClearWorkNextCheckAt().ExecX(ctx)
		if err := Release(ctx, db, session.ID, now); err != nil {
			t.Fatal(err)
		}
		f = db.Finding.GetX(ctx, f.ID)
		if f.WorkNextCheckAt == nil || !f.WorkNextCheckAt.Equal(now.Add(time.Duration(hours)*time.Hour)) {
			t.Fatal(f.WorkNextCheckAt, hours)
		}
	}
	var w Work
	if err := json.Unmarshal(f.Work, &w); err != nil {
		t.Fatal(err)
	}
	w.EvidenceAt = &now
	db.Finding.UpdateOneID(f.ID).SetWork(EncodeWork(w)).SetWorkSessionID(session.ID).ClearWorkNextCheckAt().ExecX(ctx)
	if err := Release(ctx, db, session.ID, now); err != nil {
		t.Fatal(err)
	}
	f = db.Finding.GetX(ctx, f.ID)
	if !f.WorkNextCheckAt.Equal(now.Add(6 * time.Hour)) {
		t.Fatal("新证据未重置退避", f.WorkNextCheckAt)
	}
	w.RiskSince = &now
	db.Finding.UpdateOneID(f.ID).SetWork(EncodeWork(w)).SetWorkSessionID(session.ID).ClearWorkNextCheckAt().ExecX(ctx)
	if err := Release(ctx, db, session.ID, now); err != nil {
		t.Fatal(err)
	}
	f = db.Finding.GetX(ctx, f.ID)
	if !f.WorkNextCheckAt.Equal(now.Add(15 * time.Minute)) {
		t.Fatal("风险快速复查被退避覆盖", f.WorkNextCheckAt)
	}
}
