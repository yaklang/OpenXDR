//go:build integration

package findings

import (
	"fmt"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

func TestClaimPrioritizesRiskWithoutMovedAssetsBlockingQueue(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now()
	g := db.Group.Create().SetName("old").SaveX(ctx)
	other := db.Group.Create().SetName("new").SaveX(ctx)
	owned := db.Asset.Create().SetHostname("owned").SetGroupID(g.ID).SaveX(ctx)
	moved := db.Asset.Create().SetHostname("moved").SetGroupID(other.ID).SaveX(ctx)
	for i := 0; i < 3; i++ {
		db.Finding.Create().SetGroupID(g.ID).SetAssetID(moved.ID).SetKey(fmt.Sprint("moved", i)).SetTitle("已转组的旧记录").SetSeverity("high").SetFirstSeen(now.Add(-48 * time.Hour)).ExecX(ctx)
	}
	for i := 0; i < 4; i++ {
		db.Finding.Create().SetGroupID(g.ID).SetAssetID(owned.ID).SetKey(fmt.Sprint("low", i)).SetTitle("旧日常问题").SetSeverity("low").SetFirstSeen(now.Add(-24 * time.Hour)).ExecX(ctx)
	}
	high := db.Finding.Create().SetGroupID(g.ID).SetAssetID(owned.ID).SetKey("high").SetTitle("高风险问题").SetSeverity("high").SaveX(ctx)
	session := db.AgentSession.Create().SetGroupID(g.ID).SetModel("m").SetKind("task").SetInitiator("system").SetStatus("running").SaveX(ctx)
	rows, err := Claim(ctx, db, session, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != BatchSize || rows[0].ID != high.ID {
		t.Fatal("高风险未优先或转组旧记录阻塞领取", len(rows))
	}
	for _, row := range rows {
		if row.AssetID != owned.ID {
			t.Fatal("领取了组外资产")
		}
	}
}
