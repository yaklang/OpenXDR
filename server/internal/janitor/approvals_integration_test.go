//go:build integration

package janitor

import (
	"testing"
	"time"

	"openxdr/server/ent/approval"
	"openxdr/server/internal/testdb"
)

// 过期的待审批与已批准都要收口成 expired；未过期的和已结束的不能碰
func TestExpireApprovals(t *testing.T) {
	ctx, client := testdb.New(t)
	g := client.Group.Create().SetName("g").SaveX(ctx)
	host := client.Asset.Create().SetHostname("h").SetGroupID(g.ID).SaveX(ctx)
	now := time.Now()
	cases := []struct {
		status approval.Status
		exp    time.Time
		want   approval.Status
	}{
		{approval.StatusPending, now.Add(-time.Hour), approval.StatusExpired},
		{approval.StatusApproved, now.Add(-time.Minute), approval.StatusExpired},
		{approval.StatusPending, now.Add(time.Hour), approval.StatusPending},
		{approval.StatusRejected, now.Add(-time.Hour), approval.StatusRejected},
		{approval.StatusConsumed, now.Add(-time.Hour), approval.StatusConsumed},
	}
	for i := range cases {
		c := &cases[i]
		a := client.Approval.Create().SetGroupID(g.ID).SetAssetID(host.ID).SetRequestedBy("system").
			SetOrigin(approval.OriginHuman).SetCmd("true").SetTimeoutMs(30000).SetAsync(true).
			SetStatus(c.status).SetExpiresAt(c.exp).SaveX(ctx)
		defer func() {
			if got := client.Approval.GetX(ctx, a.ID).Status; got != c.want {
				t.Errorf("%s（到期 %s）收口后应为 %s，实际 %s", c.status, c.exp.Sub(now), c.want, got)
			}
		}()
	}
	n, err := (&Janitor{DB: client}).expireApprovals(ctx, now)
	if err != nil || n != 2 {
		t.Fatalf("应收口 2 条过期审批: n=%d err=%v", n, err)
	}
}
