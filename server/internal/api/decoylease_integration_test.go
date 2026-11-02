//go:build integration

package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"openxdr/server/deception/sdk"
	"openxdr/server/ent/decoydeployment"
	"openxdr/server/internal/testdb"
)

func TestDecoyLeaseLifecycle(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("lease").SaveX(ctx)
	host := db.Asset.Create().SetHostname("host").SetGroupID(group.ID).SaveX(ctx)
	token := strings.Repeat("a", 64)
	row := db.DecoyDeployment.Create().SetAssetID(host.ID).SetKind(decoydeployment.KindHTTP).SetProfile("decoy").SetTemplate("http-decoy-v1").SetPort(8088).SetCreatedBy("test").SetTokenHash(decoyTokenHash(token)).SetTokenGroupID(group.ID).SetTokenExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
	ts := httptest.NewServer(DecoyRuntime(db))
	defer ts.Close()
	newClient := func() *sdk.Client {
		t.Helper()
		c, e := sdk.NewClient(ts.URL, row.ID.String(), token)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	check := func(err error, ok bool) {
		t.Helper()
		if (err == nil) != ok {
			t.Fatalf("success=%v: %v", ok, err)
		}
	}
	a, b := newClient(), newClient()
	check(a.Acquire(ctx), true)
	check(b.Acquire(ctx), false)
	check(a.Record(ctx, "http_page"), false)
	check(a.Ready(ctx), true)
	check(a.Record(ctx, "http_page"), true)
	check(b.Record(ctx, "http_page"), false)
	check(a.Heartbeat(ctx), true)
	current := db.DecoyDeployment.GetX(ctx, row.ID)
	if decoyRuntimeStatus(current, time.Now()) != "running" {
		t.Fatal("missing running state")
	}
	if current.TokenExpiresAt.Before(time.Now().Add(decoyTokenTTL - time.Minute)) {
		t.Fatal("续租未顺延令牌", current.TokenExpiresAt)
	}
	check(a.Finish(ctx, false), true)
	check(a.Finish(ctx, false), true)
	check(a.Record(ctx, "http_page"), false)
	check(b.Acquire(ctx), true)
	check(b.Ready(ctx), true)
	db.DecoyDeployment.UpdateOneID(row.ID).SetRuntimeSeenAt(time.Now().Add(-2 * time.Minute)).ExecX(ctx)
	check(b.Heartbeat(ctx), false)
	check(b.Record(ctx, "http_page"), false)
	current = db.DecoyDeployment.GetX(ctx, row.ID)
	if decoyRuntimeStatus(current, time.Now()) != "stale" {
		t.Fatal("expired state")
	}
	c := newClient()
	check(c.Acquire(ctx), true)
	check(c.Ready(ctx), true)
	db.DecoyDeployment.UpdateOneID(row.ID).SetTokenHash(decoyTokenHash(strings.Repeat("b", 64))).ExecX(ctx)
	current = db.DecoyDeployment.GetX(ctx, row.ID)
	if decoyRuntimeStatus(current, time.Now()) != "stopping" {
		t.Fatal("rotation must not confirm stopped")
	}
	check(c.Finish(context.Background(), false), false)
	token = strings.Repeat("b", 64)
	db.DecoyDeployment.UpdateOneID(row.ID).SetRuntimeSeenAt(time.Now().Add(-2 * time.Minute)).ExecX(ctx)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		contender := newClient()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if contender.Acquire(ctx) == nil {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("concurrent lease winners: %d", winners.Load())
	}

}
