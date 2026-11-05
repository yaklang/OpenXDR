//go:build integration

package findings

import (
	"bytes"
	"context"
	stdsql "database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/testdb"
)

func TestReleaseSecondUpdateFailureRollsBackWholeBatch(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("atomic-release").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	now := time.Now()
	session := db.AgentSession.Create().SetKind("task").SetGroupID(g.ID).SetInitiator("system").SetModel("m").SaveX(ctx)
	rows := make([]*ent.Finding, 0, 3)
	for i := 0; i < 3; i++ {
		f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey(fmt.Sprint(i)).SetTitle("pending").SetWorkAttempts(5).SetWorkSessionID(session.ID).SetWorkLeaseUntil(now.Add(30 * time.Minute)).SetWorkNextCheckAt(now.Add(15 * time.Minute)).SetWork(EncodeWork(Work{Version: 2, Plan: fmt.Sprint("specific plan ", i), RepairAttempts: 1, TransportFailures: 2})).SaveX(ctx)
		rows = append(rows, db.Finding.GetX(ctx, f.ID))
	}
	fault := errors.New("second release update failed")
	var updates atomic.Int32
	db.Finding.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if change, ok := m.(*ent.FindingMutation); ok && change.WorkSessionIDCleared() && updates.Add(1) == 2 {
				return nil, fault
			}
			return next.Mutate(ctx, m)
		})
	})
	if err := Release(ctx, db, session.ID, now, true); !errors.Is(err, fault) {
		t.Fatal("missing injected update error", err)
	}
	if updates.Load() != 2 {
		t.Fatal("second update not reached", updates.Load())
	}
	for _, before := range rows {
		after := db.Finding.GetX(ctx, before.ID)
		if after.WorkSessionID == nil || *after.WorkSessionID != session.ID || after.WorkLeaseUntil == nil || !after.WorkLeaseUntil.Equal(*before.WorkLeaseUntil) || after.WorkNextCheckAt == nil || !after.WorkNextCheckAt.Equal(*before.WorkNextCheckAt) || !bytes.Equal(after.Work, before.Work) {
			t.Fatalf("partial release committed before second update failed: %+v", after)
		}
	}
	if db.Command.Query().CountX(ctx) != 0 {
		t.Fatal("metadata release replayed commands")
	}
}

// ackLostDriver 模拟服务器已完成COMMIT而客户端未收到成功确认；不能把此错误称为已回滚。
type ackLostDriver struct{ dialect.Driver }
type ackLostTx struct{ dialect.Tx }

func (d ackLostDriver) Tx(ctx context.Context) (dialect.Tx, error) {
	tx, err := d.Driver.Tx(ctx)
	if err != nil {
		return nil, err
	}
	return ackLostTx{tx}, nil
}
func (tx ackLostTx) Commit() error {
	if err := tx.Tx.Commit(); err != nil {
		return err
	}
	return context.DeadlineExceeded
}

func TestReleaseCommitAcknowledgementLossRemainsUnknown(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("commit-unknown").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetGroupID(g.ID).SetInitiator("system").SetModel("m").SaveX(ctx)
	for i := 0; i < 3; i++ {
		db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey(fmt.Sprint(i)).SetTitle("pending").SetWorkSessionID(session.ID).SetWorkLeaseUntil(time.Now().Add(30 * time.Minute)).SetWork(EncodeWork(Work{Version: 2, Plan: "retain"})).ExecX(ctx)
	}
	raw, err := stdsql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	unknown := ent.NewClient(ent.Driver(ackLostDriver{entsql.OpenDB(dialect.Postgres, raw)}))
	defer unknown.Close()
	err = Release(ctx, unknown, session.ID, time.Now())
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "提交待办租约释放结果未知") {
		t.Fatal("commit uncertainty was hidden", err)
	}
	for _, f := range db.Finding.Query().AllX(ctx) {
		if f.WorkSessionID != nil || f.WorkLeaseUntil != nil {
			t.Fatalf("fixture should have atomically committed despite lost acknowledgement: %+v", f)
		}
	}
	if db.Command.Query().CountX(ctx) != 0 {
		t.Fatal("unknown metadata commit replayed commands")
	}
}

func TestClaimRecoversOnlyEndedOwnedOrphanLeases(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	owned := db.Asset.Create().SetHostname("owned").SetGroupID(g.ID).SaveX(ctx)
	outside := db.Asset.Create().SetHostname("outside").SetGroupID(other.ID).SaveX(ctx)
	now := time.Now()
	lease := now.Add(30 * time.Minute)
	next := now.Add(2 * time.Hour)
	makeSession := func(group uuid.UUID, status string) *ent.AgentSession {
		return db.AgentSession.Create().SetGroupID(group).SetKind("task").SetInitiator("system").SetModel("m").SetStatus(status).SaveX(ctx)
	}
	done := makeSession(g.ID, "succeeded")
	failed := makeSession(g.ID, "failed")
	active := makeSession(g.ID, "running")
	foreign := makeSession(other.ID, "failed")
	fresh := makeSession(g.ID, "running")
	before := map[uuid.UUID]*ent.Finding{}
	shouldClear := map[uuid.UUID]bool{}
	add := func(key string, group, asset, session uuid.UUID, status string, clear bool) {
		f := db.Finding.Create().SetGroupID(group).SetAssetID(asset).SetKey(key).SetTitle("evidence preserved").SetStatus(status).SetWorkAttempts(12).SetWorkSessionID(session).SetWorkLeaseUntil(lease).SetWorkNextCheckAt(next).SetWork(EncodeWork(Work{Version: 2, Plan: key, RepairAttempts: 2, VerificationAttempts: 3, EvidenceCommands: []uuid.UUID{uuid.New()}})).SaveX(ctx)
		before[f.ID] = db.Finding.GetX(ctx, f.ID)
		shouldClear[f.ID] = clear
	}
	add("done", g.ID, owned.ID, done.ID, "open", true)
	add("failed", g.ID, owned.ID, failed.ID, "open", true)
	add("active", g.ID, owned.ID, active.ID, "open", false)
	add("moved-asset", g.ID, outside.ID, failed.ID, "open", false)
	add("foreign-finding", other.ID, outside.ID, foreign.ID, "open", false)
	add("foreign-session", g.ID, owned.ID, foreign.ID, "open", false)
	add("unknown-session", g.ID, owned.ID, uuid.New(), "open", false)
	add("closed", g.ID, owned.ID, done.ID, "resolved", false)
	rows, err := Claim(ctx, db, fresh, now)
	if err != nil || len(rows) != 0 {
		t.Fatalf("future plans should not be claimed: %v %d", err, len(rows))
	}
	for id, old := range before {
		got := db.Finding.GetX(ctx, id)
		if shouldClear[id] {
			if got.WorkSessionID != nil || got.WorkLeaseUntil != nil {
				t.Fatalf("orphan not recovered %+v", got)
			}
		} else if got.WorkSessionID == nil || *got.WorkSessionID != *old.WorkSessionID || got.WorkLeaseUntil == nil || !got.WorkLeaseUntil.Equal(*old.WorkLeaseUntil) {
			t.Fatalf("active, unknown or out-of-scope lease was cleared %+v", got)
		}
		if got.Status != old.Status || got.WorkAttempts != old.WorkAttempts || !bytes.Equal(got.Work, old.Work) || got.WorkNextCheckAt == nil || !got.WorkNextCheckAt.Equal(*old.WorkNextCheckAt) {
			t.Fatalf("orphan recovery changed observation/counter/plan/next %+v", got)
		}
	}
	logs := db.AuditLog.Query().Where(auditlog.ActionEQ("finding_work_orphan_recovered")).AllX(ctx)
	if len(logs) != 1 || logs[0].Detail == nil || !strings.Contains(*logs[0].Detail, "count=2") || !strings.Contains(*logs[0].Detail, "未下发或重放指令") {
		t.Fatalf("missing precise recovery audit %+v", logs)
	}
	if _, err := Claim(ctx, db, fresh, now); err != nil {
		t.Fatal(err)
	}
	if n := db.AuditLog.Query().Where(auditlog.ActionEQ("finding_work_orphan_recovered")).CountX(ctx); n != 1 {
		t.Fatal("recovery repeated", n)
	}
	if db.Command.Query().CountX(ctx) != 0 {
		t.Fatal("orphan cleanup replayed commands")
	}
}
