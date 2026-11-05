//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/testdb"
)

func TestAuditTrackOpenCannotEraseConcurrentHumanResolution(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("audit-human-fence").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	actor := db.User.Create().SetUsername("analyst").SetPasswordHash("test").SetRole("analyst").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetInitiator(actor.Username).SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("service").SetTitle("service failed").SetWork(findings.EncodeWork(findings.Work{Version: 2, Plan: "original", RepairAttempts: 1})).SaveX(ctx)
	f = db.Finding.GetX(ctx, f.ID) // 使用PostgreSQL实际时间精度比较人工变更前后的LastSeen。
	var injected atomic.Bool
	db.Finding.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			change, ok := m.(*ent.FindingMutation)
			if ok {
				id, hasID := change.ID()
				status, setsStatus := change.Status()
				if hasID && id == f.ID && setsStatus && status == "open" && !injected.Swap(true) {
					// 在track读到旧快照之后、它首次更新之前，模拟人工完成处置；人工接口不改变LastSeen。
					if err := findings.Set(ctx, db, f, "resolved", "manually verified maintenance completed", actor.Username, "test", ""); err != nil {
						return nil, err
					}
				}
			}
			return next.Mutate(ctx, m)
		})
	})
	args := []byte(`{"host":"` + a.ID.String() + `","key":"service","title":"still failed","detail":"old observation","severity":"medium","status":"open","next_step":"stale follow-up"}`)
	_, err := (&Service{DB: db}).tool(ctx, session, commandgate.Request{UserID: actor.ID}, "track", args)
	if !injected.Load() || err == nil {
		t.Fatalf("stale track was not fenced: injected=%v err=%v", injected.Load(), err)
	}
	got := db.Finding.GetX(ctx, f.ID)
	if got.Status != "resolved" || got.ResolvedBy == nil || *got.ResolvedBy != actor.Username || got.ResolvedAt == nil || got.Note == nil || *got.Note != "manually verified maintenance completed" || !got.LastSeen.Equal(f.LastSeen) {
		t.Fatalf("human decision erased by stale AI observation: %+v", got)
	}
	if n := db.AuditLog.Query().Where(auditlog.ActionEQ("finding_status")).CountX(ctx); n != 1 {
		t.Fatal("human audit missing", n)
	}
}

func TestAuditFindingReviewCannotOverwriteConcurrentRepairBudget(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("audit-budget-fence").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SetCreatedAt(time.Now().Add(-time.Minute)).SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("service").SetTitle("service failed").SetWork(findings.EncodeWork(findings.Work{Version: 2, OriginalTitle: "service failed", OriginalProblem: "service failed", RepairAttempts: 1})).SaveX(ctx)
	now := time.Now()
	c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("systemctl show --property=ActiveState -- worker.service").SetStatus("succeeded").SetExitCode(0).SetStdout("ActiveState=active").SetCreatedAt(now.Add(-time.Second)).SetCompletedAt(now).SaveX(ctx)
	svc := &Service{DB: db, ReviewFinding: func(_ context.Context, _ *ent.AgentSession, _ *ent.Finding, _ []*ent.Command) (bool, string, error) {
		current := db.Finding.GetX(ctx, f.ID)
		var work findings.Work
		if err := json.Unmarshal(current.Work, &work); err != nil {
			return false, "", err
		}
		// 复核进行期间另一条真实执行路径已持久预留修复。最终结案不能用旧JSON覆盖此计数。
		work.RepairAttempts = 2
		work.Plan = "concurrent reservation preserved"
		if err := current.Update().SetWork(findings.EncodeWork(work)).Exec(ctx); err != nil {
			return false, "", err
		}
		return true, "service active", nil
	}}
	args := []byte(`{"host":"` + a.ID.String() + `","key":"service","title":"recovered","detail":"active","severity":"low","status":"resolved","evidence_commands":["` + c.ID.String() + `"]}`)
	if _, err := svc.tool(ctx, session, commandgate.Request{System: true}, "track", args); err == nil {
		t.Fatal("review overwrote newer repair reservation")
	}
	got := db.Finding.GetX(ctx, f.ID)
	var work findings.Work
	_ = json.Unmarshal(got.Work, &work)
	if got.Status != "open" || got.ResolvedAt != nil || work.RepairAttempts != 2 || work.VerificationAttempts != 1 || work.Plan != "concurrent reservation preserved" {
		t.Fatalf("lost concurrent state %+v %+v", got, work)
	}
	if n := db.AuditLog.Query().Where(auditlog.ActionEQ("finding_ai_review")).CountX(ctx); n != 0 {
		t.Fatal("failed CAS forged closure audit", n)
	}
}

func TestAuditRiskFollowupSurvivesRuntimeRelease(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("audit-risk-release").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	now := time.Now()
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SetCreatedAt(now.Add(-time.Minute)).SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("capacity").SetTitle("根分区空间不足").SetSeverity("medium").SetWorkAttempts(20).SetWorkSessionID(session.ID).SetWorkLeaseUntil(now.Add(30 * time.Minute)).SetWork(findings.EncodeWork(findings.Work{Version: 2, OriginalTitle: "根分区空间不足", RepairAttempts: 0})).SaveX(ctx)
	c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("df -P /").SetStatus("succeeded").SetExitCode(0).SetStdout("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/root 100000 96000 4000 96% /\n").SetCreatedAt(now.Add(-time.Second)).SetCompletedAt(now).SaveX(ctx)
	if err := (&Service{DB: db}).saveFindingPlan(ctx, session, f, "confirm sustained root disk pressure", "", []uuid.UUID{c.ID}); err != nil {
		t.Fatal(err)
	}
	if err := findings.Release(ctx, db, session.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	got := db.Finding.GetX(ctx, f.ID)
	var work findings.Work
	_ = json.Unmarshal(got.Work, &work)
	if work.RiskSince == nil || work.EscalatedAt != nil || work.RepairAttempts != 0 || got.WorkNextCheckAt == nil || got.WorkNextCheckAt.After(now.Add(16*time.Minute)) || got.WorkSessionID != nil || got.WorkLeaseUntil != nil {
		t.Fatalf("runtime Release erased pending risk schedule: %+v %+v", got, work)
	}
	if !strings.Contains(work.Plan, "sustained") {
		t.Fatal("plan lost", work.Plan)
	}
}

func TestAuditRealRecoveryAllowsNewRiskEpisodeEscalation(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("audit-risk-episodes").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	now := time.Now().UTC().Truncate(time.Microsecond)
	old := now.Add(-40 * time.Minute)
	oldEscalation := now.Add(-30 * time.Minute)
	session := db.AgentSession.Create().SetKind("chat").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SetCreatedAt(now.Add(-time.Hour)).SaveX(ctx)
	work := findings.Work{Version: 2, OriginalTitle: "根分区空间不足", RiskTarget: &findings.RiskTarget{Kind: "disk_root", Mount: "/", AssetID: a.ID}, RiskSince: &old, RiskObservedAt: &oldEscalation, RiskKind: "disk_pressure", EscalatedAt: &oldEscalation, EscalationNotifiedAt: &oldEscalation}
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("capacity").SetTitle("根分区空间不足").SetWork(findings.EncodeWork(work)).SaveX(ctx)
	if err := audit.Checked(ctx, db.AuditLog.Create(), "system", "server", "finding_risk_escalated", f.ID.String(), "previous episode"); err != nil {
		t.Fatal(err)
	}
	svc := &Service{DB: db}
	probe := func(out string, at time.Time) *ent.Command {
		return db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("df -P /").SetStatus("succeeded").SetExitCode(0).SetStdout(out).SetCreatedAt(at.Add(-time.Second)).SetCompletedAt(at).SaveX(ctx)
	}
	healthy := probe("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/root 100000 50000 50000 50% /\n", now.Add(-time.Minute))
	if err := svc.saveFindingPlan(ctx, session, f, "watch verified recovery", "", []uuid.UUID{healthy.ID}); err != nil {
		t.Fatal(err)
	}
	f = db.Finding.GetX(ctx, f.ID)
	work = findings.Work{}
	_ = json.Unmarshal(f.Work, &work)
	if work.RiskSince != nil || work.RiskKind != "" || work.EscalatedAt != nil || work.EscalationNotifiedAt != nil {
		t.Fatalf("real recovery did not end current risk episode: %+v", work)
	}
	if n := db.AuditLog.Query().Where(auditlog.ActionEQ("finding_risk_recovered")).CountX(ctx); n != 1 {
		t.Fatal("recovery history missing", n)
	}
	critical := probe("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/root 100000 96000 4000 96% /\n", now.Add(-30*time.Second))
	if err := svc.saveFindingPlan(ctx, session, f, "confirm a new risk episode", "", []uuid.UUID{critical.ID}); err != nil {
		t.Fatal(err)
	}
	f = db.Finding.GetX(ctx, f.ID)
	work = findings.Work{}
	_ = json.Unmarshal(f.Work, &work)
	if work.RiskSince == nil || work.EscalatedAt != nil {
		t.Fatalf("first new critical sample escalated prematurely %+v", work)
	}
	// 推进夹具中的历史时刻而不真实等待12分钟：恢复仍在新危急周期之前，原始探针和持久状态一致。
	healthy.Update().SetCreatedAt(now.Add(-21 * time.Minute)).SetCompletedAt(now.Add(-20 * time.Minute)).ExecX(ctx)
	critical.Update().SetCreatedAt(now.Add(-13 * time.Minute)).SetCompletedAt(now.Add(-12 * time.Minute)).ExecX(ctx)
	firstCritical := now.Add(-12 * time.Minute)
	work.RiskSince = &firstCritical
	work.RiskObservedAt = &firstCritical
	f = f.Update().SetWork(findings.EncodeWork(work)).SaveX(ctx)
	latest := probe("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/root 100000 96000 4000 96% /\n", now)
	if err := svc.saveFindingPlan(ctx, session, f, "new cycle is persistently critical", "", []uuid.UUID{latest.ID}); err != nil {
		t.Fatal(err)
	}
	f = db.Finding.GetX(ctx, f.ID)
	work = findings.Work{}
	_ = json.Unmarshal(f.Work, &work)
	if work.EscalatedAt == nil || work.EscalationNotifiedAt != nil {
		t.Fatalf("new risk cycle never escalated after prior recovery %+v", work)
	}
	if n := db.AuditLog.Query().Where(auditlog.ActionEQ("finding_risk_escalated")).CountX(ctx); n != 2 {
		t.Fatal("expected one durable escalation per cycle", n)
	}
	if n := db.AuditLog.Query().Where(auditlog.ActionEQ("finding_risk_recovered")).CountX(ctx); n != 1 {
		t.Fatal("old recovery audit lost", n)
	}
}
