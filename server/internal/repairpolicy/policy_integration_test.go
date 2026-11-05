//go:build integration

package repairpolicy

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/command"
	"openxdr/server/ent/commandpolicy"
	"openxdr/server/ent/setting"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
)

type fixture struct {
	ctx     context.Context
	db      *ent.Client
	store   *Store
	admin   *ent.User
	session *ent.AgentSession
	f       *ent.Finding
	grant   Grant
	cmd     string
	probe   *ent.Command
}

func setup(t *testing.T) *fixture {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetOs("linux").SetGroupID(g.ID).SaveX(ctx)
	admin := db.User.Create().SetUsername("admin").SetPasswordHash("h").SetRole("admin").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("real").SetStatus("running").SetRunOwner(uuid.New()).SetRunExpiresAt(time.Now().Add(3 * time.Minute)).SetRunDeadlineAt(time.Now().Add(30 * time.Minute)).SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("service-failed-worker").SetTitle("worker failed").SetWorkOwner("ai").SetWorkSessionID(session.ID).SetWorkLeaseUntil(time.Now().Add(30 * time.Minute)).SetWorkAttempts(1).SaveX(ctx)
	session.Update().SetSubjects([]string{"finding:" + f.ID.String()}).ExecX(ctx)
	db.Task.Create().SetID(findings.FollowupTask).SetName("follow").SetSchedule("*/30 * * * *").SetPrompt("p").SaveX(ctx)
	db.TaskRun.Create().SetTaskID(findings.FollowupTask).SetSessionID(session.ID).SetGroupID(g.ID).SetScheduledAt(time.Now()).SetStatus("running").SaveX(ctx)
	unit := "worker-app.service"
	probe := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd(ProbeCommand(unit)).SetStatus("succeeded").SetExitCode(0).SetStdout("Id=" + unit + "\nActiveState=failed\nUnitFileState=enabled\n").SetCompletedAt(time.Now()).SaveX(ctx)
	return &fixture{ctx, db, &Store{DB: db}, admin, session, f, Grant{ID: uuid.New(), Action: RestartFailedService, GroupID: g.ID, AssetIDs: []uuid.UUID{a.ID}, Units: []string{unit}, ExpiresAt: time.Now().Add(time.Hour), CooldownMinutes: 60}, "systemctl restart -- " + unit, probe}
}
func (x *fixture) save(t *testing.T) {
	t.Helper()
	if err := x.store.Save(auth.WithUser(x.ctx, x.admin), Policy{Grants: []Grant{x.grant}}, "test"); err != nil {
		t.Fatal(err)
	}
}
func (x *fixture) bind(t *testing.T) {
	t.Helper()
	if err := x.store.RecordProbe(x.ctx, x.session, x.probe); err != nil {
		t.Fatal(err)
	}
}

func TestRepairPolicyRequiresRealAdmin(t *testing.T) {
	x := setup(t)
	empty, err := x.store.Load(x.ctx)
	if err != nil || len(empty.Grants) != 0 {
		t.Fatal(empty, err)
	}
	if err := x.store.Save(x.ctx, Policy{Grants: []Grant{x.grant}}, "test"); err == nil {
		t.Fatal("internal task saved policy")
	}
	viewer := x.db.User.Create().SetUsername("viewer").SetPasswordHash("h").SetRole("viewer").SaveX(x.ctx)
	if err := x.store.Save(auth.WithUser(x.ctx, viewer), Policy{Grants: []Grant{x.grant}}, "test"); err == nil {
		t.Fatal("viewer saved policy")
	}
	fake := *viewer
	fake.Role = "admin"
	if err := x.store.Save(auth.WithUser(x.ctx, &fake), Policy{Grants: []Grant{x.grant}}, "test"); err == nil {
		t.Fatal("forged role accepted")
	}
	x.save(t)
	if n := x.db.AuditLog.Query().Where(auditlog.ActionEQ("repair_policy_update"), auditlog.UsernameEQ("admin")).CountX(x.ctx); n != 1 {
		t.Fatalf("no real admin audit %d", n)
	}
	x.admin.Update().SetRole("viewer").ExecX(x.ctx)
	if err := x.store.Save(auth.WithUser(x.ctx, x.admin), Policy{}, "test"); err == nil {
		t.Fatal("stale admin accepted")
	}
}

func TestRepairPolicyExactScopeAndProbe(t *testing.T) {
	for _, change := range []struct {
		name   string
		change func(*testing.T, *fixture)
	}{
		{"missing-policy", func(t *testing.T, x *fixture) {}},
		{"missing-binding", func(t *testing.T, x *fixture) { x.save(t) }},
		{"probe-other-unit", func(t *testing.T, x *fixture) {
			x.save(t)
			x.bind(t)
			x.probe.Update().SetStdout("Id=postgresql.service\nActiveState=failed\nUnitFileState=enabled\n").ExecX(x.ctx)
		}},
		{"not-failed", func(t *testing.T, x *fixture) {
			x.save(t)
			x.bind(t)
			x.probe.Update().SetStdout("Id=worker-app.service\nActiveState=inactive\nUnitFileState=enabled\n").ExecX(x.ctx)
		}},
		{"disabled", func(t *testing.T, x *fixture) {
			x.save(t)
			x.bind(t)
			x.probe.Update().SetStdout("Id=worker-app.service\nActiveState=failed\nUnitFileState=disabled\n").ExecX(x.ctx)
		}},
		{"unknown-probe", func(t *testing.T, x *fixture) {
			x.save(t)
			x.bind(t)
			x.probe.Update().SetStatus("unknown").ExecX(x.ctx)
		}},
		{"truncated-probe", func(t *testing.T, x *fixture) { x.save(t); x.bind(t); x.probe.Update().SetTruncated(true).ExecX(x.ctx) }},
		{"old-probe", func(t *testing.T, x *fixture) {
			x.save(t)
			x.bind(t)
			x.probe.Update().SetCompletedAt(time.Now().Add(-11 * time.Minute)).ExecX(x.ctx)
		}},
		{"expired-grant", func(t *testing.T, x *fixture) {
			x.grant.ExpiresAt = time.Now().Add(time.Second)
			x.save(t)
			x.bind(t)
			var p Policy
			p.Grants = []Grant{x.grant}
			p.Grants[0].ExpiresAt = time.Now().Add(-time.Second)
			raw, _ := json.Marshal(p)
			x.db.Setting.UpdateOneID(SettingKey).SetValue(raw).ExecX(x.ctx)
		}},
		{"expired-claim", func(t *testing.T, x *fixture) {
			x.save(t)
			x.bind(t)
			x.f.Update().SetWorkLeaseUntil(time.Now().Add(-time.Second)).ExecX(x.ctx)
		}},
		{"cancelled-session", func(t *testing.T, x *fixture) {
			x.save(t)
			x.bind(t)
			x.session.Update().SetCancelRequestedAt(time.Now()).ExecX(x.ctx)
		}},
		{"unknown-write", func(t *testing.T, x *fixture) {
			x.save(t)
			x.bind(t)
			x.db.Command.Create().SetKind("exec").SetAssetID(x.f.AssetID).SetCmd("systemctl restart legacy.service").SetStatus("unknown").SaveX(x.ctx)
		}},
		{"budget", func(t *testing.T, x *fixture) {
			x.save(t)
			x.bind(t)
			x.f.Update().SetWork(findings.EncodeWork(findings.Work{Version: 2, RepairAttempts: 4})).ExecX(x.ctx)
		}},
		{"moved-asset", func(t *testing.T, x *fixture) {
			x.save(t)
			x.bind(t)
			g := x.db.Group.Create().SetName("moved").SaveX(x.ctx)
			x.db.Asset.UpdateOneID(x.f.AssetID).SetGroupID(g.ID).ExecX(x.ctx)
		}},
		{"shell", func(t *testing.T, x *fixture) { x.save(t); x.bind(t); x.cmd += "; rm -rf /tmp/anything" }},
		{"other-service", func(t *testing.T, x *fixture) { x.save(t); x.bind(t); x.cmd = "systemctl restart -- other.service" }},
		{"duplicate-fields", func(t *testing.T, x *fixture) {
			x.save(t)
			x.bind(t)
			x.probe.Update().SetStdout("Id=worker-app.service\nActiveState=failed\nActiveState=failed\nUnitFileState=enabled").ExecX(x.ctx)
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			x := setup(t)
			change.change(t, x)
			if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err == nil {
				t.Fatal("unsafe restart authorized")
			}
		})
	}
}

func TestRepairPolicyAtomicReservationAndCooldown(t *testing.T) {
	x := setup(t)
	x.save(t)
	x.bind(t)
	var wg sync.WaitGroup
	var wins atomic.Int32
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if x.store.Authorize(x.ctx, x.session, x.f, x.cmd) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("concurrent authorizations %d", wins.Load())
	}
	if n := x.db.AuditLog.Query().Where(auditlog.ActionEQ("repair_action_reserved")).CountX(x.ctx); n != 1 {
		t.Fatalf("reservation audit count %d", n)
	}
	// 更新策略不能清除已预留的动作/冷却，预留后即便下发失败也不盲目重放。
	x.save(t)
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("same action replayed")
	}
	next := x.db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(x.session.GroupID).SetModel("real").SetStatus("running").SetRunOwner(uuid.New()).SetRunExpiresAt(time.Now().Add(3 * time.Minute)).SetRunDeadlineAt(time.Now().Add(30 * time.Minute)).SetSubjects([]string{"finding:" + x.f.ID.String()}).SaveX(x.ctx)
	x.db.TaskRun.Query().OnlyX(x.ctx).Update().SetSessionID(next.ID).ExecX(x.ctx)
	x.f.Update().SetWorkSessionID(next.ID).ExecX(x.ctx)
	x.session = next
	x.probe = x.db.Command.Create().SetAssetID(x.f.AssetID).SetKind("exec").SetCmd(ProbeCommand(x.grant.Units[0])).SetStatus("succeeded").SetExitCode(0).SetStdout("Id=worker-app.service\nActiveState=failed\nUnitFileState=enabled\n").SetCompletedAt(time.Now()).SaveX(x.ctx)
	x.bind(t)
	x.grant.ID = uuid.New()
	x.save(t)
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("new session/grant bypassed asset service cooldown")
	}
}

func TestRepairPolicyHandlerAndCoreUnits(t *testing.T) {
	x := setup(t)
	for _, u := range []string{"postgresql.service", "patroni.service", "openxdr-agent.service", "nats.service", "sshd.service", "systemd-networkd.service", "docker.service", "worker@01.service", "../worker.service", "worker.service;id", "worker\\x2dapp.service"} {
		copy := x.grant
		copy.Units = []string{u}
		if err := x.store.validate(x.ctx, Policy{Grants: []Grant{copy}}, time.Now()); err == nil {
			t.Errorf("unit accepted: %s", u)
		}
	}
	raw, _ := json.Marshal(Policy{Grants: []Grant{x.grant}})
	request := httptest.NewRequest(http.MethodPut, "/api/settings/repair-policy", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	x.store.Handler().ServeHTTP(w, request)
	if w.Code != http.StatusForbidden {
		t.Fatal(w.Code)
	}
	request = httptest.NewRequest(http.MethodPut, "/api/settings/repair-policy", bytes.NewReader(raw))
	request = request.WithContext(auth.WithUser(request.Context(), x.admin))
	w = httptest.NewRecorder()
	x.store.Handler().ServeHTTP(w, request)
	if w.Code != http.StatusNoContent {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	raw = []byte(`{"grants":[],"shell":"reboot"}`)
	request = httptest.NewRequest(http.MethodPut, "/api/settings/repair-policy", bytes.NewReader(raw)).WithContext(auth.WithUser(x.ctx, x.admin))
	w = httptest.NewRecorder()
	x.store.Handler().ServeHTTP(w, request)
	if w.Code != http.StatusBadRequest {
		t.Fatal("unknown field accepted", w.Code)
	}
}

func TestRepairRevalidatedAfterReviewerWaitBeforeHub(t *testing.T) {
	for _, mode := range []string{"revoked", "expired", "moved", "new-unknown", "probe-expired", "finding-closed", "approved"} {
		t.Run(mode, func(t *testing.T) {
			x := setup(t)
			if mode == "expired" {
				x.grant.ExpiresAt = time.Now().Add(500 * time.Millisecond)
			}
			x.save(t)
			x.bind(t)
			if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err != nil {
				t.Fatal(err)
			}
			agent := uuid.New()
			x.db.Asset.UpdateOneID(x.f.AssetID).SetAgentID(agent).SetOs("linux").ExecX(x.ctx)
			hub := response.NewHub(x.db, true)
			inbox := hub.Attach(agent)
			defer hub.Detach(agent, inbox)
			x.db.CommandPolicy.Create().SetGroupID(x.session.GroupID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern(`^systemctl restart -- `).SaveX(x.ctx)
			gate := &commandgate.Gate{DB: x.db, Hub: hub, Reviewer: func(_ context.Context, _ commandgate.Request) (bool, string, error) {
				switch mode {
				case "revoked":
					if err := x.store.Save(auth.WithUser(x.ctx, x.admin), Policy{Grants: []Grant{}}, "review-wait"); err != nil {
						t.Fatal(err)
					}
				case "expired":
					time.Sleep(600 * time.Millisecond)
				case "moved":
					g := x.db.Group.Create().SetName("moved-during-review").SaveX(x.ctx)
					x.db.Asset.UpdateOneID(x.f.AssetID).SetGroupID(g.ID).ExecX(x.ctx)
				case "new-unknown":
					x.db.Command.Create().SetAssetID(x.f.AssetID).SetKind("exec").SetCmd("systemctl restart legacy.service").SetStatus("unknown").SaveX(x.ctx)
				case "probe-expired":
					x.probe.Update().SetCompletedAt(time.Now().Add(-11 * time.Minute)).ExecX(x.ctx)
				case "finding-closed":
					x.f.Update().SetStatus("resolved").ClearWorkSessionID().ExecX(x.ctx)
				}
				return true, "review completed", nil
			}}
			before := 0
			req := commandgate.Request{System: true, GroupID: x.session.GroupID, SessionID: &x.session.ID, Origin: "ai", Command: response.Request{Kind: "exec", AssetID: x.f.AssetID, Cmd: &x.cmd}, BeforeIssue: func(ctx context.Context) error { before++; return x.store.Revalidate(ctx, x.session, x.f, x.cmd) }}
			_, err := gate.Issue(x.ctx, req)
			if mode == "approved" {
				if err != nil || before != 1 {
					t.Fatalf("positive path rejected: before=%d err=%v", before, err)
				}
				select {
				case got := <-inbox:
					if got.Cmd != x.cmd {
						t.Fatal(got.Cmd)
					}
				default:
					t.Fatal("approved repair not issued")
				}
				if _, err := gate.Issue(x.ctx, req); err == nil {
					t.Fatal("consumed reservation allowed a second issue")
				}
			} else if err == nil {
				t.Fatal("review delay invalidation still issued repair")
			}
			select {
			case got := <-inbox:
				t.Fatalf("unexpected extra/invalid Hub issue: %+v", got)
			default:
			}
			expected := 0
			if mode == "approved" {
				expected = 1
			}
			if n := x.db.Command.Query().Where(command.CmdEQ(x.cmd)).CountX(x.ctx); n != expected {
				t.Fatalf("commands created %d want %d", n, expected)
			}
		})
	}
}

func TestNonLinuxRepairScopeRejected(t *testing.T) {
	x := setup(t)
	x.db.Asset.UpdateOneID(x.f.AssetID).SetOs("windows").ExecX(x.ctx)
	if err := x.store.Save(auth.WithUser(x.ctx, x.admin), Policy{Grants: []Grant{x.grant}}, "test"); err == nil {
		t.Fatal("非Linux主机接受了systemd维护范围")
	}
	x.db.Asset.UpdateOneID(x.f.AssetID).SetOs("linux").ExecX(x.ctx)
	x.save(t)
	x.bind(t)
	x.db.Asset.UpdateOneID(x.f.AssetID).SetOs("windows").ExecX(x.ctx)
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("系统类型改变仍允许Linux动作")
	}
}

func repairCount(t *testing.T, x *fixture) findings.Work {
	t.Helper()
	f := x.db.Finding.GetX(x.ctx, x.f.ID)
	var work findings.Work
	if len(f.Work) > 0 {
		if err := json.Unmarshal(f.Work, &work); err != nil {
			t.Fatal(err)
		}
	}
	return work
}

func TestRepairBudgetCountsOnlyCommittedReservations(t *testing.T) {
	x := setup(t)
	x.f.Update().SetWorkAttempts(50).SetWork(findings.EncodeWork(findings.Work{Version: 2, InvestigationAttempts: 50, VerificationAttempts: 9, TransportFailures: 4})).ExecX(x.ctx)
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("missing grant accepted")
	}
	if got := repairCount(t, x); got.RepairAttempts != 0 {
		t.Fatal("denial consumed repair budget", got)
	}
	x.save(t)
	x.bind(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if x.store.Authorize(x.ctx, x.session, x.f, x.cmd) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("reservation winners", wins.Load())
	}
	got := repairCount(t, x)
	if got.RepairAttempts != 1 || got.InvestigationAttempts != 50 || got.VerificationAttempts != 9 || got.TransportFailures != 4 {
		t.Fatalf("incorrect counters %+v", got)
	}
	if err := x.store.Revalidate(x.ctx, x.session, x.f, x.cmd); err != nil {
		t.Fatal(err)
	}
	if got := repairCount(t, x); got.RepairAttempts != 1 {
		t.Fatal("finalize consumed another attempt", got)
	}
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("duplicate reservation accepted")
	}
	if got := repairCount(t, x); got.RepairAttempts != 1 {
		t.Fatal("duplicate consumed repair budget", got)
	}
}

func TestRepairLastBudgetReservationCanFinalize(t *testing.T) {
	x := setup(t)
	x.save(t)
	x.bind(t)
	x.f.Update().SetWorkAttempts(99).SetWork(findings.EncodeWork(findings.Work{RepairAttempts: 2})).ExecX(x.ctx)
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err != nil {
		t.Fatal(err)
	}
	if got := repairCount(t, x); got.RepairAttempts != 3 || got.Version != 2 {
		t.Fatalf("third reservation missing %+v", got)
	}
	if err := x.store.Revalidate(x.ctx, x.session, x.f, x.cmd); err != nil {
		t.Fatal("own last reservation was refused", err)
	}
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("new action exceeded repair budget")
	}
	if got := repairCount(t, x); got.RepairAttempts != 3 {
		t.Fatal("exhausted denial changed counter", got)
	}
	x.f.Update().SetWork(findings.EncodeWork(findings.Work{Version: 2, RepairAttempts: 4})).ExecX(x.ctx)
	if err := x.store.Revalidate(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("corrupted budget accepted")
	}
}

func TestRepairPersistedBusinessBlockerPreventsRestart(t *testing.T) {
	for _, blocker := range []string{"legacy_decommission_confirm", "manual_business_decision", "external_dependency"} {
		t.Run(blocker, func(t *testing.T) {
			x := setup(t)
			x.save(t)
			x.bind(t)
			x.f.Update().SetWork(findings.EncodeWork(findings.Work{Version: 2, Blocker: blocker})).ExecX(x.ctx)
			if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err == nil {
				t.Fatal("business blocker authorized restart")
			}
			if repairCount(t, x).RepairAttempts != 0 {
				t.Fatal("blocked action consumed budget")
			}
		})
	}
	x := setup(t)
	x.save(t)
	x.bind(t)
	x.f.Update().SetTitle("legacy retired please do not restart").ExecX(x.ctx)
	// 文本本身不是可信退役状态；不得仅按标题关键词扩大或收窄维护授权。
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err != nil {
		t.Fatal("title text was treated as trusted business state", err)
	}
	work := repairCount(t, x)
	work.Blocker = "manual_business_decision"
	x.f.Update().SetWork(findings.EncodeWork(work)).ExecX(x.ctx)
	if err := x.store.Revalidate(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("new business blocker ignored after review")
	}
}

func TestRepairReservationBindsOriginalProblemAndGrantVersion(t *testing.T) {
	for _, mode := range []string{"problem", "grant", "unrelated-grant"} {
		t.Run(mode, func(t *testing.T) {
			x := setup(t)
			x.save(t)
			x.bind(t)
			x.f.Update().SetWork(findings.EncodeWork(findings.Work{Version: 2, OriginalTitle: "worker failed", OriginalProblem: "repeated crash"})).ExecX(x.ctx)
			if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "problem":
				work := repairCount(t, x)
				work.OriginalProblem = "different business problem"
				x.f.Update().SetWork(findings.EncodeWork(work)).ExecX(x.ctx)
			case "grant":
				x.grant.ExpiresAt = x.grant.ExpiresAt.Add(time.Hour)
				x.save(t)
			case "unrelated-grant":
				other := x.grant
				other.ID = uuid.New()
				other.Units = []string{"another-worker.service"}
				if err := x.store.Save(auth.WithUser(x.ctx, x.admin), Policy{Grants: []Grant{x.grant, other}}, "test"); err != nil {
					t.Fatal(err)
				}
			}
			err := x.store.Revalidate(x.ctx, x.session, x.f, x.cmd)
			if mode == "unrelated-grant" {
				if err != nil {
					t.Fatal("unrelated grant update invalidated reservation", err)
				}
			} else if err == nil {
				t.Fatal("changed problem/grant reused old reservation")
			}
			if got := repairCount(t, x); got.RepairAttempts != 1 {
				t.Fatal("revalidation changed budget", got)
			}
		})
	}
}

func TestRepairGrantLookupIsExactAndReadOnly(t *testing.T) {
	x := setup(t)
	check := func(want bool) {
		t.Helper()
		got, err := x.store.HasGrant(x.ctx, x.session.GroupID, x.f.AssetID, RestartFailedService, x.grant.Units[0])
		if err != nil || got != want {
			t.Fatal(got, err)
		}
		all, err := x.store.HasAssetGrant(x.ctx, x.session.GroupID, x.f.AssetID)
		if err != nil || all != want {
			t.Fatal("asset scope", all, err)
		}
	}
	check(false)
	x.save(t)
	check(true)
	if got, err := x.store.HasGrant(x.ctx, x.session.GroupID, x.f.AssetID, RestartFailedService, "another-worker.service"); err != nil || got {
		t.Fatal("similar unit considered delegated", got, err)
	}
	if got, err := x.store.HasGrant(x.ctx, x.session.GroupID, x.f.AssetID, RestartFailedService, "sshd.service"); err == nil || got {
		t.Fatal("core unit accepted")
	}
	g := x.db.Group.Create().SetName("other").SaveX(x.ctx)
	if got, err := x.store.HasAssetGrant(x.ctx, g.ID, x.f.AssetID); err != nil || got {
		t.Fatal("wrong group accepted", got, err)
	}
	x.db.Setting.DeleteOneID(SettingKey).ExecX(x.ctx)
	check(false)
	if n := x.db.Setting.Query().CountX(x.ctx); n != 0 {
		t.Fatal("read-only helper wrote settings", n)
	}
	if got := repairCount(t, x); got.RepairAttempts != 0 {
		t.Fatal("read-only helper consumed repair budget", got)
	}
}

func TestRepairReservationAuditFailureRollsBackBudget(t *testing.T) {
	x := setup(t)
	x.save(t)
	x.bind(t)
	raw, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = raw.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS reject_repair_reservation ON audit_logs; DROP FUNCTION IF EXISTS reject_repair_reservation()`)
		_ = raw.Close()
	})
	_, err = raw.ExecContext(x.ctx, `CREATE FUNCTION reject_repair_reservation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'repair_action_reserved' THEN RAISE EXCEPTION 'test audit fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_repair_reservation BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_repair_reservation()`)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("audit failure committed reservation")
	}
	if got := repairCount(t, x); got.RepairAttempts != 0 {
		t.Fatal("rolled-back reservation consumed budget", got)
	}
	if exists, err := x.db.Setting.Query().Where(setting.IDEQ(useKey(x.f.AssetID, x.grant.Units[0]))).Exist(x.ctx); err != nil || exists {
		t.Fatal("rolled-back reservation survived", exists, err)
	}
}
