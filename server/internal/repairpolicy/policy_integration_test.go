//go:build integration

package repairpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/command"
	"openxdr/server/ent/commandpolicy"
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
		{"budget", func(t *testing.T, x *fixture) { x.save(t); x.bind(t); x.f.Update().SetWorkAttempts(4).ExecX(x.ctx) }},
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
