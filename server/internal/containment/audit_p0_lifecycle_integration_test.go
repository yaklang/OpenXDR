//go:build integration

package containment

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/ent/hook"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

type auditP0Fixture struct {
	ctx    context.Context
	db     *ent.Client
	hub    *response.Hub
	engine *Engine
	group  uuid.UUID
	now    time.Time
	inbox  map[uuid.UUID]chan *pb.Command
}

func auditP0Setup(t *testing.T) *auditP0Fixture {
	t.Helper()
	ctx, db := testdb.New(t)
	sq, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sq.Close() })
	f := &auditP0Fixture{ctx: ctx, db: db, hub: response.NewHub(db, true), now: time.Now().UTC(), inbox: make(map[uuid.UUID]chan *pb.Command)}
	f.group = db.Group.Create().SetName("audit-P0").SaveX(ctx).ID
	f.engine = &Engine{DB: db, SQL: sq, Hub: f.hub, Scope: ScopeAll, TTL: 24 * time.Hour, MaxPerHour: 10, AllowEndpoints: []string{"10.1.1.199:8081"}, Now: func() time.Time { return f.now }}
	return f
}

func (f *auditP0Fixture) host(name string) *ent.Asset {
	id := uuid.New()
	a := f.db.Asset.Create().SetHostname(name).SetOs("linux").SetAgentID(id).SetGroupID(f.group).SetResponseTier(entasset.ResponseTierLab).SaveX(f.ctx)
	f.inbox[a.ID] = f.hub.Attach(id)
	return a
}

func (f *auditP0Fixture) start(t *testing.T, a *ent.Asset, kind, target string) *ent.Containment {
	t.Helper()
	al := f.db.Alert.Create().SetTs(f.now).SetRuleID("audit.lifecycle").SetSeverity(5).SetAssetID(a.ID).SaveX(f.ctx)
	act := action{asset: a, kind: kind, target: target, role: "host", why: "审计状态边界"}
	if kind == "kill_process" {
		guid := uuid.New()
		act.target = guid.String()
		act.pid = 4242
		raw, _ := json.Marshal(map[string]any{"activity_id": 1, "process": map[string]any{"pid": 4242, "parent_process": map[string]any{"pid": 42}}})
		f.db.Event.Create().SetTs(f.now).SetClassUID(1007).SetSource("agent").SetAssetID(a.ID).SetProcessGUID(guid).SetRaw(raw).SaveX(f.ctx)
	}
	if err := f.engine.decide(f.ctx, al, nil, act, f.now); err != nil {
		t.Fatal(err)
	}
	return f.db.Containment.Query().Where(entcontainment.AlertIDEQ(al.ID)).OnlyX(f.ctx)
}

func (f *auditP0Fixture) receipt(t *testing.T, a *ent.Asset, id uuid.UUID, status pb.CommandResult_Status, detail string) {
	t.Helper()
	if err := f.hub.Complete(f.ctx, *a.AgentID, &pb.CommandResult{CommandId: id.String(), Status: status, Detail: detail}); err != nil {
		t.Fatal(err)
	}
}

func (f *auditP0Fixture) tick(t *testing.T) {
	t.Helper()
	if err := f.engine.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
}

func auditP0NotApplied(t *testing.T, c *ent.Containment) {
	t.Helper()
	if c.State == entcontainment.StateActive || c.State == entcontainment.StateExecuted {
		t.Errorf("未确认成功却标为已生效/已执行: %s", c.State)
	}
}

func TestAuditP0InitialReceiptLifecycle(t *testing.T) {
	for _, kind := range []string{"block_network", "kill_process"} {
		for _, st := range []struct {
			name   string
			status pb.CommandResult_Status
			detail string
		}{
			{"success", pb.CommandResult_SUCCEEDED, "ok"},
			{"failure", pb.CommandResult_FAILED, "执行失败"},
			{"unsupported", pb.CommandResult_UNSUPPORTED, "动作不支持"},
			{"unknown", pb.CommandResult_STATUS_UNSPECIFIED, "结果未知"},
			{"target_gone", pb.CommandResult_FAILED, "进程不存在或无法打开 pidfd: No such process (os error 3)"},
			{"identity_guard", pb.CommandResult_FAILED, "进程身份不匹配或已过期，拒绝结束进程"},
		} {
			t.Run(kind+"/"+st.name, func(t *testing.T) {
				f := auditP0Setup(t)
				a := f.host("endpoint")
				c := f.start(t, a, kind, "192.0.2.44")
				auditP0NotApplied(t, c)
				if c.CommandID == nil {
					t.Fatal("没有原指令关联")
				}
				id := *c.CommandID
				f.receipt(t, a, id, st.status, st.detail)
				f.tick(t)
				c = f.db.Containment.GetX(f.ctx, c.ID)
				if st.status == pb.CommandResult_SUCCEEDED {
					want := entcontainment.StateExecuted
					if kind == "block_network" {
						want = entcontainment.StateActive
					}
					if c.State != want {
						t.Errorf("成功回执未对账: got=%s want=%s", c.State, want)
					}
				} else {
					auditP0NotApplied(t, c)
				}
				f.tick(t)
				if n := f.db.Command.Query().CountX(f.ctx); n != 1 {
					t.Errorf("原指令被重复下发: %d", n)
				}
			})
		}
	}
}

func (f *auditP0Fixture) activeLease(t *testing.T, expired bool) (*ent.Asset, *ent.Containment) {
	t.Helper()
	a := f.host("lease-endpoint")
	c := f.start(t, a, "block_network", "192.0.2.44")
	f.receipt(t, a, *c.CommandID, pb.CommandResult_SUCCEEDED, "封禁已完成")
	f.tick(t)
	until := f.now.Add(time.Hour)
	if expired {
		until = f.now.Add(-time.Minute)
	}
	c = f.db.Containment.UpdateOneID(c.ID).SetState(entcontainment.StateActive).SetExpiresAt(until).SaveX(f.ctx)
	return a, c
}

func TestAuditP0ExpiryWaitsForOriginalReceipt(t *testing.T) {
	for _, st := range []struct {
		name   string
		status string
	}{
		{"sent", "sent"}, {"pending", "pending"}, {"unknown", "unknown"}, {"unsupported", "unsupported"}, {"failed", "failed"}, {"succeeded", "succeeded"},
	} {
		t.Run(st.name, func(t *testing.T) {
			f := auditP0Setup(t)
			a, c := f.activeLease(t, true)
			f.tick(t)
			c = f.db.Containment.GetX(f.ctx, c.ID)
			if c.State != entcontainment.StateActive || c.EndedAt != nil {
				t.Errorf("解除仅投递便提前完成: state=%s ended=%v", c.State, c.EndedAt)
			}
			if c.LiftCommandID == nil {
				t.Fatal("解除指令没有关联")
			}
			id := *c.LiftCommandID
			f.db.Command.UpdateOneID(id).SetStatus(st.status).ExecX(f.ctx)
			if st.status == "succeeded" {
				f.db.Command.UpdateOneID(id).SetCompletedAt(f.now).ExecX(f.ctx)
			}
			f.tick(t)
			c = f.db.Containment.GetX(f.ctx, c.ID)
			if st.status == "succeeded" {
				if c.State != entcontainment.StateExpired || c.EndedAt == nil {
					t.Errorf("成功解除未对账: %+v", c)
				}
			} else if c.State != entcontainment.StateActive || c.EndedAt != nil {
				t.Errorf("未确认解除成功却不再生效: state=%s ended=%v", c.State, c.EndedAt)
			}
			if st.status == "unknown" || st.status == "unsupported" || st.status == "sent" || st.status == "pending" {
				f.now = f.now.Add(time.Hour)
				f.tick(t)
				if n := f.db.Command.Query().CountX(f.ctx); n != 2 {
					t.Errorf("未决/不支持的解除指令被重复创建: %d", n)
				}
			}
			_ = a
		})
	}
}

func TestAuditP0ManualLiftWaitsForReceipt(t *testing.T) {
	f := auditP0Setup(t)
	a, c := f.activeLease(t, false)
	if _, err := Lift(f.ctx, f.db, f.hub, c, "audit-user", "解除测试"); err != nil {
		t.Fatal(err)
	}
	c = f.db.Containment.GetX(f.ctx, c.ID)
	if c.State != entcontainment.StateActive || c.EndedAt != nil {
		t.Errorf("人工解除只投递就标结束: %s %v", c.State, c.EndedAt)
	}
	if c.LiftCommandID == nil {
		t.Fatal("没有解除指令关联")
	}
	id := *c.LiftCommandID
	_, _ = Lift(f.ctx, f.db, f.hub, c, "audit-user", "重复点击")
	if n := f.db.Command.Query().CountX(f.ctx); n != 2 {
		t.Errorf("重复点击产生新解除指令: %d", n)
	}
	f.receipt(t, a, id, pb.CommandResult_SUCCEEDED, "解除成功")
	f.tick(t)
	c = f.db.Containment.GetX(f.ctx, c.ID)
	if c.State != entcontainment.StateLifted || c.EndedAt == nil {
		t.Errorf("人工解除成功后未对账: %s %v", c.State, c.EndedAt)
	}
}

func TestAuditP0PendingActionsReserveFuseBudget(t *testing.T) {
	t.Run("hourly", func(t *testing.T) {
		f := auditP0Setup(t)
		f.engine.MaxPerHour = 1
		a := f.host("budget")
		f.start(t, a, "block_network", "192.0.2.41")
		c := f.start(t, a, "block_network", "192.0.2.42")
		if n := f.db.Command.Query().CountX(f.ctx); n != 1 {
			t.Errorf("待确认动作没有保留小时配额: %d", n)
		}
		if c.State != entcontainment.StateHeld {
			t.Errorf("后续动作没有熔断: %s", c.State)
		}
	})
	t.Run("group_isolation", func(t *testing.T) {
		f := auditP0Setup(t)
		a := f.host("host-a")
		b := f.host("host-b")
		f.start(t, a, "isolate_host", "")
		c := f.start(t, b, "isolate_host", "")
		if n := f.db.Command.Query().CountX(f.ctx); n != 1 {
			t.Errorf("待确认隔离没保留组内配额: %d", n)
		}
		if c.State != entcontainment.StateHeld {
			t.Errorf("隔离配额未熔断: %s", c.State)
		}
	})
}

func TestAuditP0HistoricalFalseSuccessReconciles(t *testing.T) {
	f := auditP0Setup(t)
	a := f.host("legacy")
	c := f.start(t, a, "kill_process", "")
	f.receipt(t, a, *c.CommandID, pb.CommandResult_FAILED, "进程身份不匹配或已过期，拒绝结束进程")
	f.db.Containment.UpdateOneID(c.ID).SetState(entcontainment.StateExecuted).ExecX(f.ctx)
	f.tick(t)
	c = f.db.Containment.GetX(f.ctx, c.ID)
	auditP0NotApplied(t, c)
	if n := f.db.Command.Query().CountX(f.ctx); n != 1 {
		t.Errorf("历史失败被重放: %d", n)
	}
}

func TestAuditP0ConcurrentLiftHasOneDelivery(t *testing.T) {
	f := auditP0Setup(t)
	_, c := f.activeLease(t, false)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var creates atomic.Int32
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	f.db.Command.Use(func(next ent.Mutator) ent.Mutator {
		return hook.CommandFunc(func(ctx context.Context, m *ent.CommandMutation) (ent.Value, error) {
			kind, _ := m.Kind()
			if m.Op() == ent.OpCreate && kind == "unblock_network" && creates.Add(1) == 1 {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, m)
		})
	})
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	done := make(chan error, 2)
	go func() { _, err := Lift(ctx, f.db, f.hub, c, "operator-a", "并发解除"); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("首条解除指令没有进入投递阶段")
	}
	go func() { _, err := Lift(ctx, f.db, f.hub, c, "operator-b", "并发解除"); done <- err }()
	time.AfterFunc(150*time.Millisecond, func() { once.Do(func() { close(release) }) })
	<-done
	<-done
	if n := f.db.Command.Query().CountX(f.ctx); n != 2 {
		t.Errorf("并发解除创建了重复指令，含初次封禁共%d条", n)
	}
}

func TestAuditP0LiftLinkPersistenceFailureDoesNotReplay(t *testing.T) {
	for _, manual := range []bool{false, true} {
		name := "expiry"
		if manual {
			name = "manual"
		}
		t.Run(name, func(t *testing.T) {
			f := auditP0Setup(t)
			a, c := f.activeLease(t, !manual)
			_, err := f.engine.SQL.ExecContext(f.ctx, `CREATE FUNCTION audit_p0_reject_lift() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit lift link persistence failure'; END $$;
CREATE TRIGGER audit_p0_reject_lift BEFORE UPDATE OF lift_command_id ON containments FOR EACH ROW WHEN (NEW.lift_command_id IS NOT NULL AND NEW.lift_command_id IS DISTINCT FROM OLD.lift_command_id) EXECUTE FUNCTION audit_p0_reject_lift()`)
			if err != nil {
				t.Fatal(err)
			}
			clear := func() {
				_, err := f.engine.SQL.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS audit_p0_reject_lift ON containments; DROP FUNCTION IF EXISTS audit_p0_reject_lift()`)
				if err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(clear)
			attempt := func() error {
				if manual {
					_, err := Lift(f.ctx, f.db, f.hub, c, "operator", "故障注入解除")
					return err
				}
				return f.engine.Tick(f.ctx)
			}
			if err := attempt(); err == nil {
				t.Fatal("关联写入故障没有被观察到")
			}
			clear()
			if err := attempt(); err != nil && !errors.Is(err, ErrNotLiftable) {
				t.Fatal(err)
			}
			if n := f.db.Command.Query().CountX(f.ctx); n > 2 {
				t.Errorf("解除关联写入失败后创建了新指令，含封禁共%d条", n)
			}
			n := 0
			for {
				select {
				case <-f.inbox[a.ID]:
					n++
				default:
					if n > 2 {
						t.Errorf("关联故障后重复投递，含初次封禁共%d次", n)
					}
					return
				}
			}
		})
	}
}

func TestAuditP0InitialPersistenceFailureDoesNotReplay(t *testing.T) {
	f := auditP0Setup(t)
	a := f.host("initial-persistence")
	al := f.db.Alert.Create().SetTs(f.now).SetRuleID("audit.initial.crash").SetSeverity(5).SetAssetID(a.ID).SaveX(f.ctx)
	act := action{asset: a, kind: "block_network", target: "192.0.2.80", role: "host", why: "初次处置持久化故障"}
	_, err := f.engine.SQL.ExecContext(f.ctx, `CREATE FUNCTION audit_p0_reject_initial() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit initial persistence failure'; END $$;
CREATE TRIGGER audit_p0_reject_initial BEFORE INSERT ON containments FOR EACH ROW EXECUTE FUNCTION audit_p0_reject_initial()`)
	if err != nil {
		t.Fatal(err)
	}
	clear := func() {
		_, err := f.engine.SQL.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS audit_p0_reject_initial ON containments; DROP FUNCTION IF EXISTS audit_p0_reject_initial()`)
		if err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(clear)
	if err := f.engine.decide(f.ctx, al, nil, act, f.now); err == nil {
		t.Fatal("初次记录写入故障未被观察到")
	}
	clear()
	if err := f.engine.decide(f.ctx, al, nil, act, f.now); err != nil {
		t.Fatal(err)
	}
	if n := f.db.Command.Query().CountX(f.ctx); n > 1 {
		t.Errorf("初次处置记录写入失败后创建了新指令，共%d条", n)
	}
	n := len(f.inbox[a.ID])
	if n > 1 {
		t.Errorf("初次处置记录写入失败后重复投递%d次", n)
	}
}

func TestAuditP0ConcurrentInitialReservesOneLifecycle(t *testing.T) {
	f := auditP0Setup(t)
	a := f.host("concurrent-initial")
	al := f.db.Alert.Create().SetTs(f.now).SetRuleID("audit.initial.concurrent").SetSeverity(5).SetAssetID(a.ID).SaveX(f.ctx)
	act := action{asset: a, kind: "block_network", target: "192.0.2.90", role: "host", why: "并发初次处置"}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var creates atomic.Int32
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	f.db.Containment.Use(func(next ent.Mutator) ent.Mutator {
		return hook.ContainmentFunc(func(ctx context.Context, m *ent.ContainmentMutation) (ent.Value, error) {
			if m.Op() == ent.OpCreate && creates.Add(1) == 1 {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, m)
		})
	})
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- f.engine.decide(ctx, al, nil, act, f.now) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("没有进入首次预留")
	}
	go func() { done <- f.engine.decide(ctx, al, nil, act, f.now) }()
	time.AfterFunc(150*time.Millisecond, func() { once.Do(func() { close(release) }) })
	<-done
	<-done
	if n := f.db.Containment.Query().CountX(f.ctx); n != 1 {
		t.Errorf("同一决定产生%d条独立生命周期，随后会重复解除", n)
	}
	if n := f.db.Command.Query().CountX(f.ctx); n != 1 {
		t.Errorf("同一决定下发%d条指令", n)
	}
	cmd := f.db.Command.Query().FirstX(f.ctx)
	f.receipt(t, a, cmd.ID, pb.CommandResult_SUCCEEDED, "ok")
	f.now = f.now.Add(48 * time.Hour)
	f.tick(t)
	if n := f.db.Command.Query().CountX(f.ctx); n > 2 {
		t.Errorf("重复的生命周期导致%d条指令（含封禁），解除被重复下发", n)
	}
}

func TestAuditP0StaleManualLiftCannotReplaceNewAttempt(t *testing.T) {
	f := auditP0Setup(t)
	a, c := f.activeLease(t, false)
	current, err := Lift(f.ctx, f.db, f.hub, c, "operator", "第一次解除")
	if err != nil {
		t.Fatal(err)
	}
	oldID := *current.LiftCommandID
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var held atomic.Bool
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	f.db.Containment.Use(func(next ent.Mutator) ent.Mutator {
		return hook.ContainmentFunc(func(ctx context.Context, m *ent.ContainmentMutation) (ent.Value, error) {
			id, ok := m.LiftCommandID()
			if ok && id == oldID && held.CompareAndSwap(false, true) {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, m)
		})
	})
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Lift(ctx, f.db, f.hub, current, "old-operator", "旧快照"); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("旧解除请求未进入写回")
	}
	f.receipt(t, a, oldID, pb.CommandResult_FAILED, "已确认解除执行失败")
	next, err := Lift(ctx, f.db, f.hub, current, "new-operator", "失败后新尝试")
	if err != nil {
		t.Fatal(err)
	}
	if next.LiftCommandID == nil || *next.LiftCommandID == oldID {
		t.Fatal("没有创建合法的失败后新尝试")
	}
	newID := *next.LiftCommandID
	once.Do(func() { close(release) })
	<-done
	stored := f.db.Containment.GetX(f.ctx, c.ID)
	if stored.LiftCommandID == nil || *stored.LiftCommandID != newID {
		t.Fatalf("旧快照覆盖新的解除指令关联: got=%v want=%s", stored.LiftCommandID, newID)
	}
}
