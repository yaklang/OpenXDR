//go:build integration

package containment

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/ent/hook"
)

// 解除下发在建单前因调用方取消而失败：回查与回滚不跟着取消，预留的解除指令 ID 要撤掉
func TestLiftCanceledBeforeCreateRollsBack(t *testing.T) {
	f := auditP0Setup(t)
	_, c := f.activeLease(t, false)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	f.db.Command.Use(func(next ent.Mutator) ent.Mutator {
		return hook.CommandFunc(func(hctx context.Context, m *ent.CommandMutation) (ent.Value, error) {
			if kind, _ := m.Kind(); m.Op() == ent.OpCreate && kind == "unblock_network" {
				cancel()
				return nil, context.Canceled
			}
			return next.Mutate(hctx, m)
		})
	})
	if _, err := Lift(ctx, f.db, f.hub, c, "operator", "取消"); err == nil {
		t.Fatal("建单前取消应返回错误")
	}
	c = f.db.Containment.GetX(f.ctx, c.ID)
	if c.LiftCommandID != nil || c.LiftedBy != nil {
		t.Fatalf("建单失败后应撤掉预留：lift=%v by=%v", c.LiftCommandID, c.LiftedBy)
	}
}

// 预留了解除指令 ID 却没建成单（进程在建单前中断）：到期解除与人工解除都接着用同一个 ID 下发，不卡死、不假成功
func TestOrphanLiftReservationIsReissued(t *testing.T) {
	for _, manual := range []bool{false, true} {
		t.Run(map[bool]string{false: "expiry", true: "manual"}[manual], func(t *testing.T) {
			f := auditP0Setup(t)
			a, c := f.activeLease(t, !manual)
			orphan := liftCommandID(c.ID, uuid.Nil)
			upd := f.db.Containment.UpdateOneID(c.ID).SetLiftCommandID(orphan)
			if manual {
				upd.SetLiftedBy("someone")
			}
			c = upd.SaveX(f.ctx)
			for len(f.inbox[a.ID]) > 0 {
				<-f.inbox[a.ID]
			}
			if manual {
				if _, err := Lift(f.ctx, f.db, f.hub, c, "operator", "重新解除"); err != nil {
					t.Fatal(err)
				}
			} else {
				f.tick(t)
			}
			cmd, err := f.db.Command.Get(f.ctx, orphan)
			if err != nil || cmd.Kind != "unblock_network" {
				t.Fatalf("应按预留的 ID 补建解除指令：%v %v", cmd, err)
			}
			if len(f.inbox[a.ID]) != 1 {
				t.Fatalf("解除指令应投递一次，实际 %d", len(f.inbox[a.ID]))
			}
			if got := f.db.Containment.GetX(f.ctx, c.ID); got.LiftCommandID == nil || *got.LiftCommandID != orphan {
				t.Fatalf("记录应仍指向同一条解除指令：%v", got.LiftCommandID)
			}
		})
	}
}

// 同键已有多条在途记录（历史并发留下的）：decide 逐条续期，不因 NotSingular 让整轮中止
func TestDecideToleratesDuplicateInFlight(t *testing.T) {
	f := auditP0Setup(t)
	_, c := f.activeLease(t, false)
	dup := f.db.Containment.Create().SetAssetID(c.AssetID).SetNillableGroupID(c.GroupID).SetKind(c.Kind).SetTarget(c.Target).SetKey(c.Key).
		SetSignal(c.Signal).SetAlertID(uuid.New()).SetRole(c.Role).SetState(entcontainment.StateActive).SetReason("并发留下的重复").
		SetExpiresAt(f.now.Add(time.Hour)).SaveX(f.ctx)
	a := f.db.Asset.GetX(f.ctx, c.AssetID)
	al := f.db.Alert.Create().SetTs(f.now).SetRuleID("audit.lifecycle").SetSeverity(5).SetAssetID(a.ID).SaveX(f.ctx)
	act := action{asset: a, kind: c.Kind, target: c.Target, role: "host", why: "新证据"}
	last := f.now.Add(2 * time.Hour).Truncate(time.Microsecond)
	if err := f.engine.decide(f.ctx, al, nil, act, last); err != nil {
		t.Fatalf("同键多条在途不应报错：%v", err)
	}
	for _, id := range []uuid.UUID{c.ID, dup.ID} {
		if got := f.db.Containment.GetX(f.ctx, id); got.ExpiresAt == nil || !got.ExpiresAt.Equal(last.Add(f.engine.TTL)) {
			t.Errorf("在途记录 %s 应续期到 %v，实际 %v", id, last.Add(f.engine.TTL), got.ExpiresAt)
		}
	}
	if n := f.db.Containment.Query().Where(entcontainment.KeyEQ(c.Key)).CountX(f.ctx); n != 2 {
		t.Errorf("不应新建记录，同键共 %d 条", n)
	}
}

// decide 锁外查过之后，同键另一条刚被推成 pending（如 API 批准待审批处置）：锁内再查，不建重复记录
func TestDecideRechecksInFlightUnderFuseLock(t *testing.T) {
	f := auditP0Setup(t)
	a := f.host("race-endpoint")
	al := f.db.Alert.Create().SetTs(f.now).SetRuleID("audit.lifecycle").SetSeverity(5).SetAssetID(a.ID).SaveX(f.ctx)
	act := action{asset: a, kind: "block_network", target: "192.0.2.91", role: "host", why: "竞争"}
	f.engine.fuseMu.Lock()
	done := make(chan error, 1)
	go func() { done <- f.engine.decide(f.ctx, al, nil, act, f.now) }()
	time.Sleep(300 * time.Millisecond) // decide 已过锁外检查、等在熔断锁上
	f.db.Containment.Create().SetAssetID(a.ID).SetGroupID(f.group).SetKind(act.kind).SetTarget(act.target).SetKey(act.key()).
		SetSignal(SignalVerdict).SetAlertID(uuid.New()).SetRole(entcontainment.RoleHost).SetState(entcontainment.StatePending).
		SetReason("刚批准").SaveX(f.ctx)
	f.engine.fuseMu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := f.db.Containment.Query().Where(entcontainment.KeyEQ(act.key())).CountX(f.ctx); n != 1 {
		t.Fatalf("锁内应发现同键在途记录而不新建，同键共 %d 条", n)
	}
}
