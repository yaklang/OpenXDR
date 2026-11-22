//go:build integration

package containment

import (
	"testing"
	"time"

	"github.com/google/uuid"

	entcontainment "openxdr/server/ent/containment"
)

// 主机隔离期间离线很久、解除失败了上千次：回来后仍要接着最近一条失败的指令派生新指令下发，不能卡在链长上限
func TestExpiryLiftAfterLongFailedChain(t *testing.T) {
	f := setup(t)
	host := f.host(t, "laptop", "10.9.0.5", nil, "")
	expired := f.now.Add(-time.Minute)
	c := f.client.Containment.Create().SetAssetID(host.ID).SetKind("block_network").SetTarget("198.51.100.7").
		SetKey(host.ID.String() + "|block_network|198.51.100.7").SetSignal("rule.test").SetAlertID(uuid.New()).
		SetRole(entcontainment.RoleVictim).SetState(entcontainment.StateActive).SetExpiresAt(expired).SetReason("测试").
		SetCreatedAt(f.now.Add(-100 * time.Hour)).SaveX(f.ctx)

	prev := uuid.Nil
	for i := range 1100 {
		id := liftCommandID(c.ID, prev)
		f.client.Command.Create().SetID(id).SetKind("unblock_network").SetTarget("198.51.100.7").SetAssetID(host.ID).
			SetStatus("failed").SetCreatedAt(c.CreatedAt.Add(time.Duration(i) * 5 * time.Minute)).ExecX(f.ctx)
		prev = id
	}

	if err := f.engine("all").expire(f.ctx); err != nil {
		t.Fatal(err)
	}
	got := f.received("laptop")
	if len(got) != 1 || got[0].Id != liftCommandID(c.ID, prev).String() {
		t.Fatalf("应接着最后一条失败指令下发新的解除指令，收到 %v", got)
	}
	if s := f.client.Containment.GetX(f.ctx, c.ID).State; s != entcontainment.StateExpired {
		t.Fatalf("解除成功后应转 expired，实际 %s", s)
	}
}

// SSO 停用结果没写回、停在 pending 的处置：超过时限转 executed，之后能经 LiftSSO 恢复
func TestStaleSSOPendingSettles(t *testing.T) {
	f := setup(t)
	host := f.host(t, "idp", "10.9.0.6", nil, "")
	mk := func(age time.Duration) uuid.UUID {
		return f.client.Containment.Create().SetAssetID(host.ID).SetKind(KindSSO).SetTarget("alice").
			SetKey(uuid.NewString()).SetSignal("rule.test").SetAlertID(uuid.New()).SetRole(entcontainment.RoleSource).
			SetState(entcontainment.StatePending).SetReason("测试").SetCreatedAt(f.now.Add(-age)).SaveX(f.ctx).ID
	}
	stale, fresh := mk(10*time.Minute), mk(time.Minute)
	if err := f.engine("all").settleStaleSSO(f.ctx); err != nil {
		t.Fatal(err)
	}
	if s := f.client.Containment.GetX(f.ctx, stale).State; s != entcontainment.StateExecuted {
		t.Fatalf("超时的 pending 应转 executed，实际 %s", s)
	}
	if s := f.client.Containment.GetX(f.ctx, fresh).State; s != entcontainment.StatePending {
		t.Fatalf("刚建的 pending 不该动，实际 %s", s)
	}
}
