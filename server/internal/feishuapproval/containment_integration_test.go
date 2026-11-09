//go:build integration

package feishuapproval

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	entcontainment "openxdr/server/ent/containment"
)

type fakeDecider struct {
	approved chan uuid.UUID
	declined []uuid.UUID
	db       *ent.Client
}

func (f *fakeDecider) Approve(ctx context.Context, c *ent.Containment, actor string) (*ent.Containment, error) {
	f.approved <- c.ID
	return c, nil
}

func (f *fakeDecider) Decline(ctx context.Context, c *ent.Containment, actor, reason string) (*ent.Containment, error) {
	f.declined = append(f.declined, c.ID)
	return f.db.Containment.UpdateOne(c).SetState(entcontainment.StateDeclined).SetDecidedBy(actor).Save(ctx)
}

func proposed(t *testing.T, f fixture) *ent.Containment {
	return f.s.DB.Containment.Create().SetAssetID(f.asset.ID).SetGroupID(f.group).SetKind("block_network").SetTarget("203.0.113.7").
		SetKey(uuid.NewString()).SetSignal("ai:verdict").SetAlertID(uuid.New()).SetRole(entcontainment.RoleHost).
		SetState(entcontainment.StateProposed).SetReason("事件「测试」研判为可疑（置信度 75），封锁涉事外部地址 203.0.113.7").
		SetExpiresAt(time.Now().Add(time.Hour)).SaveX(f.ctx)
}

func deliveredContainment(t *testing.T, f fixture, c *ent.Containment, u *ent.User, message string) string {
	if err := f.s.enqueue(f.ctx, f.c); err != nil {
		t.Fatal(err)
	}
	var nonce string
	if err := f.s.SQL.QueryRowContext(f.ctx, `UPDATE feishu_approval_deliveries SET message_id=$3 WHERE containment_id=$1 AND user_id=$2 RETURNING nonce`,
		c.ID, u.ID, message).Scan(&nonce); err != nil {
		t.Fatal("没有投递给组管理员：", err)
	}
	return nonce
}

// 待审批处置发卡片给组管理员；驳回当场生效，批准交给处置引擎，同一张卡片不能点第二次
func TestContainmentCards(t *testing.T) {
	f := setup(t)
	fake := &fakeDecider{approved: make(chan uuid.UUID, 1), db: f.s.DB}
	f.s.Containment = fake
	bindUser(t, f, f.u, "open-1")
	viewer := f.s.DB.User.Create().SetUsername("viewer").SetRole("viewer").SetPasswordHash("unused").SaveX(f.ctx)
	bindUser(t, f, viewer, "open-2")

	reject := proposed(t, f)
	nonce := deliveredContainment(t, f, reject, f.u, "message-1")
	var others int
	_ = f.s.SQL.QueryRowContext(f.ctx, `SELECT count(*) FROM feishu_approval_deliveries WHERE user_id=$1`, viewer.ID).Scan(&others)
	if others != 0 {
		t.Fatal("非组管理员不该收到处置卡片")
	}
	card := f.s.containmentCard(f.ctx, delivery{Nonce: nonce}, reject)
	if card["header"].(map[string]any)["title"].(map[string]any)["content"] != "OpenXDR 处置待审批" {
		t.Fatalf("卡片标题不对：%v", card)
	}
	if _, err := f.s.decide(f.ctx, f.c, "tenant", "open-1", "message-1", nonce, "reject"); err != nil {
		t.Fatal(err)
	}
	if len(fake.declined) != 1 || fake.declined[0] != reject.ID {
		t.Fatalf("应驳回：%v", fake.declined)
	}
	if _, err := f.s.decide(f.ctx, f.c, "tenant", "open-1", "message-1", nonce, "approve"); err == nil {
		t.Fatal("同一张卡片不能再点")
	}

	approve := proposed(t, f)
	nonce = deliveredContainment(t, f, approve, f.u, "message-2")
	if _, err := f.s.decide(f.ctx, f.c, "tenant", "open-1", "message-2", nonce, "test"); err == nil {
		t.Fatal("处置卡片不接受连接测试操作")
	}
	if _, err := f.s.decide(f.ctx, f.c, "tenant", "open-1", "message-2", nonce, "approve"); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-fake.approved:
		if id != approve.ID {
			t.Fatalf("批准了别的处置：%v", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("批准没有交给处置引擎")
	}

	stale := proposed(t, f)
	nonce = deliveredContainment(t, f, stale, f.u, "message-3")
	f.s.DB.Containment.UpdateOne(stale).SetState(entcontainment.StateDeclined).ExecX(f.ctx)
	if _, err := f.s.decide(f.ctx, f.c, "tenant", "open-1", "message-3", nonce, "approve"); err == nil {
		t.Fatal("已在平台处理过的处置不能再从卡片批准")
	}
}
