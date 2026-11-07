//go:build integration

package findings

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/testdb"
)

func TestDecisionIdempotencyScopeAndRevocation(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("target").SetGroupID(g.ID).SaveX(ctx)
	other := db.Asset.Create().SetHostname("other").SetGroupID(g.ID).SaveX(ctx)
	u := db.User.Create().SetUsername("admin").SetRole("admin").SetPasswordHash("x").SaveX(ctx)
	w := EncodeWork(Work{Version: 3, Stage: "blocked", Blocker: "legacy_decommission_confirm", RepairAttempts: 2, OriginalProblem: "旧问题"})
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("retire").SetTitle("退役").SetWork(w).SaveX(ctx)
	at := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	request := uuid.New()
	d, created, err := Delegate(ctx, db, f.ID, u, request, "只退役此旧服务，保留新服务和数据", "m", "local", at)
	if err != nil || !created {
		t.Fatal(d, created, err)
	}
	if f2 := db.Finding.GetX(ctx, f.ID); string(encodeWorkFromTest(t, f2.Work)) != string(w) || f2.WorkOwner != "ai" {
		t.Fatal("决定不能重置待办预算和原问题", f2)
	}
	got, created, err := Delegate(ctx, db, f.ID, u, request, d.Instruction, "m", "local", at)
	if err != nil || created || got.SessionID != d.SessionID {
		t.Fatal("重复请求重建了执行", got, created, err)
	}
	if n := db.AuditLog.Query().Where(auditlog.ActionEQ("finding_execution_decided")).CountX(ctx); n != 1 {
		t.Fatal(n)
	}
	s := db.AgentSession.GetX(ctx, d.SessionID)
	if err = GuardDecisionWrite(ctx, db, s, a.ID, request); err != nil {
		t.Fatal(err)
	}
	if err = GuardDecisionWrite(ctx, db, s, other.ID, request); err == nil {
		t.Fatal("跨资产写入获准")
	}
	cmd := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("touch /tmp/pending").SetStatus("unknown").SaveX(ctx)
	if err = GuardDecisionWrite(ctx, db, s, a.ID, request); err == nil {
		t.Fatal("未知写动作被重放")
	}
	cmd.Update().SetStatus("succeeded").ExecX(ctx)
	f.Update().SetWorkOwner("human").ExecX(ctx)
	if err = GuardDecisionWrite(ctx, db, s, a.ID, request); err == nil {
		t.Fatal("管理员决定绕过人工持有")
	}
	f.Update().SetWorkOwner("ai").ExecX(ctx)
	if err = RevokeDecision(ctx, db, f.ID, u.Username, "local"); err != nil {
		t.Fatal(err)
	}
	if _, err = DecisionForSession(ctx, db, s); err == nil {
		t.Fatal("撤销后旧会话仍有效")
	}
	// 新决定替代旧决定后，重试旧 requestId 仍返回旧句柄而不是重放。
	d2, created, err := Delegate(ctx, db, f.ID, u, uuid.New(), "只读重新核查", "m", "local", at)
	if err != nil || !created {
		t.Fatal(err)
	}
	got, created, err = Delegate(ctx, db, f.ID, u, request, d.Instruction, "m", "local", at)
	if err != nil || created || got.SessionID != s.ID {
		t.Fatal("历史请求不幂等", got, err)
	}
	if _, err = DecisionForSession(ctx, db, s); err == nil {
		t.Fatal("旧会话变成了普通对话")
	}
	s2 := db.AgentSession.GetX(ctx, d2.SessionID)
	u.Update().SetRole("viewer").ExecX(ctx)
	if _, err = DecisionForSession(ctx, db, s2); err == nil {
		t.Fatal("管理员失权后决定仍有效")
	}
}

func encodeWorkFromTest(t *testing.T, b json.RawMessage) json.RawMessage {
	t.Helper()
	var w Work
	if err := json.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	return EncodeWork(w)
}

func TestDecisionRejectsChangedScopeAndExpiry(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	a := db.Asset.Create().SetHostname("target").SetGroupID(g.ID).SaveX(ctx)
	u := db.User.Create().SetUsername("admin").SetRole("admin").SetPasswordHash("x").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("a").SetTitle("a").SaveX(ctx)
	d, _, err := Delegate(ctx, db, f.ID, u, uuid.New(), "精确范围", "m", "local", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s := db.AgentSession.GetX(ctx, d.SessionID)
	a.Update().SetGroupID(other.ID).ExecX(ctx)
	if _, err = DecisionForSession(ctx, db, s); err == nil {
		t.Fatal("资产转组后未失效")
	}
	a.Update().SetGroupID(g.ID).ExecX(ctx)
	d.ExpiresAt = time.Now().Add(-time.Second)
	b, _ := json.Marshal(d)
	db.Setting.UpdateOneID(decisionKey(f.ID)).SetValue(b).ExecX(ctx)
	if _, err = DecisionForSession(ctx, db, s); err == nil {
		t.Fatal("到期决定未失效")
	}
	if _, _, err = Delegate(ctx, db, f.ID, u, uuid.New(), "范围", "m", "local", time.Now().Add(31*24*time.Hour)); err == nil {
		t.Fatal("无限授权被接受")
	}
}
