//go:build integration

package agentchat

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/findings"
	"openxdr/server/internal/questions"
	"openxdr/server/internal/testdb"
)

const askFP = "SHA256:mtwVQQEIr75wGTFfVAuMn6y/LsfD5ULsqChRXqfXqJY"

// 待办不能直接把自己标成需业务决定：先问总控，排进待答问题才能标；管理员作答后待办解除阻塞重新排队，再问由事实直接答
func TestManualDecisionGoesThroughController(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	a := db.Asset.Create().SetHostname("uos").SetGroupID(g.ID).SaveX(ctx)
	foreign := db.Asset.Create().SetHostname("far").SetGroupID(other.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("chat").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("unknown-key").SetTitle("root 下有未登记公钥").SaveX(ctx)
	now := time.Now()
	c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("cat /root/.ssh/authorized_keys").SetStatus("succeeded").SetExitCode(0).
		SetStdout("256 " + askFP + " kei@foghaven (ED25519)").SetCompletedAt(now).SaveX(ctx)
	db.Command.UpdateOneID(c.ID).SetCreatedAt(session.CreatedAt).ExecX(ctx)
	svc := &Service{DB: db}

	err := svc.saveFindingPlan(ctx, session, f, "等管理员确认钥匙归属", "manual_business_decision", []uuid.UUID{c.ID})
	if err == nil || !strings.Contains(err.Error(), "ask_controller") {
		t.Fatalf("没提问不能标需人工：%v", err)
	}
	args := func(v map[string]any) json.RawMessage { b, _ := json.Marshal(v); return b }
	if _, err := svc.ask(ctx, session, args(map[string]any{"type": "owner", "subject": map[string]any{"kind": "asset", "value": foreign.ID.String()}, "question": "谁的？"})); err == nil {
		t.Fatal("别组主机不能提问")
	}
	if _, err := svc.ask(ctx, session, args(map[string]any{"type": "owner", "subject": map[string]any{"kind": "rule", "value": uuid.NewString()}, "question": "?"})); err == nil {
		t.Fatal("模型不能就规矩或事实提问")
	}
	out, err := svc.ask(ctx, session, args(map[string]any{"type": "owner", "subject": map[string]any{"kind": "key", "value": askFP}, "question": "注释 kei@foghaven 的钥匙是谁的", "finding_id": f.ID.String()}))
	if err != nil || !strings.Contains(out, `"status":"queued"`) {
		t.Fatalf("答不了应排队：%v %s", err, out)
	}
	if err := svc.saveFindingPlan(ctx, session, f, "等管理员确认钥匙归属", "manual_business_decision", []uuid.UUID{c.ID}); err != nil {
		t.Fatal(err)
	}
	got := db.Finding.GetX(ctx, f.ID)
	var w findings.Work
	_ = json.Unmarshal(got.Work, &w)
	q := db.Question.Query().OnlyX(ctx)
	if w.Blocker != "manual_business_decision" || w.Question != questions.Ref(q.ID) {
		t.Fatalf("阻塞要记下问题编号：%+v", w)
	}

	txn, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := questions.Answer(ctx, txn, q.ID, questions.AnswerInput{Choice: "claim", Holder: "user:zachary", Content: "管理员工作机运维钥匙"}, "admin", "", time.Now()); err != nil {
		_ = txn.Rollback()
		t.Fatal(err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatal(err)
	}
	got = db.Finding.GetX(ctx, f.ID)
	w = findings.Work{}
	_ = json.Unmarshal(got.Work, &w)
	if w.Blocker != "" || got.WorkOwner != "ai" || got.WorkNextCheckAt.After(time.Now()) {
		t.Fatalf("作答后解除阻塞重新排队：%+v", w)
	}
	out, err = svc.ask(ctx, session, args(map[string]any{"type": "owner", "subject": map[string]any{"kind": "key", "value": askFP}, "question": "又见到这把钥匙", "finding_id": f.ID.String()}))
	if err != nil || !strings.Contains(out, `"status":"answered"`) || !strings.Contains(out, "user:zachary") {
		t.Fatalf("同类问题由事实直接答：%v %s", err, out)
	}
	if err := svc.saveFindingPlan(ctx, db.AgentSession.GetX(ctx, session.ID), got, "再等人", "manual_business_decision", []uuid.UUID{c.ID}); err == nil {
		t.Fatal("总控答得出就不能再标需人工")
	}
}
