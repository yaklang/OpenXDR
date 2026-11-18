//go:build integration

package questions

import (
	"encoding/json"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/testdb"
)

// 卡在只有人能解的机器阻塞、又没挂问题的待办：清扫时提问并记下编号；作答后交回平台，仍卡在原处也不重复提问
func TestBlockedSweepAsksOncePerFinding(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	host := db.Asset.Create().SetHostname("k3s-master-1").SetGroupID(g.ID).SaveX(ctx)
	now := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(key, blocker, question string) *ent.Finding {
		return db.Finding.Create().SetGroupID(g.ID).SetAssetID(host.ID).SetKey(key).SetTitle("待重启生效 " + key).
			SetWork(findings.EncodeWork(findings.Work{Stage: "blocked", Blocker: blocker, BlockerDetail: "不属于封闭修复模板", Question: question})).SaveX(ctx)
	}
	unsupported := mk("reboot", "action_unsupported", "")
	grant := mk("port", "policy_required", "")
	mk("cooldown", "cooldown", "")
	mk("asked", "action_unsupported", "Q-existing")
	work := func(f *ent.Finding) findings.Work {
		var w findings.Work
		_ = json.Unmarshal(db.Finding.GetX(ctx, f.ID).Work, &w)
		return w
	}

	if n, err := BlockedSweep(ctx, db, now); err != nil || n != 2 {
		t.Fatal("只问没挂问题、只有人能解的两条", n, err)
	}
	qs := db.Question.Query().AllX(ctx)
	if len(qs) != 2 {
		t.Fatal("每条待办一个问题", len(qs))
	}
	for _, q := range qs {
		want := map[string]string{"policy": unsupported.ID.String(), "authorization": grant.ID.String()}[q.Kind]
		if q.SubjectKind != "change" || q.Subject != ChangeSubject(host.ID, "finding-"+want) || len(q.FindingIds) != 1 || q.FindingIds[0].String() != want {
			t.Fatalf("问题主题应是主机加待办编号：%+v", q)
		}
	}
	w := work(unsupported)
	if w.Question == "" || w.Stage != "blocked" {
		t.Fatalf("问题编号应写进待办：%+v", w)
	}
	if n, err := BlockedSweep(ctx, db, now); err != nil || n != 0 {
		t.Fatal("已挂问题的不重复问", n, err)
	}

	for _, q := range qs {
		in := AnswerInput{Choice: "decision", Content: "维护窗口内由人重启"}
		if q.Kind == "authorization" {
			in = AnswerInput{Choice: "grant", Content: "允许收紧管理端口", ExpiresInDays: 7}
		}
		if _, err := answer(t, ctx, db, q.ID, in); err != nil {
			t.Fatal(q.Kind, err)
		}
	}
	// 作答后待办交回平台；子代理评估后仍卡在原处，答案已在计划里，不再重复提问
	for _, x := range []*ent.Finding{unsupported, grant} {
		cur := db.Finding.GetX(ctx, x.ID)
		var w findings.Work
		_ = json.Unmarshal(cur.Work, &w)
		if w.Question != "" || w.Stage == "blocked" {
			t.Fatalf("作答后应交回平台：%+v", w)
		}
		w.Stage, w.Blocker = "blocked", map[bool]string{true: "action_unsupported", false: "policy_required"}[x.ID == unsupported.ID]
		db.Finding.UpdateOneID(x.ID).SetWork(findings.EncodeWork(w)).ExecX(ctx)
	}
	if n, err := BlockedSweep(ctx, db, now); err != nil || n != 0 || db.Question.Query().CountX(ctx) != 2 {
		t.Fatal("答过的不再重复提问", n, err)
	}
}
