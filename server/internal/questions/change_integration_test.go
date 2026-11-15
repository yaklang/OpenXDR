//go:build integration

package questions

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/question"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/testdb"
)

// 同一资产上的两项变更：批准一项不能自动批准另一项；同一项变更重复提问由写回的事实直接答复
func TestChangeAuthorizationIsPerChange(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	pve1 := db.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SaveX(ctx)
	db.Fact.Create().SetKind("asset_role").SetAssetID(pve1.ID).SetGroupID(g.ID).SetContent("PVE 宿主机").SetCreatedBy("admin").ExecX(ctx)
	now := time.Now()
	ask := func(key string) *Result {
		t.Helper()
		res, err := Ask(ctx, db, Request{Kind: "authorization", SubjectKind: "change", Subject: ChangeSubject(pve1.ID, key), Groups: []uuid.UUID{g.ID}, Source: "ask_controller"}, now)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if _, err := Ask(ctx, db, Request{Kind: "authorization", SubjectKind: "change", Subject: pve1.ID.String(), Groups: []uuid.UUID{g.ID}}, now); !errors.As(err, new(ErrInvalid)) {
		t.Fatalf("变更问题必须带变更标识：%v", err)
	}
	retire := ask("retire-cyberedge-agent")
	dropin := ask("gateway-systemd-dropin")
	if retire.Answered || dropin.Answered || retire.Question.ID == dropin.Question.ID {
		t.Fatal("同资产的两项变更是两个问题，资产角色不能代答")
	}
	if len(retire.Context) == 0 || retire.Context[0].Kind != "asset_role" {
		t.Fatalf("资产角色作为背景附上：%+v", retire.Context)
	}
	out, err := answer(t, ctx, db, retire.Question.ID, AnswerInput{Choice: "grant", Content: "退役 cyberedge-agent"})
	if err != nil || out.Fact.Subject != "authorization:change:"+ChangeSubject(pve1.ID, "retire-cyberedge-agent") || !strings.Contains(out.Fact.Content, "仅这一项变更") {
		t.Fatalf("写回的事实只属于这一项变更：%v %+v", err, out)
	}
	if ask("gateway-systemd-dropin").Answered {
		t.Fatal("批准退役不能自动批准 drop-in")
	}
	if n, a, err := BackfillSweep(ctx, db, now); err != nil || n != 0 || a < 0 {
		t.Fatalf("后台收敛也不能代答另一项变更：%d %v", n, err)
	}
	if db.Question.GetX(ctx, dropin.Question.ID).Status != "open" {
		t.Fatal("drop-in 仍待答")
	}
	again := ask("retire-cyberedge-agent")
	if !again.Answered || len(again.Facts) != 1 || again.Facts[0].ID != out.Fact.ID {
		t.Fatalf("同一项变更重复提问由事实直接答复：%+v", again)
	}
	// 主机级授权问题也不被具体变更的批准代答
	if res, _ := Ask(ctx, db, Request{Kind: "authorization", SubjectKind: "asset", Subject: pve1.ID.String(), Groups: []uuid.UUID{g.ID}}, now); res.Answered {
		t.Fatal("一项变更的批准不是整台主机的授权")
	}
}

// 存量：变更问题被 auto_lookup 拿别的问题写回的事实答掉的，启动扫描置回待答、补变更标识、待办重新挂回阻塞、留审计；
// 自己的、人工答的不动；再跑一次不重复处理
func TestReopenCrossChangeAnswers(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	pve1 := db.Asset.Create().SetHostname("pve1").SetGroupID(g.ID).SaveX(ctx)
	now := time.Now()
	// 存量问题：主题是裸资产 UUID
	legacy := func() uuid.UUID {
		return db.Question.Create().SetKind("authorization").SetSubjectKind("change").SetSubject(pve1.ID.String()).SetStatus("answered").
			SetGroupIds([]uuid.UUID{g.ID}).SetCreatedBy("session:x").SaveX(ctx).ID
	}
	// 人工答的 cyberedge（自己写回的事实）
	human := legacy()
	cyber := db.Fact.Create().SetKind("change").SetSubject("authorization:change:" + pve1.ID.String()).SetAssetID(pve1.ID).SetGroupID(g.ID).
		SetContent("授权：退役 cyberedge-agent（总控问题 " + Ref(human) + "）").SetCreatedBy("admin").SetExpiresAt(now.AddDate(0, 0, 30)).SaveX(ctx)
	db.Question.UpdateOneID(human).SetAnswer(&schema.QuestionAnswer{Choice: "grant"}).SetFactID(cyber.ID).SetAnsweredBy("admin").SetAnsweredAt(now).ExecX(ctx)
	// 被 auto_lookup 拿 cyberedge 的事实答掉的 drop-in
	wrong := legacy()
	db.Question.UpdateOneID(wrong).SetAnswer(&schema.QuestionAnswer{Choice: "auto_lookup"}).SetFactID(cyber.ID).SetAnsweredBy("system").SetAnsweredAt(now).ExecX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(pve1.ID).SetKey("dropin").SetTitle("gateway drop-in").SetWorkOwner("ai").
		SetWork(findings.EncodeWork(findings.Work{Stage: "waiting", LastWakeReason: "总控问题 " + Ref(wrong) + " 已答"})).SaveX(ctx)
	db.Question.UpdateOneID(wrong).SetFindingIds([]uuid.UUID{f.ID}).ExecX(ctx)
	// 一条存量裸 UUID 的待答变更问题：只补标识
	open := db.Question.Create().SetKind("permission").SetSubjectKind("change").SetSubject(pve1.ID.String()).SetCreatedBy("session:y").SaveX(ctx)

	n, err := ReopenCrossChangeAnswers(ctx, db, now)
	if err != nil || n != 1 {
		t.Fatalf("只置回跨问题自动作答的那一条：%d %v", n, err)
	}
	q := db.Question.GetX(ctx, wrong)
	if q.Status != "open" || q.Answer != nil || q.FactID != nil || !strings.HasPrefix(q.Subject, pve1.ID.String()+"/legacy-") {
		t.Fatalf("置回待答并补上自己的变更标识：%+v", q)
	}
	if !db.AuditLog.Query().Where(auditlog.ActionEQ("question_reopened"), auditlog.TargetEQ(wrong.String())).ExistX(ctx) {
		t.Fatal("要留审计")
	}
	var w findings.Work
	_ = json.Unmarshal(db.Finding.GetX(ctx, f.ID).Work, &w)
	if w.Blocker != "manual_business_decision" || w.Question != Ref(wrong) {
		t.Fatalf("关联待办重新挂回阻塞：%+v", w)
	}
	if h := db.Question.GetX(ctx, human); h.Status != "answered" || h.FactID == nil || h.Subject != pve1.ID.String() {
		t.Fatal("人工答的不动")
	}
	if o := db.Question.GetX(ctx, open.ID); o.Status != "open" || !strings.HasPrefix(o.Subject, pve1.ID.String()+"/legacy-") {
		t.Fatalf("存量待答变更问题补标识：%+v", o)
	}
	if n, err := ReopenCrossChangeAnswers(ctx, db, now); err != nil || n != 0 {
		t.Fatalf("幂等：%d %v", n, err)
	}
	// 置回的问题照常人工作答，写回的事实只属于它
	out, err := answer(t, ctx, db, wrong, AnswerInput{Choice: "grant", Content: "gateway drop-in"})
	if err != nil || out.Fact.Subject != "authorization:change:"+q.Subject {
		t.Fatalf("作答写回带自己的标识：%v %+v", err, out)
	}
	if n := db.Question.Query().Where(question.StatusEQ("open")).CountX(ctx); n != 1 {
		t.Fatalf("只剩存量 permission 问题待答：%d", n)
	}
}
