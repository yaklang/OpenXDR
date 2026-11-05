//go:build integration

package incidentwork

import (
	"encoding/json"
	"testing"
	"time"

	"openxdr/server/ent/incident"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/review"
	"openxdr/server/internal/testdb"
)

func TestGapOwnedButNeverFalsePositive(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	inc := db.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SetCreatedAt(now.Add(-48 * time.Hour)).SetTriagedAt(now).SetAiVerdict(json.RawMessage(`{"verdict":"suspicious","action_codes":["collect_original_records"]}`)).SaveX(ctx)
	if !db.Incident.Query().Where(incident.IDEQ(inc.ID), review.Needed()).ExistX(ctx) {
		t.Fatal("未接管缺证不得静默")
	}
	if err := Refresh(ctx, db, inc, now); err != nil {
		t.Fatal(err)
	}
	inc = db.Incident.GetX(ctx, inc.ID)
	if inc.Work.Owner != "ai" || inc.WorkNextCheckAt == nil {
		t.Fatal("未生成可执行计划")
	}
	if db.Incident.Query().Where(incident.IDEQ(inc.ID), review.Needed()).ExistX(ctx) {
		t.Fatal("AI低风险跟进不应占人工队列")
	}
	if db.Incident.Query().Where(incident.IDEQ(inc.ID), review.StaleBenign(now)).ExistX(ctx) {
		t.Fatal("缺证不得按误报结案")
	}
	if !db.Incident.Query().Where(Due(now.Add(7 * time.Hour))).ExistX(ctx) {
		t.Fatal("未进入到期队列")
	}
	db.Incident.UpdateOneID(inc.ID).SetEvidenceAt(now.Add(time.Minute)).ExecX(ctx)
	if db.Incident.Query().Where(Due(now.Add(7 * time.Hour))).ExistX(ctx) {
		t.Fatal("新证据不能复用旧计划")
	}
	if !db.Incident.Query().Where(incident.IDEQ(inc.ID), review.Needed()).ExistX(ctx) {
		t.Fatal("旧快照不可静默新证据")
	}
}

func TestBudgetAndStaleProposal(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	inc := db.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SetTriagedAt(now).SetAiVerdict(json.RawMessage(`{"verdict":"benign","action_codes":["collect_original_records"]}`)).SetClosureProposal(&schema.ClosureProposal{Status: "false_positive", At: now.Add(-time.Hour)}).SaveX(ctx)
	if err := Reconcile(ctx, db, now); err != nil {
		t.Fatal(err)
	}
	inc = db.Incident.GetX(ctx, inc.ID)
	if inc.ClosureProposal != nil {
		t.Fatal("过期建议未失效")
	}
	work := *inc.Work
	work.Attempts = MaxAttempts
	inc.Work = &work
	db.Incident.UpdateOneID(inc.ID).SetWork(&work).ExecX(ctx)
	if err := Refresh(ctx, db, inc, now); err != nil {
		t.Fatal(err)
	}
	inc = db.Incident.GetX(ctx, inc.ID)
	if inc.Work.Stage != "monitoring" || inc.WorkNextCheckAt != nil {
		t.Fatal("预算耗尽应转证据唤醒监测")
	}
	if db.Incident.Query().Where(incident.IDEQ(inc.ID), review.StaleBenign(now.Add(time.Hour))).ExistX(ctx) {
		t.Fatal("benign仍缺证不得结案")
	}
	// 旧清理快照不能删除并发替换的新建议。
	old := *inc
	old.ClosureProposal = &schema.ClosureProposal{Status: "false_positive", At: now.Add(-time.Hour)}
	fresh := &schema.ClosureProposal{Status: "closed", At: now.Add(time.Minute)}
	db.Incident.UpdateOneID(inc.ID).SetClosureProposal(fresh).ExecX(ctx)
	if err := clearStaleProposal(ctx, db, &old); err != nil {
		t.Fatal(err)
	}
	if db.Incident.GetX(ctx, inc.ID).ClosureProposal.Status != "closed" {
		t.Fatal("删除了新建议")
	}
}

func TestRefreshCannotOverwriteManualTerminal(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	inc := db.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SetTriagedAt(now).SetAiVerdict(json.RawMessage(`{"verdict":"suspicious","action_codes":["collect_original_records"]}`)).SaveX(ctx)
	db.Incident.UpdateOneID(inc.ID).SetStatus("closed").ExecX(ctx)
	if err := Refresh(ctx, db, inc, now); err == nil {
		t.Fatal("旧快照改写人工终态")
	}
	if db.Incident.GetX(ctx, inc.ID).Work != nil {
		t.Fatal("终态被接管")
	}
}
