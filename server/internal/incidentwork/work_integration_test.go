//go:build integration

package incidentwork

import (
	"database/sql"
	"encoding/json"
	"github.com/google/uuid"
	"os"
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

func TestLegacyProposalJSONWithoutNewMetadataExpires(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	inc := db.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SetTriagedAt(now).SetAiVerdict(json.RawMessage(`{"verdict":"benign","action_codes":["monitor"]}`)).SaveX(ctx)
	// 真实旧版本只存这四项；通过原始 SQL 写入，避免当前结构体序列化补上新增的零 UUID。
	raw, err := json.Marshal(map[string]any{"at": now.Add(-time.Hour), "status": "false_positive", "note": "旧版本建议", "sessionId": uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "UPDATE incidents SET closure_proposal=$1::jsonb WHERE id=$2", string(raw), inc.ID); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(ctx, db, now); err != nil {
		t.Fatal(err)
	}
	got := db.Incident.GetX(ctx, inc.ID)
	if got.ClosureProposal != nil {
		t.Fatal("真实旧 JSON 的过期建议未清理")
	}
	if got.Status != "triaged" {
		t.Fatal("清理建议改变了事件结论")
	}
}
