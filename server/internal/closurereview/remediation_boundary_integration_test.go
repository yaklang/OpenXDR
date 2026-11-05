//go:build integration

package closurereview

import (
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/response"
)

// 杀进程的正面效果证明只能覆盖该目标，不证明持久化、凭据或服务整体恢复。
// 即使事件没有并入新告警、报告声称已恢复，也不能把 closed 提案当作可自动批准的事实。
func TestEffectiveProcessExitDoesNotProveIncidentRecovered(t *testing.T) {
	f := setup(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = response.EnsureVerificationSchema(f.ctx, db); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	guid := uuid.New()
	cmd := f.db.Command.Create().SetAssetID(f.asset.ID).SetIncidentID(f.inc.ID).SetKind("kill_process").SetStatus("succeeded").SetPid(42).SetProcessGUID(guid).SetCreatedAt(now.Add(-30 * time.Second)).SetCompletedAt(now.Add(-20 * time.Second)).SaveX(f.ctx)
	exit := f.db.Event.Create().SetTs(now.Add(-10 * time.Second)).SetSource("agent").SetClassUID(1007).SetAssetID(f.asset.ID).SetProcessGUID(guid).SetRaw(json.RawMessage(`{"activity_id":2,"process":{"pid":42}}`)).SaveX(f.ctx)
	verification, err := response.RecordMachineVerification(f.ctx, db, response.MachineVerificationInput{CommandID: cmd.ID, GroupID: f.group.ID, Source: "system", Component: "closure-boundary-test", Method: "telemetry_post_action", Outcome: "effective", Expected: "目标进程退出", Observed: "同资产相同GUID和PID的agent退出事件", EventIDs: []uuid.UUID{exit.ID}})
	if err != nil || verification.Outcome != "effective" || len(verification.Evidence) != 1 || verification.Evidence[0].ID != exit.ID {
		t.Fatalf("夹具必须具有真实机器效果验证：%+v %v", verification, err)
	}
	p := *f.proposal
	p.Status = "closed"
	p.Note = "目标进程已结束且未新增告警，报告认为事件已完全恢复"
	f.db.Incident.UpdateOneID(f.inc.ID).SetClosureProposal(&p).ExecX(f.ctx)
	f.db.Report.UpdateOneID(f.report.ID).SetMarkdown("已结束目标进程；之后未新增告警，因此建议视为全部恢复").ExecX(f.ctx)
	ok, err := f.r.Review(f.ctx, f.inc.ID)
	if ok || err != nil || f.calls != 0 {
		t.Fatalf("目标退出不能自动结案或提交模型：ok=%v err=%v calls=%d", ok, err, f.calls)
	}
	inc := f.db.Incident.GetX(f.ctx, f.inc.ID)
	if inc.Status != "triaged" || inc.ResolvedAt != nil || inc.ResolutionSource != nil {
		t.Fatal("不得伪造整体恢复或结案来源", inc)
	}
	if n := f.db.AuditLog.Query().Where(auditlog.ActionEQ("incident_closure_ai_reviewed")).CountX(f.ctx); n != 0 {
		t.Fatal("缺少整体恢复证明时不应生成模型审查决策", n)
	}
}
