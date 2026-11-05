//go:build integration

package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/triagerun"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/review"
	"openxdr/server/internal/testdb"
)

func dueAutonomyIncident(t *testing.T, ctx context.Context, db *ent.Client, now time.Time) *ent.Incident {
	t.Helper()
	raw := json.RawMessage(fmt.Sprintf(`{"verdict":"suspicious","action_codes":["collect_original_records"],"evidence_capability_version":%d}`, evidenceCapabilityVersion))
	inc := db.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SetCreatedAt(now.Add(-48 * time.Hour)).SetTriagedAt(now.Add(-24 * time.Hour)).SetAiVerdict(raw).SaveX(ctx)
	if err := incidentwork.Refresh(ctx, db, inc, now.Add(-incidentwork.FollowupDelay-time.Minute)); err != nil {
		t.Fatal(err)
	}
	return db.Incident.GetX(ctx, inc.ID)
}

func TestAutonomyFollowupLeaseRecoveryAndBudget(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	inc := dueAutonomyIncident(t, ctx, db, now)
	engine := &Engine{DB: db, Cooldown: time.Minute}
	first, err := engine.beginRun(ctx, inc, now, "test")
	if err != nil || first == nil {
		t.Fatalf("领取失败 row=%v err=%v", first, err)
	}
	current := db.Incident.GetX(ctx, inc.ID)
	if current.Work.Attempts != 1 || current.WorkNextCheckAt == nil || first.Trigger != "autonomy_followup" {
		t.Fatal("领取不得丢失计划或漏计尝试", current.Work)
	}
	if duplicate, err := engine.beginRun(ctx, current, now, "test"); err != nil || duplicate != nil {
		t.Fatal("有效租约被重复领取", duplicate, err)
	}
	// 模拟节点退出：只有持久记录和过期心跳，没有正常完成或清理回调。
	db.Incident.UpdateOneID(inc.ID).SetTriageHeartbeatAt(now.Add(-2 * RunningTTL)).ExecX(ctx)
	if err := incidentwork.Reconcile(ctx, db, now); err != nil {
		t.Fatal(err)
	}
	current = db.Incident.GetX(ctx, inc.ID)
	second, err := engine.beginRun(ctx, current, time.Now().UTC().Truncate(time.Microsecond), "test")
	if err != nil || second == nil {
		t.Fatal("失联任务未能接管", second, err)
	}
	if db.TriageRun.GetX(ctx, first.ID).Status != triagerun.StatusInterrupted {
		t.Fatal("旧运行未标中断")
	}
	// 模拟正常取消路径：记录中断并由 keepRunning 清除自己的租约，下一轮仍可接管。
	parent, cancel := context.WithCancel(ctx)
	_, finish := engine.keepRunning(parent, inc.ID, second.StartedAt)
	cancel()
	finish()
	engine.failRun(second, &runTiming{}, "model", context.Canceled)
	current = db.Incident.GetX(ctx, inc.ID)
	third, err := engine.beginRun(ctx, current, time.Now().UTC().Truncate(time.Microsecond), "test")
	if err != nil || third == nil {
		t.Fatal("取消后任务丢失", third, err)
	}
	if err := incidentwork.Reconcile(ctx, db, time.Now()); err != nil {
		t.Fatal(err)
	}
	current = db.Incident.GetX(ctx, inc.ID)
	if current.Work.Attempts != incidentwork.MaxAttempts || current.Work.Stage != "followup" {
		t.Fatal("不得在有效租约期间耗尽转监测", current.Work)
	}
	db.Incident.UpdateOneID(inc.ID).SetTriageHeartbeatAt(now.Add(-2 * RunningTTL)).ExecX(ctx)
	if err := incidentwork.Reconcile(ctx, db, time.Now()); err != nil {
		t.Fatal(err)
	}
	current = db.Incident.GetX(ctx, inc.ID)
	if current.Work.Stage != "monitoring" || current.WorkNextCheckAt != nil || current.Work.Attempts != incidentwork.MaxAttempts {
		t.Fatal("第三次失联后必须有界转监测", current.Work)
	}
	queued, err := engine.queue(ctx, time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range queued {
		if q.ID == inc.ID {
			t.Fatal("预算耗尽仍无限入队")
		}
	}
	if current.Status != "triaged" || current.EvidenceAt != nil || db.Incident.Query().Where(incident.IDEQ(inc.ID), review.StaleBenign(now.Add(72*time.Hour))).ExistX(ctx) {
		t.Fatal("跟进不得伪造证据或误报结案")
	}
}

func TestAutonomyClaimRejectsNewEvidenceAndManualTerminal(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	engine := &Engine{DB: db, Cooldown: time.Minute}
	for _, state := range []string{"new_evidence", "closed", "false_positive"} {
		inc := dueAutonomyIncident(t, ctx, db, now)
		if state == "new_evidence" {
			db.Incident.UpdateOneID(inc.ID).SetEvidenceAt(now).ExecX(ctx)
		} else {
			db.Incident.UpdateOneID(inc.ID).SetStatus(state).ExecX(ctx)
		}
		row, err := engine.beginRun(ctx, inc, now, "test")
		if err != nil || row != nil {
			t.Fatalf("旧计划领取覆盖%s row=%v err=%v", state, row, err)
		}
		got := db.Incident.GetX(ctx, inc.ID)
		if got.Work.Attempts != 0 {
			t.Fatal("未领取却消费调查预算")
		}
		if state != "new_evidence" && got.Status != state {
			t.Fatal("人工终态被改写")
		}
	}
}
