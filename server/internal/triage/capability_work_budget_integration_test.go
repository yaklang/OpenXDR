//go:build integration

package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/schema"
	"openxdr/server/ent/triagerun"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/testdb"
)

func capabilityBudgetWork(t *testing.T, ctx context.Context, db *ent.Client, now time.Time, version int, offset time.Duration) *ent.Incident {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"verdict": "suspicious", "action_codes": []string{"collect_original_records"}, "evidence_capability_version": version})
	inc := db.Incident.Create().SetGraph(json.RawMessage(`{}`)).SetStatus("triaged").SetCreatedAt(now.Add(-48 * time.Hour)).SetTriagedAt(now.Add(-24 * time.Hour)).SetTriageCount(1).SetAiVerdict(raw).SaveX(ctx)
	if err := incidentwork.Refresh(ctx, db, inc, now.Add(offset)); err != nil {
		t.Fatal(err)
	}
	return db.Incident.GetX(ctx, inc.ID)
}

func failedCapabilityBudget(ctx context.Context, db *ent.Client, id uuid.UUID, now time.Time, trigger string) {
	for range capabilityMaxAttempts {
		db.TriageRun.Create().SetIncidentID(id).SetModel("test").SetTrigger(trigger).SetStartedAt(now.Add(-9 * time.Hour)).SetStatus(triagerun.StatusFailed).SetFinishedAt(now.Add(-8 * time.Hour)).ExecX(ctx)
	}
}

func TestExhaustedCapabilityWorkDoesNotBlockNormalFollowup(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	stuck := capabilityBudgetWork(t, ctx, db, now, evidenceCapabilityVersion-1, -8*time.Hour)
	receipt := schema.WorkReceipt{CommandID: uuid.NewString(), Template: "linux_auth_journal", Status: "unknown"}
	original := *stuck.Work
	original.Receipts = []schema.WorkReceipt{receipt}
	db.Incident.UpdateOneID(stuck.ID).SetWork(&original).ExecX(ctx)
	failedCapabilityBudget(ctx, db, stuck.ID, now, capabilityTrigger)
	good := capabilityBudgetWork(t, ctx, db, now, evidenceCapabilityVersion, -7*time.Hour)
	e := &Engine{DB: db, Cooldown: time.Minute}
	for range 2 {
		queued, err := e.queue(ctx, now)
		if err != nil || len(queued) != 1 || queued[0].ID != good.ID {
			t.Fatalf("耗尽的旧能力阻塞普通工作: queue=%v err=%v", queued, err)
		}
	}
	paused := db.Incident.GetX(ctx, stuck.ID)
	if paused.Work.Stage != "monitoring" || paused.WorkNextCheckAt != nil || paused.Work.Attempts != original.Attempts || paused.Work.GapKind != original.GapKind || !reflect.DeepEqual(paused.Work.Receipts, original.Receipts) || !strings.Contains(paused.Work.Reason, "升级重试预算耗尽") {
		t.Fatal("暂停必须保留缺口、回执和独立普通预算", paused.Work)
	}
	if string(paused.AiVerdict) != string(stuck.AiVerdict) || paused.Status != "triaged" || paused.ResolvedAt != nil || paused.EvidenceAt != nil {
		t.Fatal("暂停不得伪造新结论、证据或结案")
	}
	if err := incidentwork.Reconcile(ctx, db, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	paused = db.Incident.GetX(ctx, stuck.ID)
	if paused.Work.Stage != "monitoring" || paused.WorkNextCheckAt != nil {
		t.Fatal("责任对账重新激活耗尽计划")
	}
	row, err := e.beginRun(ctx, db.Incident.GetX(ctx, good.ID), now, "test")
	if err != nil || row == nil || row.Trigger != "autonomy_followup" {
		t.Fatal("正常v3工作仍无法领取", row, err)
	}
	if db.Incident.GetX(ctx, good.ID).Work.Attempts != 1 {
		t.Fatal("普通跟进预算计数错误")
	}
	if db.TriageRun.Query().Where(triagerun.IncidentIDEQ(stuck.ID)).CountX(ctx) != capabilityMaxAttempts {
		t.Fatal("耗尽能力被重复执行")
	}
}

func TestPendingCapabilityIsExcludedFromOrdinaryWorkAndCanWake(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	stuck := capabilityBudgetWork(t, ctx, db, now, evidenceCapabilityVersion-1, -8*time.Hour)
	failedCapabilityBudget(ctx, db, stuck.ID, now, capabilityTrigger)
	good := capabilityBudgetWork(t, ctx, db, now, evidenceCapabilityVersion, -7*time.Hour)
	// 有效执行租约阻止对账暂停；即便旧坏计划仍在队首，普通工作筛选也必须独立排除它。
	db.Incident.UpdateOneID(stuck.ID).SetTriageStartedAt(now).SetTriageHeartbeatAt(now).ExecX(ctx)
	e := &Engine{DB: db, Cooldown: time.Minute}
	queued, err := e.queue(ctx, now)
	if err != nil || len(queued) != 1 || queued[0].ID != good.ID {
		t.Fatal("旧能力从普通WorkDue漏入Limit1", queued, err)
	}
	if db.Incident.GetX(ctx, stuck.ID).Work.Stage != "followup" {
		t.Fatal("有效租约被后台改写")
	}
	db.Incident.UpdateOneID(stuck.ID).ClearTriageStartedAt().ClearTriageHeartbeatAt().ExecX(ctx)
	if err := e.pauseExhaustedCapabilityWork(ctx, now); err != nil {
		t.Fatal(err)
	}
	// 新证据走真正的 evidence 队列，不受旧能力预算或监测态阻挡。
	db.Incident.UpdateOneID(stuck.ID).SetEvidenceAt(now.Add(-time.Hour)).ExecX(ctx)
	changed := db.Incident.GetX(ctx, stuck.ID)
	queued, err = e.queue(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, inc := range queued {
		if inc.ID == stuck.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("新证据未能唤醒监测工作")
	}
	row, err := e.beginRun(ctx, changed, now, "recovered-provider")
	if err != nil || row == nil || row.Trigger != "evidence" {
		t.Fatal("恢复后的新证据无法领取", row, err)
	}
	// 显式人工重开也有自己的 fresh 路径，不能借此重置能力或普通预算。
	db.Incident.UpdateOneID(stuck.ID).ClearTriageStartedAt().ClearTriageHeartbeatAt().ClearEvidenceAt().SetStatus("open").ExecX(ctx)
	reopened := db.Incident.GetX(ctx, stuck.ID)
	row, err = e.beginRun(ctx, reopened, now.Add(time.Microsecond), "recovered-provider")
	if err != nil || row == nil || row.Trigger != "reopened" {
		t.Fatal("明确重开被旧能力预算阻塞", row, err)
	}
	if db.Incident.GetX(ctx, stuck.ID).Work.Attempts != 0 {
		t.Fatal("把能力预算混入普通预算")
	}
	// 其他能力版本的历史失败不消耗当前 trigger 的额度。
	fresh := capabilityBudgetWork(t, ctx, db, now, evidenceCapabilityVersion-1, -8*time.Hour)
	failedCapabilityBudget(ctx, db, fresh.ID, now, fmt.Sprintf("capability_upgrade_v%d", evidenceCapabilityVersion-1))
	if !db.Incident.Query().Where(incident.IDEQ(fresh.ID), capabilityDue(now, e.Cooldown)).ExistX(ctx) {
		t.Fatal("旧能力版本错误消耗新版本预算")
	}
}

func TestCapabilityPauseSnapshotCannotReplaceNewWork(t *testing.T) {
	for _, change := range []string{"new_evidence", "new_plan", "reopened", "closed", "new_verdict", "active_lease"} {
		t.Run(change, func(t *testing.T) {
			ctx, db := testdb.New(t)
			now := time.Now().UTC().Truncate(time.Microsecond)
			stale := capabilityBudgetWork(t, ctx, db, now, evidenceCapabilityVersion-1, -8*time.Hour)
			failedCapabilityBudget(ctx, db, stale.ID, now, capabilityTrigger)
			switch change {
			case "new_evidence":
				db.Incident.UpdateOneID(stale.ID).SetEvidenceAt(now).ExecX(ctx)
			case "new_plan":
				work := *stale.Work
				work.Attempts = 1
				work.Reason = "并发新计划"
				db.Incident.UpdateOneID(stale.ID).SetWork(&work).SetWorkNextCheckAt(now.Add(time.Hour)).ExecX(ctx)
			case "reopened":
				db.Incident.UpdateOneID(stale.ID).SetStatus("open").ExecX(ctx)
			case "closed":
				db.Incident.UpdateOneID(stale.ID).SetStatus("closed").ExecX(ctx)
			case "new_verdict":
				db.Incident.UpdateOneID(stale.ID).SetAiVerdict(withEvidenceCapability(stale.AiVerdict)).ExecX(ctx)
			case "active_lease":
				db.Incident.UpdateOneID(stale.ID).SetTriageStartedAt(now).SetTriageHeartbeatAt(now).ExecX(ctx)
			}
			before := db.Incident.GetX(ctx, stale.ID)
			if err := (&Engine{DB: db}).pauseCapabilityWork(ctx, stale, now); err != nil {
				t.Fatal(err)
			}
			after := db.Incident.GetX(ctx, stale.ID)
			if !reflect.DeepEqual(before.Work, after.Work) || !reflect.DeepEqual(before.WorkNextCheckAt, after.WorkNextCheckAt) || before.Status != after.Status || string(before.AiVerdict) != string(after.AiVerdict) {
				t.Fatal("旧预算快照覆盖了并发变化", before, after)
			}
		})
	}
}
