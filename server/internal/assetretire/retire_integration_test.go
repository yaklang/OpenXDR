//go:build integration

package assetretire

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/review"
	"openxdr/server/internal/testdb"
)

func TestRetireAutoClosesIncidentsAndSweepCatchesStragglers(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("ops").SaveX(ctx)
	gym := db.Asset.Create().SetHostname("gym").SetGroupID(g.ID).SaveX(ctx)
	testLinux := db.Asset.Create().SetHostname("openxdr-test-linux").SetGroupID(g.ID).SaveX(ctx)
	activeHost := db.Asset.Create().SetHostname("zachary-dev").SetGroupID(g.ID).SaveX(ctx)
	now := time.Now().UTC().Truncate(time.Microsecond)

	newInc := func(status string, hosts ...*uuid.UUID) *ent.Incident {
		b := db.Incident.Create().SetStatus(status).SetGraph(json.RawMessage(`{}`)).SetCreatedAt(now.Add(-2 * time.Hour))
		if status == "triaged" {
			b.SetTriagedAt(now.Add(-time.Hour)).SetAiVerdict(json.RawMessage(`{"verdict":"malicious","summary":"靶机演练命令"}`)).
				SetClosureProposal(&schema.ClosureProposal{Status: "closed", Note: "旧建议", SessionID: uuid.New(), At: now.Add(-30 * time.Minute)})
		}
		inc := b.SaveX(ctx)
		for _, h := range hosts {
			evB := db.Event.Create().SetTs(now.Add(-90 * time.Minute)).SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{"process":{"cmd_line":"whoami"}}`))
			if h != nil {
				evB.SetAssetID(*h)
			}
			ev := evB.SaveX(ctx)
			alB := db.Alert.Create().SetTs(ev.Ts).SetRuleID("r-recon").SetSeverity(3).SetIncidentID(inc.ID).SetEventID(ev.ID)
			if h != nil {
				alB.SetAssetID(*h)
			}
			alB.SaveX(ctx)
		}
		return inc
	}

	openGym := newInc("open", &gym.ID)
	triagedGym := newInc("triaged", &gym.ID)
	mixedActive := newInc("triaged", &gym.ID, &activeHost.ID)
	mixedTwoRetiring := newInc("open", &gym.ID, &testLinux.ID)
	sensorUnbound := newInc("open", &gym.ID, nil)
	alreadyFP := newInc("open", &gym.ID)
	db.Incident.UpdateOneID(alreadyFP.ID).SetStatus("false_positive").SetResolvedBy("analyst").SetResolvedAt(now.Add(-time.Hour)).SetResolution("已知演练").ExecX(ctx)
	manualLocked := newInc("open", &gym.ID)
	db.Incident.UpdateOneID(manualLocked.ID).SetWork(&schema.IncidentWork{Version: 1, Owner: "human", ManualLock: true}).ExecX(ctx)

	// 1. 退役 gym：纯 gym 的 open 与 triaged 事件立即按 closed + asset_retired 结案，跨主机事件因另一台未退役而保持原状
	retiredGym, err := Retire(ctx, db, gym, "admin", "靶机实验结束销毁", now)
	if err != nil {
		t.Fatalf("Retire gym 失败：%v", err)
	}
	for _, id := range []uuid.UUID{openGym.ID, triagedGym.ID} {
		got := db.Incident.GetX(ctx, id)
		if got.Status != "closed" {
			t.Fatalf("事件 %s 应按 closed 结案，实际 status=%s", id, got.Status)
		}
		if got.ResolutionSource == nil || *got.ResolutionSource != ResolutionSource {
			t.Fatalf("事件 %s resolution_source 应为 %q，实际=%v", id, ResolutionSource, got.ResolutionSource)
		}
		if got.ResolvedBy == nil || *got.ResolvedBy != review.ClosedBy {
			t.Fatalf("事件 %s resolved_by 应为 %q，实际=%v", id, review.ClosedBy, got.ResolvedBy)
		}
		if got.ClosureProposal != nil {
			t.Fatalf("事件 %s 结案后应清空 closure_proposal", id)
		}
		if got.Resolution == nil || !strings.Contains(*got.Resolution, "由 admin 退役（原因：靶机实验结束销毁），主机不复存在") {
			t.Fatalf("事件 %s resolution 不符合要求：%v", id, got.Resolution)
		}
		logs := db.AuditLog.Query().Where(auditlog.ActionEQ("incident_status"), auditlog.TargetEQ(id.String())).AllX(ctx)
		if len(logs) != 1 || logs[0].Username != review.ClosedBy || logs[0].Detail == nil || !strings.HasPrefix(*logs[0].Detail, "closed 资产已于 ") {
			t.Fatalf("事件 %s 结案审计不符合预期：%+v", id, logs)
		}
	}

	// 仍有未退役资产、含无资产告警、人工锁定、原先已结案的事件均不能被动
	if s := db.Incident.GetX(ctx, mixedActive.ID).Status; s != "triaged" {
		t.Fatalf("含在线主机告警的事件不应结案：%s", s)
	}
	if s := db.Incident.GetX(ctx, mixedTwoRetiring.ID).Status; s != "open" {
		t.Fatalf("第二台主机尚未退役前跨机事件不应结案：%s", s)
	}
	if s := db.Incident.GetX(ctx, sensorUnbound.ID).Status; s != "open" {
		t.Fatalf("含无资产归属告警的事件不应结案：%s", s)
	}
	if got := db.Incident.GetX(ctx, alreadyFP.ID); got.Status != "false_positive" || *got.ResolvedBy != "analyst" {
		t.Fatalf("已结案事件不应被改写：%+v", got)
	}
	if s := db.Incident.GetX(ctx, manualLocked.ID).Status; s != "open" {
		t.Fatalf("人工锁定事件不应自动结案：%s", s)
	}

	// 2. 第二台涉及主机 openxdr-test-linux 也退役后，跨两台退役主机的事件随之结案
	later := now.Add(5 * time.Minute)
	if _, err := Retire(ctx, db, testLinux, "ops", "测试环境回收", later); err != nil {
		t.Fatalf("Retire testLinux 失败：%v", err)
	}
	gotMixed := db.Incident.GetX(ctx, mixedTwoRetiring.ID)
	if gotMixed.Status != "closed" || gotMixed.ResolutionSource == nil || *gotMixed.ResolutionSource != ResolutionSource {
		t.Fatalf("两台涉事主机均退役后应自动结案：%+v", gotMixed)
	}
	if gotMixed.Resolution == nil || !strings.Contains(*gotMixed.Resolution, "gym") || !strings.Contains(*gotMixed.Resolution, "openxdr-test-linux") {
		t.Fatalf("多退役主机结案说明应列出涉事资产：%v", gotMixed.Resolution)
	}

	// 3. 模拟竞态或历史遗留：在已退役资产上新关联出一个未结事件，单活兜底循环 Sweep 应补收
	straggler := newInc("triaged", &gym.ID)
	closer := &Closer{DB: db}
	swept, err := closer.Sweep(ctx, later.Add(time.Minute))
	if err != nil || swept != 1 {
		t.Fatalf("兜底 Sweep 应补收 1 起遗留事件：swept=%d err=%v", swept, err)
	}
	if got := db.Incident.GetX(ctx, straggler.ID); got.Status != "closed" || got.ResolutionSource == nil || *got.ResolutionSource != ResolutionSource {
		t.Fatalf("遗留事件兜底结案结果异常：%+v", got)
	}

	// 4. Restore 恢复资产后，已按 asset_retired 结案的事件绝不重开
	if _, err := Restore(ctx, db, retiredGym); err != nil {
		t.Fatalf("Restore gym 失败：%v", err)
	}
	for _, id := range []uuid.UUID{openGym.ID, triagedGym.ID, mixedTwoRetiring.ID, straggler.ID} {
		if s := db.Incident.GetX(ctx, id).Status; s != "closed" {
			t.Fatalf("资产恢复不应重开已结事件 %s：%s", id, s)
		}
	}
}

func TestRetireClosesFindingsAndQuestionsAndSweepCatchesStragglers(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("ops").SaveX(ctx)
	gym := db.Asset.Create().SetHostname("gym").SetGroupID(g.ID).SaveX(ctx)
	lizhen := db.Asset.Create().SetHostname("lizhen-dev").SetGroupID(g.ID).SaveX(ctx)
	activeHost := db.Asset.Create().SetHostname("zachary-dev").SetGroupID(g.ID).SaveX(ctx)
	now := time.Now().UTC().Truncate(time.Microsecond)

	fGym := db.Finding.Create().SetGroupID(g.ID).SetAssetID(gym.ID).SetKey("collect:silent").SetTitle("gym 失联").SetStatus("open").SaveX(ctx)
	fActive := db.Finding.Create().SetGroupID(g.ID).SetAssetID(activeHost.ID).SetKey("collect:silent").SetTitle("zachary-dev 失联").SetStatus("open").SaveX(ctx)

	qGymOwner := db.Question.Create().SetKind("owner").SetSubjectKind("asset").SetSubject(gym.ID.String()).
		SetGroupIds([]uuid.UUID{g.ID}).SetFindingIds([]uuid.UUID{fGym.ID}).SetStatus("open").SetCreatedBy("system").SaveX(ctx)
	qGymKey := db.Question.Create().SetKind("authorization").SetSubjectKind("key").
		SetSubject("SHA256:mtwVQQEIr75wGTFfVAuMn6y/LsfD5ULsqChRXqfXqJY").
		SetGroupIds([]uuid.UUID{g.ID}).SetFindingIds([]uuid.UUID{fGym.ID}).SetStatus("open").SetCreatedBy("system").SaveX(ctx)
	qMixedKey := db.Question.Create().SetKind("authorization").SetSubjectKind("key").
		SetSubject("SHA256:tEASU9iIr75wGTFfVAuMn6y/LsfD5ULsqChRXqfXqJY").
		SetGroupIds([]uuid.UUID{g.ID}).SetFindingIds([]uuid.UUID{fGym.ID, fActive.ID}).SetStatus("open").SetCreatedBy("system").SaveX(ctx)

	if _, err := Retire(ctx, db, gym, "admin", "实验机器销毁", now); err != nil {
		t.Fatalf("Retire gym: %v", err)
	}

	gotFGym := db.Finding.GetX(ctx, fGym.ID)
	if gotFGym.Status != "resolved" || gotFGym.Note == nil || !strings.HasPrefix(*gotFGym.Note, "资产已退役：") {
		t.Fatalf("退役资产上的未结待办应按资产已退役关闭：%+v", gotFGym)
	}
	if !db.AuditLog.Query().Where(auditlog.ActionEQ("finding_status"), auditlog.TargetEQ(fGym.ID.String())).ExistX(ctx) {
		t.Fatal("退役关闭待办应落 finding_status 审计")
	}

	for _, qid := range []uuid.UUID{qGymOwner.ID, qGymKey.ID} {
		gotQ := db.Question.GetX(ctx, qid)
		if gotQ.Status != "voided" || gotQ.Answer == nil || gotQ.Answer.Choice != "voided_retired" || !strings.Contains(gotQ.Answer.Content, "资产已退役，问题作废") {
			t.Fatalf("只涉及已退役资产的待答问题应作废：%+v", gotQ)
		}
		if !db.AuditLog.Query().Where(auditlog.ActionEQ("question_voided"), auditlog.TargetEQ(qid.String())).ExistX(ctx) {
			t.Fatalf("作废问题 %s 应落 question_voided 审计", qid)
		}
	}
	if gotMixed := db.Question.GetX(ctx, qMixedKey.ID); gotMixed.Status != "open" {
		t.Fatalf("仍涉及在线资产的问题不应被退役作废：%s", gotMixed.Status)
	}
	if gotActive := db.Finding.GetX(ctx, fActive.ID); gotActive.Status != "open" {
		t.Fatalf("在线资产上的待办不应受影响：%s", gotActive.Status)
	}

	// 模拟生产存量：资产早已退役，但历史待办与问题仍处于 open，兜底循环 Sweep 应一次收口
	db.Asset.UpdateOneID(lizhen.ID).SetRetiredAt(now.Add(-24 * time.Hour)).SetRetiredBy("admin").SetRetiredReason("旧开发机回收").ExecX(ctx)
	fStraggler := db.Finding.Create().SetGroupID(g.ID).SetAssetID(lizhen.ID).SetKey("disk-full").SetTitle("磁盘告警").SetStatus("open").SaveX(ctx)
	qStraggler := db.Question.Create().SetKind("policy").SetSubjectKind("asset").SetSubject(lizhen.ID.String()).
		SetGroupIds([]uuid.UUID{g.ID}).SetStatus("open").SetCreatedBy("system").SaveX(ctx)

	swept, err := (&Closer{DB: db}).Sweep(ctx, now.Add(time.Minute))
	if err != nil || swept != 2 {
		t.Fatalf("兜底 Sweep 应收敛存量退役待办与问题各 1 条：swept=%d err=%v", swept, err)
	}
	if db.Finding.GetX(ctx, fStraggler.ID).Status != "resolved" || db.Question.GetX(ctx, qStraggler.ID).Status != "voided" {
		t.Fatal("存量退役待办与问题均应已收敛")
	}
}

func TestParkAssetSuppressesSilenceAndPiFollowup(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("lab").SaveX(ctx)
	agentID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	testSrv := db.Asset.Create().
		SetHostname("TESTSRV").
		SetGroupID(g.ID).
		SetAgentID(agentID).
		SetLastSeen(now.Add(-2 * time.Hour)).
		SetSilentSince(now.Add(-time.Hour)).
		SaveX(ctx)

	fSilent := db.Finding.Create().SetGroupID(g.ID).SetAssetID(testSrv.ID).SetKey("collect:silent").SetTitle("TESTSRV 整机静默").
		SetStatus("open").SetWorkOwner("ai").SetWorkNextCheckAt(now).SaveX(ctx)
	fOther := db.Finding.Create().SetGroupID(g.ID).SetAssetID(testSrv.ID).SetKey("weak-sshd").SetTitle("SSH 配置待加固").
		SetStatus("open").SetWorkOwner("ai").SetWorkNextCheckAt(now).SaveX(ctx)
	qPlan := db.Question.Create().SetKind("policy").SetSubjectKind("asset").SetSubject(testSrv.ID.String()).
		SetGroupIds([]uuid.UUID{g.ID}).SetFindingIds([]uuid.UUID{fSilent.ID}).SetStatus("open").SetCreatedBy("system").SaveX(ctx)

	parked, err := Park(ctx, db, testSrv, "admin", "测试 VM 按需开机，平时关机保留", now)
	if err != nil {
		t.Fatalf("Park TESTSRV: %v", err)
	}
	if parked.ParkedAt == nil || parked.SilentSince != nil {
		t.Fatalf("Park 后应记录 parked_at 并清除 silent_since：%+v", parked)
	}
	if got := db.Finding.GetX(ctx, fSilent.ID); got.Status != "resolved" || got.Note == nil || !strings.Contains(*got.Note, "停机保留") {
		t.Fatalf("静默类待办应在停机保留时自动解决：%+v", got)
	}
	if got := db.Finding.GetX(ctx, fOther.ID); got.Status != "open" || got.WorkNextCheckAt != nil {
		t.Fatalf("非静默待办应保持 open 但停止轮询调度：%+v", got)
	}
	if gotQ := db.Question.GetX(ctx, qPlan.ID); gotQ.Status != "answered" || gotQ.Answer == nil || gotQ.Answer.Choice != "parked" {
		t.Fatalf("计划停机问题应随停机保留自动应答：%+v", gotQ)
	}

	// 1. 停机保留期间：Pi 跟进任务不再领取该主机待办
	sess := db.AgentSession.Create().SetGroupID(g.ID).SetKind("task").SetModel("test").SetInitiator("system").SaveX(ctx)
	db.Finding.UpdateOneID(fOther.ID).SetWorkNextCheckAt(now).ExecX(ctx)
	claimed, err := findings.Claim(ctx, db, sess, now.Add(time.Minute))
	if err != nil || len(claimed) != 0 {
		t.Fatalf("停机保留主机的待办不应被 Pi 领取：claimed=%d err=%v", len(claimed), err)
	}

	// 2. 取消停机保留后：非静默待办恢复可领取
	unparked, err := Unpark(ctx, db, parked, now.Add(2*time.Minute))
	if err != nil || unparked.ParkedAt != nil {
		t.Fatalf("Unpark TESTSRV: %v %+v", err, unparked)
	}
	sess2 := db.AgentSession.Create().SetGroupID(g.ID).SetKind("task").SetModel("test").SetInitiator("system").SaveX(ctx)
	claimedAfter, err := findings.Claim(ctx, db, sess2, now.Add(3*time.Minute))
	if err != nil || len(claimedAfter) != 1 || claimedAfter[0].ID != fOther.ID {
		t.Fatalf("取消停机保留后遗留待办应恢复领取：claimed=%d err=%v", len(claimedAfter), err)
	}
}
