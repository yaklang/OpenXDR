//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/commandpolicy"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/response"
	"openxdr/server/internal/schedule"
	"openxdr/server/internal/testdb"
)

func TestFindingAutonomyClaimsBudgetAndScope(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	b := db.Asset.Create().SetHostname("b").SetGroupID(other.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	task := db.Task.Create().SetID(findings.FollowupTask).SetName("followup").SetSchedule("*/30 * * * *").SetPrompt("p").SaveX(ctx)
	db.TaskRun.Create().SetTaskID(task.ID).SetGroupID(g.ID).SetSessionID(session.ID).SetScheduledAt(time.Now()).SetStatus("running").SaveX(ctx)
	for i := 0; i < 5; i++ {
		db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey(fmt.Sprint(i)).SetTitle("capacity").SaveX(ctx)
	}
	db.Finding.Create().SetGroupID(g.ID).SetAssetID(b.ID).SetKey("moved").SetTitle("moved").SaveX(ctx)
	svc := &Service{DB: db}
	bound, has, err := svc.prepareFindingWork(ctx, session)
	if err != nil || !bound || !has || len(session.Subjects) != 3 {
		t.Fatalf("claim: %v %v %v %+v", bound, has, err, session.Subjects)
	}
	// 其他会话不能再次领取有效租约。
	next := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	rows, err := findings.Claim(ctx, db, next, time.Now())
	if err != nil || len(rows) != 2 {
		t.Fatalf("second claim %d %v", len(rows), err)
	}
	if err := svc.guardFindingExec(ctx, session, b.ID, "df -h"); err == nil {
		t.Fatal("cross group host accepted")
	}
	if err := svc.guardFindingExec(ctx, session, a.ID, "df -h"); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"iptables -S", "iptables -L -n -v", "nft list ruleset"} {
		if err := svc.guardFindingExec(ctx, session, a.ID, cmd); err != nil {
			t.Fatalf("只读防火墙诊断被拒：%s: %v", cmd, err)
		}
	}
	if err := svc.guardFindingExec(ctx, session, a.ID, "systemctl restart -- test.service"); err == nil {
		t.Fatal("write without trusted maintenance scope accepted")
	}
	if _, err := svc.findingExecTarget(ctx, session, a.ID, "docker exec x ls", uuid.MustParse(strings.TrimPrefix(session.Subjects[0], "finding:"))); err == nil || !strings.Contains(err.Error(), "自治跟进只允许只读命令") {
		t.Fatalf("unexpected denial: %v", err)
	}
	called := 0
	svc.RevalidateFindingRepair = func(context.Context, *ent.AgentSession, *ent.Finding, string) error { return nil }
	svc.AuthorizeFindingRepair = func(_ context.Context, gotSession *ent.AgentSession, got *ent.Finding, cmd string) error {
		called++
		if gotSession.ID != session.ID || got.AssetID != a.ID || cmd != "systemctl restart -- test.service" {
			return fmt.Errorf("not in maintenance scope")
		}
		return nil
	}
	if _, err := svc.findingExecTarget(ctx, session, a.ID, "systemctl restart -- test.service", uuid.MustParse(strings.TrimPrefix(session.Subjects[0], "finding:"))); err != nil || called != 1 {
		t.Fatalf("trusted scope not consulted: %v %d", err, called)
	}
	if err := svc.guardFindingExec(ctx, session, a.ID, "systemctl restart production.service"); err == nil {
		t.Fatal("out of scope write accepted")
	}
	// 未知写操作不能补发，独立只读观察仍可继续。
	db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("systemctl restart app").SetStatus("unknown").SaveX(ctx)
	if err := svc.guardFindingExec(ctx, session, a.ID, "systemctl restart app"); err == nil {
		t.Fatal("unknown replay accepted")
	}
	if err := svc.guardFindingExec(ctx, session, a.ID, "df -h"); err != nil {
		t.Fatal(err)
	}
	id := uuid.MustParse(strings.TrimPrefix(session.Subjects[0], "finding:"))
	f := db.Finding.GetX(ctx, id)
	db.Finding.UpdateOneID(f.ID).SetWorkAttempts(4).ExecX(ctx)
	if err := svc.guardFindingExec(ctx, session, a.ID, "systemctl restart app"); err == nil {
		t.Fatal("budget ignored")
	}
	if err := findings.Release(ctx, db, session.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	f = db.Finding.GetX(ctx, id)
	if f.WorkSessionID != nil || f.WorkLeaseUntil != nil || f.WorkNextCheckAt == nil || f.WorkNextCheckAt.Before(time.Now().Add(23*time.Hour)) {
		t.Fatalf("not deferred: %+v", f)
	}
	if err := svc.guardFindingExec(ctx, session, a.ID, "df -h"); err == nil {
		t.Fatal("released task may execute")
	}
}

func TestFindingResolvedRequiresFreshIndependentEvidence(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("service").SetTitle("failed").SaveX(ctx)
	svc := &Service{DB: db}
	if err := svc.findingEvidence(ctx, session, f, nil, true, ""); err == nil {
		t.Fatal("no evidence accepted")
	}
	mk := func(cmd, status, out string) *ent.Command {
		created := time.Now()
		return db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd(cmd).SetStatus(status).SetExitCode(0).SetStdout(out).SetCreatedAt(created).SetCompletedAt(time.Now()).SaveX(ctx)
	}
	for _, c := range []*ent.Command{mk("systemctl restart app", "succeeded", "done"), mk("systemctl is-active app", "unknown", "active"), mk("journalctl -n 40", "succeeded", "")} {
		if err := svc.findingEvidence(ctx, session, f, []uuid.UUID{c.ID}, true, ""); err == nil {
			t.Fatalf("bad proof accepted: %+v", c)
		}
	}
	proof := mk("systemctl is-active app", "succeeded", "active")
	if err := svc.findingEvidence(ctx, session, f, []uuid.UUID{proof.ID}, true, ""); err != nil {
		t.Fatal(err)
	}
	proof.Update().SetTruncated(true).ExecX(ctx)
	if err := svc.findingEvidence(ctx, session, f, []uuid.UUID{proof.ID}, true, ""); err == nil {
		t.Fatal("truncated accepted")
	}
	proof.Update().SetTruncated(false).ExecX(ctx)
	mk("systemctl restart app", "succeeded", "done")
	if err := svc.findingEvidence(ctx, session, f, []uuid.UUID{proof.ID}, true, ""); err == nil {
		t.Fatal("write after verification accepted")
	}
	fail := mk("journalctl -n 40", "failed", "")
	fail.Update().SetStderr("permission denied").ExecX(ctx)
	if err := svc.saveFindingPlan(ctx, session, f, "operator must grant log access", "permission", []uuid.UUID{fail.ID}); err != nil {
		t.Fatal(err)
	}
	got := db.Finding.GetX(ctx, f.ID)
	var work findings.Work
	_ = json.Unmarshal(got.Work, &work)
	if got.WorkOwner != "human" || work.Stage != "blocked" || got.Status != "open" {
		t.Fatalf("human blocker missing: %+v %s", got, got.Work)
	}
	// 忽略后的原快照不能重新写计划或关单。
	db.Finding.UpdateOneID(f.ID).SetStatus("ignored").ExecX(ctx)
	args := []byte(`{"host":"` + a.ID.String() + `","key":"service","title":"resolved","detail":"active","severity":"low","status":"resolved"}`)
	out, err := svc.tool(ctx, session, commandgate.Request{System: true}, "track", args)
	if err != nil || !strings.Contains(out, "ignored") || db.Finding.GetX(ctx, f.ID).Status != "ignored" {
		t.Fatalf("human ignore not preserved: %s %v", out, err)
	}
}

func TestFindingIndependentReviewRequiredAndManualFence(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("service").SetTitle("service failed").SaveX(ctx)
	c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("systemctl show app.service -p ActiveState").SetCreatedAt(session.CreatedAt).SetStatus("succeeded").SetExitCode(0).SetStdout("ActiveState=active").SetCompletedAt(time.Now()).SaveX(ctx)
	args := []byte(`{"host":"` + a.ID.String() + `","key":"service","title":"recovered","detail":"verified active","severity":"low","status":"resolved","evidence_commands":["` + c.ID.String() + `"]}`)
	svc := &Service{DB: db}
	call := func() error {
		_, err := svc.tool(ctx, session, commandgate.Request{System: true}, "track", args)
		return err
	}
	if err := call(); err == nil || db.Finding.GetX(ctx, f.ID).Status != "open" {
		t.Fatal("missing independent reviewer closed finding")
	}
	svc.ReviewFinding = func(_ context.Context, _ *ent.AgentSession, _ *ent.Finding, _ []*ent.Command) (bool, string, error) {
		return false, "evidence does not cover dependency", nil
	}
	if err := call(); err == nil || db.Finding.GetX(ctx, f.ID).Status != "open" {
		t.Fatal("review rejection closed finding")
	}
	svc.ReviewFinding = func(_ context.Context, _ *ent.AgentSession, _ *ent.Finding, _ []*ent.Command) (bool, string, error) {
		db.Finding.UpdateOneID(f.ID).SetStatus("ignored").SetNote("human ignored during review").ExecX(ctx)
		return true, "active", nil
	}
	if err := call(); err == nil || db.Finding.GetX(ctx, f.ID).Status != "ignored" {
		t.Fatal("review overwrote manual terminal")
	}
}

func TestFindingFollowupNoDueSkipsModel(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	db.Task.Create().SetID(findings.FollowupTask).SetName("followup").SetSchedule("*/30 * * * *").SetPrompt("p").SaveX(ctx)
	db.TaskRun.Create().SetTaskID(findings.FollowupTask).SetGroupID(g.ID).SetSessionID(session.ID).SetScheduledAt(time.Now()).SetStatus("running").SaveX(ctx)
	// 未提供 Pi Runner 或模型端点：空队列不能调用模型，更不能编造报告/修复结果。
	svc := &Service{DB: db}
	if err := svc.RunTask(ctx, schedule.Job{Session: session, Prompt: "follow up"}); err != nil {
		t.Fatal(err)
	}
	if got := db.AgentSession.GetX(ctx, session.ID); got.Status != "succeeded" {
		t.Fatalf("%+v", got)
	}
}

func TestFindingRepairBindsFinalGateRevalidation(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	agent := uuid.New()
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SetAgentID(agent).SetOs("linux").SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("service").SetTitle("failed").SetWorkSessionID(session.ID).SetWorkLeaseUntil(time.Now().Add(time.Minute)).SetWorkAttempts(1).SaveX(ctx)
	db.Task.Create().SetID(findings.FollowupTask).SetName("followup").SetSchedule("*/30 * * * *").SetPrompt("p").SaveX(ctx)
	db.TaskRun.Create().SetTaskID(findings.FollowupTask).SetGroupID(g.ID).SetSessionID(session.ID).SetScheduledAt(time.Now()).SetStatus("running").SaveX(ctx)
	db.CommandPolicy.Create().SetGroupID(g.ID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern(`systemctl restart`).SaveX(ctx)
	hub := response.NewHub(db, true)
	inbox := hub.Attach(agent)
	defer hub.Detach(agent, inbox)
	reviews, finalChecks, authorizations := 0, 0, 0
	gate := &commandgate.Gate{DB: db, Hub: hub, Reviewer: func(context.Context, commandgate.Request) (bool, string, error) {
		reviews++
		return true, "approved", nil
	}}
	svc := &Service{DB: db, Gate: gate, AuthorizeFindingRepair: func(context.Context, *ent.AgentSession, *ent.Finding, string) error { authorizations++; return nil }}
	args := []byte(`{"host":"` + a.ID.String() + `","cmd":"systemctl restart -- worker-app.service"}`)
	if _, err := svc.tool(ctx, session, commandgate.Request{System: true}, "exec", args); err == nil || authorizations != 0 {
		t.Fatal("missing final revalidation should fail before reserving action")
	}
	svc.RevalidateFindingRepair = func(_ context.Context, gotSession *ent.AgentSession, got *ent.Finding, cmd string) error {
		finalChecks++
		if gotSession.ID != session.ID || got.ID != f.ID || cmd != "systemctl restart -- worker-app.service" {
			t.Fatal("final hook lost original scope")
		}
		return fmt.Errorf("grant revoked during review")
	}
	if _, err := svc.tool(ctx, session, commandgate.Request{System: true}, "exec", args); err == nil {
		t.Fatal("service dropped final hook")
	}
	if reviews != 1 || finalChecks != 1 || authorizations != 1 {
		t.Fatalf("incorrect call chain: initial=%d reviewer=%d final=%d", authorizations, reviews, finalChecks)
	}
	select {
	case c := <-inbox:
		t.Fatalf("revoked action reached Hub: %+v", c)
	default:
	}
	if db.Command.Query().CountX(ctx) != 0 {
		t.Fatal("revoked action persisted a command")
	}
}

func TestFindingReclaimTemplatesReachGrantAndRequireVerification(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetGroupID(g.ID).SetModel("m").SetStatus("running").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("disk-full").SetTitle("磁盘空间不足").SetWorkOwner("ai").SetWorkSessionID(session.ID).SetWorkLeaseUntil(time.Now().Add(time.Minute)).SaveX(ctx)
	db.Task.Create().SetID(findings.FollowupTask).SetName("follow").SetSchedule("*/30 * * * *").SetPrompt("p").ExecX(ctx)
	db.TaskRun.Create().SetTaskID(findings.FollowupTask).SetGroupID(g.ID).SetSessionID(session.ID).SetScheduledAt(time.Now()).SetStatus("running").ExecX(ctx)
	count := 0
	svc := &Service{DB: db, AuthorizeFindingRepair: func(context.Context, *ent.AgentSession, *ent.Finding, string) error { count++; return nil }, RevalidateFindingRepair: func(context.Context, *ent.AgentSession, *ent.Finding, string) error { return nil }}
	if _, err := svc.findingExecTarget(ctx, session, a.ID, "apt-get clean", f.ID); err == nil || count != 0 {
		t.Fatal("缺少验证仍预留回收")
	}
	svc.RecordFindingProbe = func(context.Context, *ent.AgentSession, *ent.Command) error { return nil }
	svc.VerifyFindingRepair = func(context.Context, *ent.AgentSession, *ent.Finding, []uuid.UUID) error {
		return fmt.Errorf("空间尚未增加")
	}
	for _, cmd := range []string{"docker image prune -f", "docker builder prune -f", "apt-get clean", "find -- /srv/cache -xdev -type f -mtime +7 -delete"} {
		target, err := svc.findingExecTarget(ctx, session, a.ID, cmd, f.ID)
		if err != nil || target == nil || target.ID != f.ID {
			t.Fatal(cmd, target, err)
		}
	}
	if count != 4 {
		t.Fatal("回收模板未走真实授权入口", count)
	}
	for _, cmd := range []string{"apt-get clean; id", "find -- /srv/cache -xdev -type f -mtime +6 -delete", "docker image prune -af"} {
		if _, err := svc.findingExecTarget(ctx, session, a.ID, cmd, f.ID); err == nil || !strings.Contains(err.Error(), "docker image prune -f") {
			t.Fatal("非模板命令未拒绝或缺少可用模板提示", err)
		}
	}
	probe := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("df -P /").SetCreatedAt(time.Now()).SetStatus("succeeded").SetExitCode(0).SetStdout("fresh probe").SetCompletedAt(time.Now()).SaveX(ctx)
	if err := svc.findingEvidence(ctx, session, f, []uuid.UUID{probe.ID}, true, ""); err == nil || !strings.Contains(err.Error(), "空间尚未增加") {
		t.Fatal("结案绕过独立回收验证", err)
	}
}
