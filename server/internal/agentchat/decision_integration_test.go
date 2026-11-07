//go:build integration

package agentchat

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/commandpolicy"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/findings"
	"openxdr/server/internal/response"
	"openxdr/server/internal/testdb"
)

func TestDelegatedContextAndHardDenialRemainSeparate(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(g.ID).SaveX(ctx)
	u := db.User.Create().SetUsername("admin").SetRole("admin").SetPasswordHash("x").SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("retire").SetTitle("退役").SetWork(findings.EncodeWork(findings.Work{Version: 3, Stage: "blocked", Blocker: "legacy_decommission_confirm", RepairAttempts: 2})).SaveX(ctx)
	d, _, err := findings.Delegate(ctx, db, f.ID, u, uuid.New(), "仅退役旧服务，保留所有数据", "m", "local", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s := db.AgentSession.GetX(ctx, d.SessionID)
	s.Update().SetStatus("running").ExecX(ctx)
	s = db.AgentSession.GetX(ctx, s.ID)
	svc := &Service{DB: db, Gate: &commandgate.Gate{DB: db, Hub: response.NewHub(db, true)}}
	// 对话不注入自治任务有限模板，避免把合法管理员决定错误解释为缺授权。
	svc.FindingRepairCapabilities = func(_ctx context.Context, _s *ent.AgentSession, _f *ent.Finding, _cmd, _mount string) (findings.RepairCapabilities, error) {
		t.Fatal("对话被误当成封闭维修任务")
		return findings.RepairCapabilities{}, nil
	}
	data, err := svc.contextData(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if data["execution_mode"] != "delegated_chat" || data["operator_decision"] == nil {
		t.Fatal(data)
	}
	svc.FindingRepairCapabilities = nil
	observer := db.AgentSession.Create().SetGroupID(g.ID).SetKind("chat").SetInitiator(u.Username).SetModel("m").SetSubjects([]string{"finding:" + f.ID.String()}).SaveX(ctx)
	view, err := svc.contextData(ctx, observer)
	if err != nil {
		t.Fatal(err)
	}
	if view["operator_decision"] != nil || view["subjects"].([]map[string]any)[0]["operator_decision"] == nil {
		t.Fatal("后续会话看不到已作出的决定，或误取得了执行身份", view)
	}
	if authority, err := findings.DecisionForSession(ctx, db, observer); err != nil || authority != nil {
		t.Fatal("观察决定等于取得执行权限", authority, err)
	}
	probe := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCreatedAt(s.CreatedAt.Add(time.Microsecond)).SetCmd("systemctl show metis-dispatcher.service").SetStatus("succeeded").SetExitCode(0).SetCompletedAt(time.Now()).SetStdout("ActiveState=active").SaveX(ctx)
	db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("systemctl disable --now old.service").SetCreatedAt(time.Now()).SetCompletedAt(time.Now()).SetStatus("succeeded").SetExitCode(0).SaveX(ctx)
	if err = svc.saveFindingPlan(ctx, s, f, "按已记录决定执行，仍经审计", "none", []uuid.UUID{probe.ID}); err != nil {
		t.Fatal("真实管理员决定没有承接旧人工阻塞", err)
	}
	var work findings.Work
	json.Unmarshal(db.Finding.GetX(ctx, f.ID).Work, &work)
	if work.Blocker != "" || work.RepairAttempts != 2 {
		t.Fatal("解除意图阻塞损坏了预算", work)
	}
	if err = svc.saveFindingPlan(ctx, s, db.Finding.GetX(ctx, f.ID), "按决定继续独立验证", "none", []uuid.UUID{probe.ID}); err != nil {
		t.Fatal("重复承接决定不幂等", err)
	}
	if err = svc.findingEvidence(ctx, s, f, []uuid.UUID{probe.ID}, true, ""); err == nil || !strings.Contains(err.Error(), "不要混入修复前证据") {
		t.Fatal("承接决定被当成修复效果", err)
	}
	post := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("systemctl show old.service").SetCreatedAt(time.Now()).SetCompletedAt(time.Now()).SetStatus("succeeded").SetExitCode(0).SetStdout("ActiveState=inactive\nUnitFileState=disabled").SaveX(ctx)
	if err = svc.findingEvidence(ctx, s, f, []uuid.UUID{post.ID}, true, ""); err != nil {
		t.Fatal("独立变更后证据未被接受", err)
	}
	args, _ := json.Marshal(map[string]any{"host": a.ID, "cmd": "rm -f /etc/systemd/system/old.service", "timeout": 30})
	_, err = svc.tool(ctx, s, commandgate.Request{UserID: u.ID}, "exec", args)
	if err == nil || !strings.Contains(err.Error(), "硬拒绝") {
		t.Fatal("决定绕过了删除硬拒绝", err)
	}
	db.CommandPolicy.Create().SetGroupID(g.ID).SetOrigin(commandpolicy.OriginAi).SetMode(commandpolicy.ModeDeny).SetPattern("systemctl").SaveX(ctx)
	svc.Gate.Reviewer = func(context.Context, commandgate.Request) (bool, string, error) {
		return true, "范围可用，但同时撤销", findings.RevokeDecision(ctx, db, f.ID, "admin", "local")
	}
	args, _ = json.Marshal(map[string]any{"host": a.ID, "cmd": "systemctl disable --now old.service", "timeout": 30})
	if _, err = svc.tool(ctx, s, commandgate.Request{UserID: u.ID}, "exec", args); err == nil {
		t.Fatal("审批后撤销未阻止下发")
	}
	if db.Command.Query().CountX(ctx) != 3 {
		t.Fatal("撤销后仍创建了新动作")
	}
}
