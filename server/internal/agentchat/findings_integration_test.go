//go:build integration

package agentchat

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/ent/finding"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/testdb"
)

// 待办生命周期：登记 → 仍在 → 复查修复 → 复发重开 → 人工忽略后 AI 不再改动。
func TestTrackFindings(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("o").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve2").SetGroupID(group.ID).SaveX(ctx)
	stranger := db.Asset.Create().SetHostname("x").SetGroupID(other.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetGroupID(group.ID).SetInitiator(commandgate.SystemActor).
		SetModel("m").SetStatus("running").SetTitle("巡检").SaveX(ctx)
	s := &Service{DB: db, ReviewFinding: func(context.Context, *ent.AgentSession, *ent.Finding, []*ent.Command) (bool, string, error) {
		return true, "服务 active，与原故障直接对应", nil
	}}
	track := func(host, status string) (string, error) {
		return s.tool(ctx, session, commandgate.Request{System: true}, "track", []byte(
			`{"host":"`+host+`","key":"backup-failed","title":"备份服务失败","detail":"termix-backup-pull failed","severity":"medium","status":"`+status+`"}`))
	}
	get := func() string { return db.Finding.Query().OnlyX(ctx).Status }

	if out, err := track(host.ID.String(), "resolved"); err == nil {
		t.Fatalf("没有待办时标修复应报错：%s", out)
	}
	if out, err := track(host.ID.String(), "open"); err != nil || !strings.Contains(out, `"new":true`) {
		t.Fatalf("应新登记：%s %v", out, err)
	}
	if out, err := track(host.ID.String(), "open"); err != nil || !strings.Contains(out, `"reopened":false`) || db.Finding.Query().CountX(ctx) != 1 {
		t.Fatalf("同一问题应去重更新：%s %v", out, err)
	}
	check := db.Command.Create().SetAssetID(host.ID).SetKind("exec").SetCmd("systemctl is-active termix-backup-pull").SetStatus("succeeded").SetExitCode(0).SetStdout("active").SetCreatedAt(session.CreatedAt).SetCompletedAt(time.Now()).SaveX(ctx)
	if _, err := s.tool(ctx, session, commandgate.Request{System: true}, "track", []byte(
		`{"host":"`+host.ID.String()+`","key":"backup-failed","title":"备份服务已恢复","detail":"复查：termix-backup-pull active","severity":"medium","status":"resolved","evidence_commands":["`+check.ID.String()+`"]}`)); err != nil || get() != "resolved" {
		t.Fatalf("复查修复应关闭：%v %s", err, get())
	}
	if f := db.Finding.Query().OnlyX(ctx); f.ResolvedBy == nil || *f.ResolvedBy != commandgate.SystemActor ||
		f.Title != "备份服务已恢复" || f.Detail != "复查：termix-backup-pull active" {
		t.Errorf("AI 关闭应记 system 并更新复查后的标题与详情：%+v", f)
	}
	if out, err := track(host.ID.String(), "open"); err != nil || !strings.Contains(out, `"reopened":true`) || get() != "open" {
		t.Fatalf("复发应重开：%s %v", out, err)
	}

	db.Finding.Update().SetStatus("ignored").SetNote("计划下线，不处理").ExecX(ctx)
	if out, err := track(host.ID.String(), "open"); err != nil || !strings.Contains(out, `"ignored"`) || !strings.Contains(out, "计划下线") {
		t.Fatalf("忽略的待办应原样告知：%s %v", out, err)
	}
	if _, err := track(host.ID.String(), "resolved"); err != nil || get() != "ignored" {
		t.Fatalf("AI 不能改动人工忽略的待办：%s", get())
	}
	if _, err := track(stranger.ID.String(), "open"); err == nil {
		t.Fatal("别组主机不能登记")
	}

	// 不需要人处理的（info）与空 detail 拒绝登记
	for _, bad := range []string{
		`{"host":"` + host.ID.String() + `","key":"ok-record","title":"磁盘正常","detail":"无异常","severity":"info","status":"open"}`,
		`{"host":"` + host.ID.String() + `","key":"empty","title":"空","detail":"  ","severity":"low","status":"open"}`,
	} {
		if out, err := s.tool(ctx, session, commandgate.Request{System: true}, "track", []byte(bad)); err == nil {
			t.Errorf("应拒绝：%s → %s", bad, out)
		}
	}

	// 本轮登记错的可以撤回，遗留的不行；每轮最多新登记 maxNewFindings 条
	fresh := db.AgentSession.Create().SetKind("task").SetGroupID(group.ID).SetInitiator(commandgate.SystemActor).
		SetModel("m").SetStatus("running").SetTitle("巡检").SaveX(ctx)
	add := func(key, status string) error {
		_, err := s.tool(ctx, fresh, commandgate.Request{System: true}, "track", []byte(
			`{"host":"`+host.ID.String()+`","key":"`+key+`","title":"t","detail":"d","severity":"low","status":"`+status+`"}`))
		return err
	}
	db.Finding.Create().SetGroupID(group.ID).SetAssetID(host.ID).SetKey("legacy").SetTitle("上轮的").SetSessionID(session.ID).SaveX(ctx)
	if err := add("legacy", "withdrawn"); err == nil {
		t.Error("遗留待办不能撤回")
	}
	db.Finding.Delete().Where(finding.KeyEQ("legacy")).ExecX(ctx)
	if err := add("typo", "open"); err != nil {
		t.Fatal(err)
	}
	if err := add("typo", "withdrawn"); err != nil || db.Finding.Query().Where(finding.KeyEQ("typo")).ExistX(ctx) {
		t.Fatalf("本轮登记的应能撤回：%v", err)
	}
	for i := range maxNewFindings {
		if err := add(fmt.Sprintf("n%d", i), "open"); err != nil {
			t.Fatalf("第 %d 条不该被拦：%v", i, err)
		}
	}
	if err := add("one-more", "open"); err == nil {
		t.Error("超过上限应拒绝")
	}
	db.Finding.Delete().Where(finding.SessionIDEQ(fresh.ID)).ExecX(ctx)

	// 遗留、忽略与近期人工标为已处理（带说明）的待办随系统提示交给模型
	db.Finding.Create().SetGroupID(group.ID).SetAssetID(host.ID).SetKey("disk-full").SetTitle("磁盘将满").SaveX(ctx)
	db.Finding.Create().SetGroupID(group.ID).SetAssetID(host.ID).SetKey("token-verified").SetTitle("API Token 待核实").
		SetStatus("resolved").SetResolvedBy("admin").SetResolvedAt(time.Now()).SetNote("已确认 Secrux 验证授权").SaveX(ctx)
	r, err := s.request(context.Background(), session, "巡检", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.SystemPrompt, `"open_findings":[{"host":"`+host.ID.String()+`","hostname":"pve2","key":"disk-full"`) ||
		!strings.Contains(r.SystemPrompt, `"ignored_findings":[{`) || !strings.Contains(r.SystemPrompt, "计划下线") ||
		!strings.Contains(r.SystemPrompt, `"resolved_findings":[{"host":"`+host.ID.String()+`","hostname":"pve2","key":"token-verified"`) ||
		!strings.Contains(r.SystemPrompt, "已确认 Secrux 验证授权") {
		t.Errorf("待办数据缺失：%s", r.SystemPrompt)
	}
	// 交给 AI 的会话：绑定对象的当前状态随系统提示交给模型
	inc := db.Incident.Create().SetStatus("triaged").SetTitle("反弹 shell @ pve2").SetGraph([]byte(`{}`)).SaveX(ctx)
	db.Alert.Create().SetTs(time.Now()).SetRuleID("r").SetSeverity(5).SetAssetID(host.ID).SetIncidentID(inc.ID).SaveX(ctx)
	bound := db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("a").SetModel("m").SetStatus("idle").
		SetSubjects([]string{"incident:" + inc.ID.String(), "finding:" + uuid.NewString()}).SaveX(ctx)
	r, err = s.request(context.Background(), bound, "处理", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.SystemPrompt, `"subjects":[{`) || !strings.Contains(r.SystemPrompt, "反弹 shell @ pve2") || !strings.Contains(r.SystemPrompt, "结案建议") {
		t.Errorf("绑定对象未进系统提示：%s", r.SystemPrompt)
	}
	// 对话只围绕交过来的对象，遗留待办仅供参考，不带巡检的复查指令
	if !strings.Contains(r.SystemPrompt, "仅供参考") || strings.Contains(r.SystemPrompt, "巡检时逐条复查") {
		t.Errorf("对话会话不该要求复查遗留待办：%s", r.SystemPrompt)
	}
	if n := db.Finding.Query().Where(finding.StatusEQ("open")).CountX(ctx); n != 1 {
		t.Errorf("应只有一条遗留：%d", n)
	}
}

// 对话里代人忽略待办：只有组管理员发起的对话可以，定时任务与非管理员一律拒绝；落库与审计同控制台
func TestIgnoreFinding(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve2").SetGroupID(group.ID).SaveX(ctx)
	f := db.Finding.Create().SetGroupID(group.ID).SetAssetID(host.ID).SetKey("raid-bbu-failed").SetTitle("RAID 电池故障").SaveX(ctx)
	boss := db.User.Create().SetUsername("boss").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	member := db.GroupMember.Create().SetGroupID(group.ID).SetUserID(boss.ID).SetRole("admin").SaveX(ctx)
	ana := db.User.Create().SetUsername("ana").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	db.GroupMember.Create().SetGroupID(group.ID).SetUserID(ana.ID).SetRole("analyst").SaveX(ctx)
	chat := func(initiator string) *ent.AgentSession {
		return db.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator(initiator).SetModel("m").SetStatus("running").SaveX(ctx)
	}
	task := db.AgentSession.Create().SetKind("task").SetGroupID(group.ID).SetInitiator(commandgate.SystemActor).
		SetModel("m").SetStatus("running").SetTitle("巡检").SaveX(ctx)
	s := &Service{DB: db}
	args := []byte(`{"host":"` + host.ID.String() + `","key":"raid-bbu-failed","reason":"电池已订货，下周更换"}`)
	ignore := func(session *ent.AgentSession, who commandgate.Request) (string, error) {
		return s.tool(ctx, session, who, "ignore", args)
	}
	untouched := func() {
		t.Helper()
		if got := db.Finding.GetX(ctx, f.ID); got.Status != "open" || got.Note != nil {
			t.Fatalf("待办不该被改：%+v", got)
		}
	}

	if out, err := ignore(task, commandgate.Request{System: true}); err == nil || !strings.Contains(err.Error(), "定时任务") {
		t.Fatalf("定时任务必须拒绝并说明原因：%s %v", out, err)
	}
	untouched()
	if _, err := ignore(chat(ana.Username), commandgate.Request{UserID: ana.ID}); err == nil {
		t.Fatal("组内 analyst 发起的对话不能忽略")
	}
	untouched()
	if _, err := ignore(chat(ana.Username), commandgate.Request{UserID: boss.ID}); err == nil {
		t.Fatal("代办身份必须是会话发起人")
	}
	untouched()
	// 角色每次从库里取：降级后立即失效
	db.GroupMember.UpdateOne(member).SetRole("analyst").ExecX(ctx)
	if _, err := ignore(chat(boss.Username), commandgate.Request{UserID: boss.ID}); err == nil {
		t.Fatal("降级后不能再忽略")
	}
	untouched()
	db.GroupMember.UpdateOne(member).SetRole("admin").ExecX(ctx)

	session := chat(boss.Username)
	out, err := ignore(session, commandgate.Request{UserID: boss.ID})
	if err != nil || !strings.Contains(out, `"status":"ignored"`) {
		t.Fatalf("组管理员的对话应能忽略：%s %v", out, err)
	}
	got := db.Finding.GetX(ctx, f.ID)
	if got.Status != "ignored" || got.Note == nil || *got.Note != "电池已订货，下周更换" || got.ResolvedBy == nil || *got.ResolvedBy != "boss" {
		t.Fatalf("忽略应记在发起人名下并带理由：%+v", got)
	}
	logs := db.AuditLog.Query().Where(auditlog.ActionEQ("finding_status")).AllX(ctx)
	if len(logs) != 1 || logs[0].Username != "boss" || logs[0].Detail == nil ||
		!strings.Contains(*logs[0].Detail, "电池已订货") || !strings.Contains(*logs[0].Detail, session.ID.String()) {
		t.Fatalf("审计应记人、理由与会话：%+v", logs)
	}
	if out, err := ignore(session, commandgate.Request{UserID: boss.ID}); err != nil || !strings.Contains(out, `"already":true`) {
		t.Fatalf("已忽略的应原样告知：%s %v", out, err)
	}
	if _, err := s.tool(ctx, session, commandgate.Request{UserID: boss.ID}, "ignore",
		[]byte(`{"host":"`+host.ID.String()+`","key":"nope","reason":"x"}`)); err == nil {
		t.Error("没有的待办应报错")
	}
	if _, err := s.tool(ctx, session, commandgate.Request{UserID: boss.ID}, "ignore",
		[]byte(`{"host":"`+host.ID.String()+`","key":"raid-bbu-failed","reason":"  "}`)); err == nil {
		t.Error("空理由应拒绝")
	}
}
