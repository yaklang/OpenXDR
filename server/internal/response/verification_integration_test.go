//go:build integration

package response

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
	"os"
	"testing"
	"time"
)

func TestVerificationEvidenceAuditAndScope(t *testing.T) {
	ctx, c := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := EnsureVerificationSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	g := c.Group.Create().SetName("verify-a").SaveX(ctx)
	b := c.Group.Create().SetName("verify-b").SaveX(ctx)
	a := c.Asset.Create().SetHostname("verify-host").SetGroupID(g.ID).SaveX(ctx)
	other := c.Asset.Create().SetHostname("other-host").SetGroupID(g.ID).SaveX(ctx)
	u := c.User.Create().SetUsername("reviewer").SetPasswordHash("unused").SetRole("analyst").SaveX(ctx)
	m := c.GroupMember.Create().SetGroupID(g.ID).SetUserID(u.ID).SetRole("analyst").SaveX(ctx)
	admin := c.User.Create().SetUsername("verify-admin").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	issued := time.Now().Add(-time.Hour)
	cmd := c.Command.Create().SetAssetID(a.ID).SetKind("isolate_host").SetStatus("unknown").SetCreatedAt(issued).SaveX(ctx)
	event := func(asset uuid.UUID, ts time.Time) uuid.UUID {
		return c.Event.Create().SetAssetID(asset).SetTs(ts).SetSource("agent").SetClassUID(4001).SetRaw(json.RawMessage(`{"connection":"test-evidence"}`)).SaveX(ctx).ID
	}
	good := event(a.ID, issued.Add(time.Minute))
	in := VerificationInput{Outcome: "inconclusive", Expected: "隔离后的策略生效", Observed: "连接日志不足以判断策略效果", EventIDs: []uuid.UUID{good}}
	v, err := RecordVerification(ctx, db, u.ID, cmd.ID, "10.0.0.8", in)
	if err != nil {
		t.Fatal(err)
	}
	if v.Reviewer != u.Username || v.CommandStatus != "unknown" || len(v.Evidence) != 1 || v.GroupID == nil || *v.GroupID != g.ID {
		t.Fatalf("字段丢失: %+v", v)
	}
	if got := c.Command.GetX(ctx, cmd.ID); got.Status != "unknown" || got.CompletedAt != nil {
		t.Fatal("复核覆盖执行回执")
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='command_verification_recorded' AND target=$1 AND remote_addr='10.0.0.8'`, cmd.ID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("审计缺失: %d %v", count, err)
	}
	for _, bad := range []uuid.UUID{uuid.New(), event(other.ID, issued.Add(time.Minute)), event(a.ID, issued.Add(-time.Minute)), event(a.ID, time.Now().Add(time.Hour))} {
		x := in
		x.EventIDs = []uuid.UUID{bad}
		if _, err := RecordVerification(ctx, db, u.ID, cmd.ID, "10.0.0.8", x); !errors.Is(err, ErrVerificationInput) {
			t.Fatalf("接受无效证据: %v", err)
		}
	}
	c.Event.DeleteOneID(good).ExecX(ctx)
	check := func(user uuid.UUID, want int) []Verification {
		t.Helper()
		items, err := ListVerifications(ctx, db, user, cmd.ID)
		if err != nil || len(items) != want {
			t.Fatalf("列表 %d/%d: %v", len(items), want, err)
		}
		return items
	}
	if items := check(u.ID, 1); len(items[0].Evidence) != 1 || len(items[0].Evidence[0].Raw) != 0 {
		t.Fatal("列表应保留证据元数据且不展开原文")
	}
	empty := VerificationInput{Outcome: "inconclusive", Expected: "check", Observed: "unknown"}
	var retained string
	if err := db.QueryRow(`SELECT evidence->0->'raw'->>'connection' FROM command_verifications WHERE id=$1`, v.ID).Scan(&retained); err != nil || retained != "test-evidence" {
		t.Fatalf("证据快照丢失: %v", err)
	}

	detail, err := GetVerification(ctx, db, u.ID, cmd.ID, v.ID)
	if err != nil || len(detail.Evidence) != 1 || string(detail.Evidence[0].Raw) == "" {
		t.Fatalf("授权证据原文读取失败: %v", err)
	}
	if _, err := GetVerification(ctx, db, u.ID, uuid.New(), v.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("跨指令引用复核")
	}
	if _, err := GetVerification(ctx, db, u.ID, cmd.ID, uuid.New()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("不存在复核未拒绝")
	}
	c.GroupMember.UpdateOne(m).SetRole("viewer").ExecX(ctx)
	if _, err := RecordVerification(ctx, db, u.ID, cmd.ID, "10.0.0.8", empty); !errors.Is(err, ErrVerificationScope) {
		t.Fatal("viewer 写入")
	}
	c.Asset.UpdateOneID(a.ID).SetGroupID(b.ID).ExecX(ctx)
	check(u.ID, 0)
	if _, err := GetVerification(ctx, db, u.ID, cmd.ID, v.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("组外证据原文泄露")
	}
	c.GroupMember.DeleteOne(m).ExecX(ctx)
	c.GroupMember.Create().SetGroupID(b.ID).SetUserID(u.ID).SetRole("analyst").SaveX(ctx)
	check(u.ID, 0)
	if _, err := GetVerification(ctx, db, u.ID, cmd.ID, v.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("组外证据原文泄露")
	}
	check(admin.ID, 1)
	if _, err := GetVerification(ctx, db, admin.ID, cmd.ID, v.ID); err != nil {
		t.Fatalf("管理员无法读取原文: %v", err)
	}
	_, err = db.Exec(`ALTER TABLE audit_logs ADD CONSTRAINT reject_verification_test CHECK (action <> 'command_verification_recorded') NOT VALID`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(`ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS reject_verification_test`) })
	if _, err := RecordVerification(ctx, db, u.ID, cmd.ID, "10.0.0.8", empty); err == nil {
		t.Fatal("审计失败未阻断")
	}
	check(admin.ID, 1)
	if _, err := GetVerification(ctx, db, admin.ID, cmd.ID, v.ID); err != nil {
		t.Fatalf("管理员无法读取原文: %v", err)
	}
	if _, err := db.Exec(`ALTER TABLE audit_logs DROP CONSTRAINT reject_verification_test`); err != nil {
		t.Fatal(err)
	}
	c.Asset.UpdateOneID(a.ID).ClearGroupID().ExecX(ctx)
	if _, err := RecordVerification(ctx, db, u.ID, cmd.ID, "10.0.0.8", empty); !errors.Is(err, ErrVerificationScope) {
		t.Fatal("未分组越权")
	}
	if _, err := RecordVerification(ctx, db, admin.ID, cmd.ID, "10.0.0.8", empty); err != nil {
		t.Fatal(err)
	}
}

func TestMachineVerificationFailClosedAndAutoVerify(t *testing.T) {
	ctx, c := testdb.New(t)
	db, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureVerificationSchema(ctx, db); err != nil {
		t.Fatal(err)
	}

	g := c.Group.Create().SetName("verify-machine").SaveX(ctx)
	otherGroup := c.Group.Create().SetName("verify-other").SaveX(ctx)
	host := c.Asset.Create().SetHostname("verify-endpoint").SetGroupID(g.ID).SaveX(ctx)
	admin := c.User.Create().SetUsername("machine-admin").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)

	issued := time.Now().UTC().Add(-10 * time.Minute)
	targetGUID := uuid.New()
	otherGUID := uuid.New()

	killCmd := c.Command.Create().
		SetAssetID(host.ID).SetKind("kill_process").SetStatus("succeeded").
		SetPid(42).SetProcessGUID(targetGUID).SetCreatedAt(issued).SetCompletedAt(issued.Add(time.Second)).SaveX(ctx)
	blockCmd := c.Command.Create().
		SetAssetID(host.ID).SetKind("block_network").SetTarget("198.51.100.9").SetStatus("succeeded").
		SetCreatedAt(issued).SetCompletedAt(issued.Add(time.Second)).SaveX(ctx)
	isoCmd := c.Command.Create().
		SetAssetID(host.ID).SetKind("isolate_host").SetStatus("succeeded").
		SetCreatedAt(issued).SetCompletedAt(issued.Add(time.Second)).SaveX(ctx)

	session := c.AgentSession.Create().
		SetKind("chat").SetGroupID(g.ID).SetInitiator("analyst").SetModel("test").
		SetStatus("running").SetRunExpiresAt(time.Now().UTC().Add(time.Hour)).SaveX(ctx)

	// 1. 来源冒充拒绝：不能用 RecordMachineVerification 写 human 或 manual_review
	if _, err := RecordMachineVerification(ctx, db, MachineVerificationInput{
		CommandID: killCmd.ID, GroupID: g.ID, Source: "human", Method: "manual_review",
		Outcome: "inconclusive", Expected: "e", Observed: "o",
	}); !errors.Is(err, ErrVerificationInput) {
		t.Fatalf("应拒绝伪造 human 来源: %v", err)
	}

	// 2. 五类负例：子串 PID/父 PID、备注里的 GUID、任意网络/文件事件提及目标、isolate_host 任意 raw 均拒绝记 effective
	evParentPID := c.Event.Create().SetAssetID(host.ID).SetTs(issued.Add(time.Minute)).SetSource("agent").SetClassUID(1007).
		SetProcessGUID(targetGUID).SetRaw(json.RawMessage(`{"activity_id":2,"process":{"pid":142,"parent_process":{"pid":42}}}`)).SaveX(ctx).ID
	evGUIDInComment := c.Event.Create().SetAssetID(host.ID).SetTs(issued.Add(time.Minute)).SetSource("agent").SetClassUID(1007).
		SetProcessGUID(otherGUID).SetRaw(json.RawMessage(`{"activity_id":2,"process":{"pid":42},"note":"` + targetGUID.String() + `"}`)).SaveX(ctx).ID
	evNetMention := c.Event.Create().SetAssetID(host.ID).SetTs(issued.Add(time.Minute)).SetSource("agent").SetClassUID(4001).
		SetRaw(json.RawMessage(`{"dst_endpoint":{"ip":"198.51.100.9"}}`)).SaveX(ctx).ID
	evIsoRaw := c.Event.Create().SetAssetID(host.ID).SetTs(issued.Add(time.Minute)).SetSource("agent").SetClassUID(5001).
		SetRaw(json.RawMessage(`{"inventory":"ok"}`)).SaveX(ctx).ID

	for _, tc := range []struct {
		name string
		cmd  uuid.UUID
		ev   uuid.UUID
	}{
		{"wrong_pid_contains_42", killCmd.ID, evParentPID},
		{"guid_only_in_raw_note", killCmd.ID, evGUIDInComment},
		{"network_mentions_ip", blockCmd.ID, evNetMention},
		{"isolate_arbitrary_raw", isoCmd.ID, evIsoRaw},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RecordMachineVerification(ctx, db, MachineVerificationInput{
				CommandID: tc.cmd, GroupID: g.ID, Source: "ai", SessionID: &session.ID,
				Method: "telemetry_post_action", Outcome: "effective",
				Expected: "处置生效", Observed: "伪正向证据", EventIDs: []uuid.UUID{tc.ev},
			}); !errors.Is(err, ErrVerificationInput) {
				t.Fatalf("%s 应被拒绝为非确定性证据: %v", tc.name, err)
			}
		})
	}

	// 3. 下发前退出事件：不能塞入 EventIDs，只能进 ContextEventIDs 且结论必须为 inconclusive
	preExit := c.Event.Create().SetAssetID(host.ID).SetTs(issued.Add(-time.Minute)).SetSource("agent").SetClassUID(1007).
		SetProcessGUID(targetGUID).SetRaw(json.RawMessage(`{"activity_id":2,"process":{"pid":42}}`)).SaveX(ctx).ID
	if _, err := RecordMachineVerification(ctx, db, MachineVerificationInput{
		CommandID: killCmd.ID, GroupID: g.ID, Source: "ai", SessionID: &session.ID,
		Method: "context_only", Outcome: "effective",
		Expected: "e", Observed: "o", ContextEventIDs: []uuid.UUID{preExit},
	}); !errors.Is(err, ErrVerificationInput) {
		t.Fatalf("下发前退出不能记为 effective: %v", err)
	}
	vCtx, err := RecordMachineVerification(ctx, db, MachineVerificationInput{
		CommandID: killCmd.ID, GroupID: g.ID, Source: "ai", SessionID: &session.ID,
		Method: "context_only", Outcome: "inconclusive",
		Expected: "核对进程状态", Observed: "进程在下发前已退出", ContextEventIDs: []uuid.UUID{preExit},
	})
	if err != nil || vCtx.Source != "ai" || vCtx.Reviewer != "ai:session:"+session.ID.String() || len(vCtx.Context) != 1 {
		t.Fatalf("上下文归档验证异常: %+v %v", vCtx, err)
	}

	// 4. 跨组会话与已失效会话拒绝写入
	foreignSession := c.AgentSession.Create().SetKind("chat").SetGroupID(otherGroup.ID).SetInitiator("analyst").SetModel("test").SetStatus("running").SaveX(ctx)
	if _, err := RecordMachineVerification(ctx, db, MachineVerificationInput{
		CommandID: killCmd.ID, GroupID: g.ID, Source: "ai", SessionID: &foreignSession.ID,
		Method: "ai_investigation", Outcome: "inconclusive", Expected: "e", Observed: "o",
	}); !errors.Is(err, ErrVerificationScope) {
		t.Fatalf("跨组会话应被拒绝: %v", err)
	}

	// 5. 自动核验闭环：先无下发后退出事件 -> 记 1 条 system inconclusive（含下发前退出上下文），重复调用不膨胀；
	//    随后到达真实结构化退出事件（source=agent, class_uid=1007, process_guid=targetGUID, pid=42, activity_id=2）-> 自动升级补记 1 条 effective，后续不再重复。
	if err := AutoVerifyCommands(ctx, db, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := AutoVerifyCommands(ctx, db, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	items, err := ListVerifications(ctx, db, admin.ID, killCmd.ID)
	if err != nil || len(items) != 2 { // 1 条 AI + 1 条 system inconclusive
		t.Fatalf("自动核验幂等数量异常: len=%d err=%v", len(items), err)
	}

	realExit := c.Event.Create().SetAssetID(host.ID).SetTs(issued.Add(2 * time.Minute)).SetSource("agent").SetClassUID(1007).
		SetProcessGUID(targetGUID).SetRaw(json.RawMessage(`{"activity_id":2,"process":{"pid":42}}`)).SaveX(ctx).ID
	if err := AutoVerifyCommands(ctx, db, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := AutoVerifyCommands(ctx, db, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	items, err = ListVerifications(ctx, db, admin.ID, killCmd.ID)
	if err != nil || len(items) != 3 {
		t.Fatalf("退出事件到达后应升级 1 条 effective 且不再重复: len=%d err=%v", len(items), err)
	}
	if items[0].Source != "system" || items[0].Outcome != "effective" || len(items[0].Evidence) != 1 || items[0].Evidence[0].ID != realExit {
		t.Fatalf("最新自动核验记录应为 effective 并绑定真实退出事件: %+v", items[0])
	}

	// 6. unknown 指令拒绝一切非 inconclusive 结论（包括 ineffective）
	unknownCmd := c.Command.Create().SetAssetID(host.ID).SetKind("kill_process").SetStatus("unknown").
		SetPid(42).SetProcessGUID(targetGUID).SetCreatedAt(issued).SaveX(ctx)
	if _, err := RecordMachineVerification(ctx, db, MachineVerificationInput{
		CommandID: unknownCmd.ID, GroupID: g.ID, Source: "ai", SessionID: &session.ID,
		Method: "telemetry_post_action", Outcome: "ineffective",
		Expected: "e", Observed: "o", EventIDs: []uuid.UUID{realExit},
	}); !errors.Is(err, ErrVerificationInput) {
		t.Fatalf("unknown 指令不得记录 ineffective: %v", err)
	}

	// 7. 24h 内 >100 条指令全覆盖且重复调用不增行
	var batchIDs []uuid.UUID
	for i := 0; i < 105; i++ {
		ts := issued.Add(time.Duration(i) * time.Second)
		bc := c.Command.Create().SetAssetID(host.ID).SetKind("block_network").SetStatus("succeeded").
			SetTarget("198.51.100.1").SetCreatedAt(ts).SetCompletedAt(ts.Add(time.Second)).SaveX(ctx)
		batchIDs = append(batchIDs, bc.ID)
	}
	if err := AutoVerifyCommands(ctx, db, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var beforeTotal int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM command_verifications WHERE source = 'system'`).Scan(&beforeTotal); err != nil {
		t.Fatal(err)
	}
	if err := AutoVerifyCommands(ctx, db, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var afterTotal int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM command_verifications WHERE source = 'system'`).Scan(&afterTotal); err != nil {
		t.Fatal(err)
	}
	if beforeTotal != afterTotal {
		t.Fatalf("重复调用 AutoVerifyCommands 不得新增记录: before=%d after=%d", beforeTotal, afterTotal)
	}
	// 最早与最晚的指令均已被覆盖
	for _, checkID := range []uuid.UUID{batchIDs[0], batchIDs[len(batchIDs)-1]} {
		list, err := ListVerifications(ctx, db, admin.ID, checkID)
		if err != nil || len(list) != 1 || list[0].Source != "system" {
			t.Fatalf(">100 条指令应全部被覆盖且无饥饿: id=%s len=%d err=%v", checkID, len(list), err)
		}
	}
}
