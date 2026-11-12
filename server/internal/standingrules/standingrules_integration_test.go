//go:build integration

package standingrules_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/approval"
	"openxdr/server/ent/standingrule"
	"openxdr/server/ent/standingrulerun"
	"openxdr/server/internal/repaircmd"
	"openxdr/server/internal/repairpolicy"
	"openxdr/server/internal/standingrules"
	"openxdr/server/internal/testdb"
)

func TestStandingRulesLifecycleAndAutoDowngrade(t *testing.T) {
	ctx, db := testdb.New(t)
	if err := standingrules.SeedBuiltins(ctx, db); err != nil {
		t.Fatal(err)
	}
	// 再次执行保持幂等，且全部默认停用
	if err := standingrules.SeedBuiltins(ctx, db); err != nil {
		t.Fatal(err)
	}
	seeded := db.StandingRule.Query().AllX(ctx)
	if len(seeded) != 8 {
		t.Fatalf("应种子化 8 条内置规矩，实际 %d", len(seeded))
	}
	for _, r := range seeded {
		if r.Enabled {
			t.Fatalf("内置规矩 %s 必须默认停用", r.BuiltinKey)
		}
	}

	grp := db.Group.Create().SetName("prod").SaveX(ctx)
	osLinux := "linux"
	agentID := uuid.New()
	host1 := db.Asset.Create().SetHostname("app-1").SetGroupID(grp.ID).SetOs(osLinux).SetAgentID(agentID).SetLastSeen(time.Now()).SaveX(ctx)
	host2 := db.Asset.Create().SetHostname("app-2").SetGroupID(grp.ID).SetOs(osLinux).SetAgentID(uuid.New()).SetLastSeen(time.Now()).SaveX(ctx)

	// 1. human 档：命中后待办直接进入人工队列
	staleRule := db.StandingRule.Query().Where(standingrule.BuiltinKeyEQ(standingrules.TplStaleConnArchive)).OnlyX(ctx)
	db.StandingRule.UpdateOneID(staleRule.ID).SetEnabled(true).ExecX(ctx)
	fHuman := db.Finding.Create().SetGroupID(grp.ID).SetAssetID(host1.ID).SetKey("ssh-stale").SetTitle("发现废弃密钥与失效连接配置").SaveX(ctx)

	repair := &repairpolicy.Store{DB: db}
	var failExec bool
	dfStep := 0
	runner := &standingrules.Runner{
		DB:     db,
		Repair: repair,
		IssueAndWait: func(ctx context.Context, a *ent.Asset, cmd, issuedBy string, _ time.Duration, onIssued func(*ent.Command) error) (*ent.Command, error) {
			now := time.Now()
			code := int32(0)
			out := ""
			switch {
			case strings.Contains(cmd, "APT_KB|"):
				out = "APT_KB|20480\nArchived and active journals take up 640.0M in the file system.\n"
			case cmd == "df -P /":
				dfStep++
				avail := 200000 + dfStep*10000
				used := 1000000 - avail
				pct := (used*100 + 999999) / 1000000
				out = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 1000000 " + itoa(used) + " " + itoa(avail) + " " + itoa(pct) + "% /\n"
			case strings.Contains(cmd, "MEM_KB|"):
				out = "MEM_KB|2097152\nSWAP_KB|0\nROOT_AVAIL_KB|8388608\n"
			default:
				if failExec {
					code = 1
					c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetIssuedBy(issuedBy).SetCmd(cmd).SetStatus("failed").SetExitCode(code).SetCompletedAt(now).SaveX(ctx)
					if onIssued != nil {
						_ = onIssued(c)
					}
					return c, errors.New("模拟执行错误")
				}
				out = "done\n"
			}
			c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetIssuedBy(issuedBy).SetCmd(cmd).SetStatus("succeeded").SetExitCode(code).SetStdout(out).SetCreatedAt(now.Add(-5 * time.Millisecond)).SetCompletedAt(now).SaveX(ctx)
			if onIssued != nil {
				if err := onIssued(c); err != nil {
					return c, err
				}
			}
			return c, nil
		},
	}

	if err := runner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	fHuman = db.Finding.GetX(ctx, fHuman.ID)
	if fHuman.WorkOwner != "human" {
		t.Fatalf("human 档应将待办转交 human，实际 %s", fHuman.WorkOwner)
	}

	// 2. propose 档：生成 Approval，批准后原子消费并执行
	swapRule := db.StandingRule.Query().Where(standingrule.BuiltinKeyEQ(standingrules.TplLowMemAddSwap)).OnlyX(ctx)
	db.StandingRule.UpdateOneID(swapRule.ID).SetEnabled(true).SetMaintenanceWindow("").ExecX(ctx)
	_ = db.Finding.Create().SetGroupID(grp.ID).SetAssetID(host1.ID).SetKey("no-swap").SetTitle("低内存主机无 swap").SaveX(ctx)
	if err := runner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	pRun := db.StandingRuleRun.Query().Where(standingrulerun.RuleIDEQ(swapRule.ID)).OnlyX(ctx)
	if pRun.Status != standingrulerun.StatusPendingApproval || pRun.ApprovalID == nil {
		t.Fatalf("propose 档应处于 pending_approval: %+v", pRun)
	}
	db.Approval.UpdateOneID(*pRun.ApprovalID).SetStatus(approval.StatusApproved).SetDecidedBy("zachary").SetDecidedAt(time.Now()).ExecX(ctx)
	if err := runner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	pRun = db.StandingRuleRun.GetX(ctx, pRun.ID)
	app := db.Approval.GetX(ctx, *pRun.ApprovalID)
	if pRun.Status != standingrulerun.StatusSucceeded || app.Status != approval.StatusConsumed {
		t.Fatalf("批准后应消费并成功执行: run=%s approval=%s", pRun.Status, app.Status)
	}

	// 3. auto 档成功执行 + 连续两次失败自动降级为 propose
	cleanRule := db.StandingRule.Query().Where(standingrule.BuiltinKeyEQ(standingrules.TplPkgJournalClean)).OnlyX(ctx)
	db.StandingRule.UpdateOneID(cleanRule.ID).SetEnabled(true).ExecX(ctx)
	_ = db.Finding.Create().SetGroupID(grp.ID).SetAssetID(host1.ID).SetKey("disk-full-1").SetTitle("根盘空间使用率过高").SaveX(ctx)
	if err := runner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	aRun := db.StandingRuleRun.Query().Where(standingrulerun.RuleIDEQ(cleanRule.ID)).OnlyX(ctx)
	if aRun.Status != standingrulerun.StatusSucceeded || !strings.Contains(aRun.Result, "df -P") {
		t.Fatalf("auto 档应成功并带 df -P 核验: %+v", aRun)
	}

	// 模拟在另一主机（及清掉冷却后）连续两次执行失败 -> 自动降级为 propose
	failExec = true
	_ = db.Finding.Create().SetGroupID(grp.ID).SetAssetID(host2.ID).SetKey("disk-full-2").SetTitle("磁盘容量不足").SaveX(ctx)
	if err := runner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	db.Setting.Delete().ExecX(ctx) // 清冷却以模拟下一次命中再次出错
	_ = db.Finding.Create().SetGroupID(grp.ID).SetAssetID(host2.ID).SetKey("disk-full-3").SetTitle("磁盘空间告警").SaveX(ctx)
	if err := runner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	cleanRule = db.StandingRule.GetX(ctx, cleanRule.ID)
	if cleanRule.Tier != standingrule.TierPropose || cleanRule.DegradedAt == nil || cleanRule.ConsecutiveFailures < 2 {
		t.Fatalf("连续出错后应自动降级为 propose: tier=%s degraded=%v failures=%d", cleanRule.Tier, cleanRule.DegradedAt, cleanRule.ConsecutiveFailures)
	}

	// 4. 探针失败落 skipped 记录并在 skipDedupWindow 内去重，且不计入连续出错；同时校验每轮下发上限与 ReserveStanding 目录边界
	db.StandingRule.Update().SetEnabled(false).ExecX(ctx)
	backupRule := db.StandingRule.Query().Where(standingrule.BuiltinKeyEQ(standingrules.TplOldBackupCompress)).OnlyX(ctx)
	db.StandingRule.UpdateOneID(backupRule.ID).SetEnabled(true).SetMaintenanceWindow("").ExecX(ctx)

	bCmd, _, ok := repaircmd.FormatBackupCompress("/var/backups", []string{"/var/backups/db.sql"})
	if !ok {
		t.Fatal("构造测试备份压缩命令失败")
	}
	dfOut := "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 1000000 800000 200000 80% /\n"
	nowProbe := time.Now()
	dfProbe := db.Command.Create().SetAssetID(host1.ID).SetKind("exec").SetIssuedBy("test").SetCmd("df -P /").SetStatus("succeeded").SetExitCode(0).SetStdout(dfOut).SetCreatedAt(nowProbe.Add(-time.Second)).SetCompletedAt(nowProbe).SaveX(ctx)
	if _, err := repair.ReserveStanding(ctx, repairpolicy.StandingRequest{
		RuleID:          backupRule.ID,
		RuleVersion:     "v1",
		GroupID:         grp.ID,
		AssetID:         host1.ID,
		Unit:            repairpolicy.ReclaimDisk,
		Command:         bCmd,
		Mount:           "/",
		AllowedPaths:    []string{"/srv/backups"},
		BeforeProbeID:   dfProbe.ID,
		CooldownMinutes: 360,
	}); err == nil {
		t.Fatal("ReserveStanding 应拒绝不在规矩 AllowedPaths 内的备份文件压缩")
	}

	probeCalls := 0
	simNow := time.Now()
	probeRunner := &standingrules.Runner{
		DB:                db,
		Repair:            repair,
		Now:               func() time.Time { return simNow },
		MaxHostDispatches: 1,
		IssueAndWait: func(ctx context.Context, a *ent.Asset, cmd, issuedBy string, _ time.Duration, _ func(*ent.Command) error) (*ent.Command, error) {
			probeCalls++
			return nil, errors.New("主机探针超时")
		},
	}
	fProbe1 := db.Finding.Create().SetGroupID(grp.ID).SetAssetID(host1.ID).SetKey("backup-1").SetTitle("备份目录空间告警 1").SaveX(ctx)
	fProbe2 := db.Finding.Create().SetGroupID(grp.ID).SetAssetID(host2.ID).SetKey("backup-2").SetTitle("备份目录空间告警 2").SaveX(ctx)
	if err := probeRunner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if probeCalls != 1 {
		t.Fatalf("MaxHostDispatches=1 应将首轮探针限制为 1 次，实际 %d", probeCalls)
	}
	if err := probeRunner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if probeCalls != 2 {
		t.Fatalf("第二轮应只处理剩余第 2 条待办且第 1 条命中 skipped 去重，累计应为 2，实际 %d", probeCalls)
	}
	if err := probeRunner.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if probeCalls != 2 {
		t.Fatalf("skipDedupWindow 内重复 Tick 不应再次下发探针，实际 %d", probeCalls)
	}
	backupRule = db.StandingRule.GetX(ctx, backupRule.ID)
	if backupRule.ConsecutiveFailures != 0 || backupRule.Tier != standingrule.TierAuto {
		t.Fatalf("探针失败不应计入连续出错或触发降级: %+v", backupRule)
	}
	_ = fProbe1
	_ = fProbe2
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
