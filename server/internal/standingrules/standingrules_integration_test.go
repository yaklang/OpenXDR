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
