package standingrules

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/standingrule"
	"openxdr/server/internal/repaircmd"
	"openxdr/server/internal/repairpolicy"
)

func TestBuiltinCatalogCompletenessAndTierBounds(t *testing.T) {
	all := Templates()
	builtins := 0
	byKey := map[string]Template{}
	for _, tpl := range all {
		byKey[tpl.Key] = tpl
		if tpl.Builtin {
			builtins++
		}
	}
	if builtins != 8 {
		t.Fatalf("内置规矩数量应为 8，实际为 %d", builtins)
	}
	if got := byKey[TplStaleConnArchive]; len(got.AllowedTiers) != 1 || got.AllowedTiers[0] != "human" || got.DefaultTier != "human" {
		t.Fatalf("stale_conn_archive 必须固定为 human 档: %+v", got)
	}
	for _, k := range []string{TplLowMemAddSwap, TplExpiredNeverLogin, TplSystemdCrashLoop, TplMgmtPortRestrict} {
		for _, tier := range byKey[k].AllowedTiers {
			if tier == "auto" {
				t.Errorf("%s 不应允许设为 auto 档", k)
			}
		}
	}
	for _, k := range []string{TplDockerUnused7d, TplPkgJournalClean, TplOldBackupCompress} {
		if byKey[k].DefaultTier != "auto" {
			t.Errorf("%s 默认档位应为 auto，实际为 %s", k, byKey[k].DefaultTier)
		}
	}
}

func TestValidateInputEnforcesBoundaries(t *testing.T) {
	ctx := context.Background()
	if err := ValidateInput(ctx, nil, RuleInput{
		Name:             "违规设 auto",
		ConditionSummary: "测试",
		ActionTemplate:   TplLowMemAddSwap,
		Tier:             "auto",
		CooldownMinutes:  360,
	}); err == nil {
		t.Fatal("low_mem_add_swap 设为 auto 应被拒绝")
	}

	if err := ValidateInput(ctx, nil, RuleInput{
		Name:             "管理端口全开未配网段即启用",
		ConditionSummary: "测试",
		ActionTemplate:   TplMgmtPortRestrict,
		Tier:             "propose",
		CooldownMinutes:  360,
		Enabled:          true,
		ActionParams:     map[string]any{"ports": []int{8006}, "allowed_cidrs": []string{}},
	}); err == nil {
		t.Fatal("启用 mgmt_port_restrict 但未配 allowed_cidrs 应被拒绝")
	}

	if err := ValidateInput(ctx, nil, RuleInput{
		Name:             "管理端口限制",
		ConditionSummary: "测试",
		ActionTemplate:   TplMgmtPortRestrict,
		Tier:             "propose",
		CooldownMinutes:  360,
		Enabled:          true,
		ActionParams:     map[string]any{"ports": []int{8006}, "allowed_cidrs": []string{"10.8.0.0/24"}},
	}); err != nil {
		t.Fatalf("合法 mgmt_port_restrict 被拒绝: %v", err)
	}

	gid := uuid.New()
	if err := ValidateInput(ctx, nil, RuleInput{
		Name:             "尝试重启核心服务",
		ConditionSummary: "测试",
		ActionTemplate:   TplRestartFailedService,
		Tier:             "auto",
		GroupID:          &gid,
		AssetIDs:         []uuid.UUID{uuid.New()},
		CooldownMinutes:  180,
		ActionParams:     map[string]any{"units": []string{"postgresql.service"}},
	}); err == nil {
		t.Fatal("核心服务 postgresql.service 应被拒绝")
	}
}

func TestBuildPlansAndRollbacks(t *testing.T) {
	now := time.Date(2026, 11, 13, 3, 0, 0, 0, time.UTC)
	anonOld := strings.Repeat("b2", 32)
	anonNew := strings.Repeat("c3", 32)

	dockerRule := &ent.StandingRule{ActionTemplate: TplDockerUnused7d, ActionParams: map[string]any{"mount": "/"}}
	dockerProbe := strings.Join([]string{
		"IMG|nginx:1.25|sha256:111|2026-10-01 10:00:00 +0000 UTC",
		"IMG|redis:7|sha256:222|2026-10-01 10:00:00 +0000 UTC",
		"CTR|redis:7",
		"VOL|" + anonOld + "|2026-10-01T10:00:00Z",
		"VOL|" + anonNew + "|2026-11-12T10:00:00Z",
		"VOL|named_pgdata|2026-09-01T10:00:00Z",
		"DF|Build Cache|1.2GB",
	}, "\n")
	plan, err := BuildPlan(dockerRule, nil, dockerProbe, now)
	if err != nil || !plan.Applicable || !repaircmd.IsStandingDiskAction(plan.Command) {
		t.Fatalf("docker 方案构建失败: %+v err=%v", plan, err)
	}
	if !strings.Contains(plan.Command, anonOld) || strings.Contains(plan.Command, anonNew) || strings.Contains(plan.Command, "named_pgdata") {
		t.Fatalf("docker 卷过滤错误: %s", plan.Command)
	}
	if !strings.Contains(plan.Rollback, "docker pull nginx:1.25") || strings.Contains(plan.Rollback, "redis:7") {
		t.Fatalf("docker 回退镜像列表错误: %s", plan.Rollback)
	}

	backupRule := &ent.StandingRule{
		ActionTemplate: TplOldBackupCompress,
		ActionParams:   map[string]any{"paths": []string{"/var/backups"}, "min_age_days": 7, "mount": "/"},
	}
	backupPlan, err := BuildPlan(backupRule, nil, "/var/backups/app-2026-10-01.sql\n/var/backups/already.tar.gz\n/etc/shadow\n", now)
	if err != nil || !backupPlan.Applicable {
		t.Fatalf("备份压缩方案失败: %+v err=%v", backupPlan, err)
	}
	if !strings.Contains(backupPlan.Command, "gzip -9 -k -- /var/backups/app-2026-10-01.sql") ||
		!strings.Contains(backupPlan.Command, "gzip -t -- /var/backups/app-2026-10-01.sql.gz") ||
		strings.Contains(backupPlan.Command, "/etc/shadow") ||
		backupPlan.Rollback != "gzip -d -- /var/backups/app-2026-10-01.sql.gz" {
		t.Fatalf("备份压缩安全边界或回退不符: %+v", backupPlan)
	}

	swapRule := &ent.StandingRule{ActionTemplate: TplLowMemAddSwap, ActionParams: map[string]any{"swap_size_gb": 2}}
	swapPlan, err := BuildPlan(swapRule, nil, "MEM_KB|2048000\nSWAP_KB|0\nROOT_AVAIL_KB|10485760\n", now)
	if err != nil || !swapPlan.Applicable || !strings.Contains(swapPlan.Command, "fallocate -l 2G /swapfile") || !strings.Contains(swapPlan.Rollback, "swapoff /swapfile") {
		t.Fatalf("swap 提议方案不符: %+v err=%v", swapPlan, err)
	}

	acctRule := &ent.StandingRule{ActionTemplate: TplExpiredNeverLogin}
	acctPlan, err := BuildPlan(acctRule, &ent.Finding{Title: "发现过期账号 legacy_ops 从未登录"}, "EXPIRED_USER|legacy_ops\nEXPIRED_USER|root\n", now)
	if err != nil || !acctPlan.Applicable || acctPlan.Command != "usermod -L -- legacy_ops" || acctPlan.Rollback != "usermod -U -- legacy_ops" {
		t.Fatalf("账号锁定提议不符: %+v err=%v", acctPlan, err)
	}

	crashRule := &ent.StandingRule{ActionTemplate: TplSystemdCrashLoop, ActionParams: map[string]any{"min_restarts": 5}}
	crashPlan, err := BuildPlan(crashRule, &ent.Finding{Title: "worker-sync.service 持续崩溃重启"}, "Id=worker-sync.service\nActiveState=activating\nNRestarts=12\nUnitFileState=enabled\n", now)
	if err != nil || !crashPlan.Applicable || crashPlan.Command != "systemctl disable --now -- worker-sync.service" || crashPlan.Rollback != "systemctl enable --now -- worker-sync.service" {
		t.Fatalf("systemd 崩溃循环提议不符: %+v err=%v", crashPlan, err)
	}

	mgmtRule := &ent.StandingRule{
		ActionTemplate: TplMgmtPortRestrict,
		ActionParams:   map[string]any{"ports": []int{8006}, "allowed_cidrs": []string{"10.8.0.0/24"}},
	}
	ssOut := "LISTEN 0 4096 0.0.0.0:8006 0.0.0.0:* users:((\"pveproxy\",pid=1200,fd=6))\n"
	mgmtPlan, err := BuildPlan(mgmtRule, &ent.Finding{Title: "管理端口 8006 对内网全开"}, ssOut, now)
	if err != nil || !mgmtPlan.Applicable || !strings.Contains(mgmtPlan.Command, "OPENXDR_MGMT_8006") || !strings.Contains(mgmtPlan.Command, "-s 10.8.0.0/24 -j RETURN") || !strings.Contains(mgmtPlan.Rollback, "iptables -X OPENXDR_MGMT_8006") {
		t.Fatalf("管理端口收敛提议不符: %+v err=%v", mgmtPlan, err)
	}
}

func TestWindowBoundsAndMatching(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	inside := time.Date(2026, 11, 13, 3, 30, 0, 0, loc)
	outside := time.Date(2026, 11, 13, 14, 0, 0, 0, loc)

	ok, _, _, err := repairpolicy.WindowBounds("02:00-05:00", loc, inside)
	if err != nil || !ok {
		t.Fatalf("03:30 应在 02:00-05:00 窗口内: %v %v", ok, err)
	}
	ok, nextStart, _, err := repairpolicy.WindowBounds("02:00-05:00", loc, outside)
	if err != nil || ok || nextStart.Day() != 14 || nextStart.Hour() != 2 {
		t.Fatalf("14:00 应在窗口外且下一窗口为次日 02:00: ok=%v next=%v err=%v", ok, nextStart, err)
	}
	ok, _, _, err = repairpolicy.WindowBounds("23:00-05:00", loc, inside)
	if err != nil || !ok {
		t.Fatalf("03:30 应在跨零点窗口 23:00-05:00 内: %v %v", ok, err)
	}

	gid := uuid.New()
	aid := uuid.New()
	rule := &ent.StandingRule{
		Enabled:        true,
		Tier:           standingrule.TierAuto,
		ActionTemplate: TplPkgJournalClean,
		GroupID:        &gid,
		AssetIds:       []uuid.UUID{aid},
	}
	f := &ent.Finding{Status: "open", GroupID: gid, AssetID: aid, Key: "disk-pressure", Title: "根盘空间使用率 92%"}
	if !MatchFinding(rule, f) {
		t.Fatal("预期命中磁盘容量待办")
	}
	otherAsset := *f
	otherAsset.AssetID = uuid.New()
	if MatchFinding(rule, &otherAsset) {
		t.Fatal("不在 asset_ids 内的主机不应命中")
	}
}
