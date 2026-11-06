//go:build integration

package repairpolicy

import (
	"encoding/json"
	"github.com/google/uuid"
	"openxdr/server/internal/findings"
	"testing"
	"time"
)

func TestCapabilitiesExactActionAndProbe(t *testing.T) {
	x := setupDisk(t, "apt-get clean")
	x.save(t)
	inspect := func(cmd string) findings.RepairCapabilities {
		t.Helper()
		v, err := x.store.Capabilities(x.ctx, x.session.GroupID, x.session.ID, x.f, cmd, "/")
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := inspect("apt-get clean"); v.Status != "probe_invalid" || v.Probe != "df -P /" {
		t.Fatalf("missing probe: %+v", v)
	}
	if v := inspect("systemctl restart -- worker-app.service"); v.Status != "policy_required" || v.Probe == "" {
		t.Fatalf("other action grant borrowed: %+v", v)
	}
	if v := inspect("docker compose restart"); v.Status != "action_unsupported" {
		t.Fatalf("unknown action: %+v", v)
	}
	x.bind(t)
	if v := inspect("apt-get clean"); v.Status != "ready" {
		t.Fatalf("valid probe: %+v", v)
	}
	x.probe.Update().SetTruncated(true).ExecX(x.ctx)
	if v := inspect("apt-get clean"); v.Status != "probe_invalid" {
		t.Fatal(v)
	}
	if _, err := x.store.Capabilities(x.ctx, uuid.New(), x.session.ID, x.f, "apt-get clean", "/"); err == nil {
		t.Fatal("cross group inspection accepted")
	}
	if n := repairCount(t, x).RepairAttempts; n != 0 {
		t.Fatal("inspection consumed budget", n)
	}
}

func TestMaintenanceWindowIsAdministratorGrantBoundary(t *testing.T) {
	x := setupDisk(t, "apt-get clean")
	at := time.Now().Add(time.Hour)
	x.grant.NotBefore = &at
	x.grant.ExpiresAt = at.Add(time.Hour)
	x.save(t)
	x.bind(t)
	state, err := x.store.Capabilities(x.ctx, x.session.GroupID, x.session.ID, x.f, x.cmd, "/")
	if err != nil || state.Status != "maintenance_window_required" || state.RetryAt == nil || !state.RetryAt.Equal(at) {
		t.Fatal(state, err)
	}
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("future window authorized")
	}
	if repairCount(t, x).RepairAttempts != 0 {
		t.Fatal("future window consumed budget")
	}
	at = time.Now().Add(-time.Minute)
	x.grant.NotBefore = &at
	x.save(t)
	// 保存窗口后必须重取本轮探针；模型声明一个日期不能替代管理员授权。
	x.bind(t)
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err != nil {
		t.Fatal(err)
	}
	state, err = x.store.Capabilities(x.ctx, x.session.GroupID, x.session.ID, x.f, "docker builder prune -f", "/")
	if err != nil || state.Status != "cooldown" || state.RetryAt == nil {
		t.Fatal(state, err)
	}
	catalog, err := x.store.Capabilities(x.ctx, x.session.GroupID, x.session.ID, x.f, "", "")
	if err != nil || len(catalog.Grants) != 1 || catalog.Grants[0].CooldownUntil == nil || len(catalog.Grants[0].RequiredProbes) == 0 {
		t.Fatal(catalog, err)
	}
}

func TestDependencyRecoveryRequiresReevaluationAndReopensBeforeIssue(t *testing.T) {
	x := setupDisk(t, "apt-get clean")
	x.save(t)
	x.bind(t)
	dep := x.db.Finding.Create().SetGroupID(x.session.GroupID).SetAssetID(x.f.AssetID).SetKey("upstream").SetTitle("upstream").SaveX(x.ctx)
	var w findings.Work
	json.Unmarshal(x.f.Work, &w)
	w.Blocker = "external_dependency"
	w.DependsOn = []uuid.UUID{dep.ID}
	x.f = x.f.Update().SetWork(findings.EncodeWork(w)).SaveX(x.ctx)
	state, err := x.store.Capabilities(x.ctx, x.session.GroupID, x.session.ID, x.f, x.cmd, "/")
	if err != nil || state.Status != "external_dependency" {
		t.Fatal(state, err)
	}
	dep.Update().SetStatus("resolved").ExecX(x.ctx)
	state, err = x.store.Capabilities(x.ctx, x.session.GroupID, x.session.ID, x.f, x.cmd, "/")
	if err != nil || state.Status != "ready" {
		t.Fatal(state, err)
	}
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("能力快照直接解除上游阻塞")
	}
	w.Blocker = ""
	x.f = x.f.Update().SetWork(findings.EncodeWork(w)).SaveX(x.ctx)
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err != nil {
		t.Fatal(err)
	}
	dep.Update().SetStatus("open").ExecX(x.ctx)
	if err := x.store.Revalidate(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("下发前依赖重新打开仍被放行")
	}
	if repairCount(t, x).RepairAttempts != 1 {
		t.Fatal("依赖重开清除了原预留预算")
	}
}

func TestWindowClassificationRequiresMatchingGrant(t *testing.T) {
	x := setupDisk(t, "apt-get clean")
	x.save(t)
	x.f = x.f.Update().SetWork(findings.EncodeWork(findings.Work{Blocker: "maintenance_window_required"})).SaveX(x.ctx)
	state, err := x.store.Capabilities(x.ctx, x.session.GroupID, x.session.ID, x.f, x.cmd, "/")
	if err != nil || state.Status != "maintenance_window_required" {
		t.Fatal(state, err)
	}
	x.db.Setting.UpdateOneID(SettingKey).SetValue(json.RawMessage(`{"grants":[]}`)).ExecX(x.ctx)
	state, err = x.store.Capabilities(x.ctx, x.session.GroupID, x.session.ID, x.f, x.cmd, "/")
	if err != nil || state.Status != "policy_required" {
		t.Fatal("没有精确授权却被误记为等待窗口", state, err)
	}
}

func TestHumanOwnershipChangeBeforeIssuePreservesReservation(t *testing.T) {
	x := setupDisk(t, "apt-get clean")
	x.save(t)
	x.bind(t)
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err != nil {
		t.Fatal(err)
	}
	x.f.Update().SetWorkOwner("human").ExecX(x.ctx)
	if err := x.store.Revalidate(x.ctx, x.session, x.f, x.cmd); err == nil {
		t.Fatal("人工接管后仍下发")
	}
	if repairCount(t, x).RepairAttempts != 1 {
		t.Fatal("人工接管清除了原预留")
	}
}
