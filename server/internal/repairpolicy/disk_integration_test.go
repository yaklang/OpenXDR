//go:build integration

package repairpolicy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/findings"
)

const diskHeader = "Filesystem 1024-blocks Used Available Capacity Mounted on\n"

func setupDisk(t *testing.T, cmd string) *fixture {
	x := setup(t)
	x.grant.Action, x.grant.Units, x.grant.Paths = ReclaimDisk, nil, []string{"/srv/cache"}
	x.cmd = cmd
	x.f = x.f.Update().SetKey("disk-full").SetTitle("磁盘空间不足").SaveX(x.ctx)
	x.probe = x.probe.Update().SetCompletedAt(time.Now()).SetCmd("df -P /").SetStdout(diskHeader + "/dev/root 1000 950 50 95% /\n").SaveX(x.ctx)
	return x
}

func TestDiskTemplatesReserveRevalidateAndCooldown(t *testing.T) {
	for _, cmd := range []string{"docker image prune -f", "docker builder prune -f", "apt-get clean", "find -- /srv/cache -xdev -type f -mtime +7 -delete"} {
		t.Run(cmd, func(t *testing.T) {
			x := setupDisk(t, cmd)
			x.save(t)
			x.bind(t)
			if err := x.store.Authorize(x.ctx, x.session, x.f, cmd); err != nil {
				t.Fatal(err)
			}
			if err := x.store.Revalidate(x.ctx, x.session, x.f, cmd); err != nil {
				t.Fatal(err)
			}
			row := x.db.Setting.GetX(x.ctx, useKey(x.f.AssetID, ReclaimDisk))
			var u use
			if err := strict(row.Value, &u); err != nil {
				t.Fatal(err)
			}
			if u.VerifiedAt != nil || u.FinalizedAt == nil {
				t.Fatal("消费预留被误作效果验证")
			}
			if err := x.store.Revalidate(x.ctx, x.session, x.f, cmd); err == nil {
				t.Fatal("重复消费预留")
			}
			// 即使换会话和回收模板也不能绕过资产级回收冷却。
			u.SessionID = uuid.New()
			raw, _ := json.Marshal(u)
			x.db.Setting.UpdateOneID(row.ID).SetValue(raw).ExecX(x.ctx)
			if err := x.store.Authorize(x.ctx, x.session, x.f, "apt-get clean"); err == nil {
				t.Fatal("回收冷却被绕过")
			}
			if repairCount(t, x).RepairAttempts != 1 {
				t.Fatal("重复请求消耗预算")
			}
		})
	}
}

func TestDiskRefusesMissingProofAndScope(t *testing.T) {
	for _, change := range []struct {
		name   string
		change func(*fixture)
	}{
		{"outside-path", func(x *fixture) { x.cmd = "find -- /srv/other -xdev -type f -mtime +7 -delete" }},
		{"non-disk", func(x *fixture) { x.f.Update().SetKey("service-failed").SetTitle("worker failed").ExecX(x.ctx) }},
		{"io-error", func(x *fixture) { x.f.Update().SetKey("disk-io").SetTitle("磁盘故障").ExecX(x.ctx) }},
		{"probe-failed", func(x *fixture) { x.probe.Update().SetStatus("failed").ExecX(x.ctx) }},
		{"probe-truncated", func(x *fixture) { x.probe.Update().SetTruncated(true).ExecX(x.ctx) }},
		{"probe-mount", func(x *fixture) {
			x.probe.Update().SetStdout(diskHeader + "/dev/root 1000 950 50 95% /other\n").ExecX(x.ctx)
		}},
		{"expired", func(x *fixture) { x.probe.Update().SetCompletedAt(time.Now().Add(-11 * time.Minute)).ExecX(x.ctx) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			x := setupDisk(t, "apt-get clean")
			x.save(t)
			x.bind(t)
			change.change(x)
			if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err == nil {
				t.Fatal("无效范围或证据被接受")
			}
		})
	}
}

func TestDiskForbiddenPathsAtSave(t *testing.T) {
	x := setupDisk(t, "apt-get clean")
	for _, p := range []string{"/", "cache", "/srv/../etc", "/srv//cache", "/etc", "/bin", "/sbin", "/usr", "/lib64", "/boot", "/proc", "/sys", "/dev", "/root/.ssh", "/var/lib/postgresql", "/var/lib/docker", "/var/log/audit", "/opt/openxdr-data", "/var", "/opt"} {
		x.grant.Paths = []string{p}
		if err := x.store.Save(auth.WithUser(x.ctx, x.admin), Policy{Grants: []Grant{x.grant}}, "test"); err == nil {
			t.Error("保存了禁止目录", p)
		}
	}
	x.grant.Paths = []string{"/srv/cache"}
	raw, _ := json.Marshal(Policy{Grants: []Grant{x.grant}})
	req := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(raw)).WithContext(auth.WithUser(x.ctx, x.admin))
	w := httptest.NewRecorder()
	x.store.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body.String())
	}
	p, err := x.store.Load(x.ctx)
	if err != nil || len(p.Grants) != 1 || len(p.Grants[0].Paths) != 1 || p.Grants[0].Paths[0] != "/srv/cache" {
		t.Fatal(p, err)
	}
}

func issuedDisk(t *testing.T) (*fixture, *ent.Command) {
	x := setupDisk(t, "apt-get clean")
	x.save(t)
	x.bind(t)
	if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err != nil {
		t.Fatal(err)
	}
	if err := x.store.Revalidate(x.ctx, x.session, x.f, x.cmd); err != nil {
		t.Fatal(err)
	}
	action := x.db.Command.Create().SetAssetID(x.f.AssetID).SetKind("exec").SetCmd(x.cmd).SetStatus("succeeded").SetExitCode(0).SetCreatedAt(time.Now()).SetCompletedAt(time.Now()).SaveX(x.ctx)
	if err := x.store.RecordProbe(x.ctx, x.session, action); err != nil {
		t.Fatal(err)
	}
	return x, action
}

func TestDiskVerificationRequiresIndependentImprovement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		out    string
		mutate func(*fixture, *ent.Command)
	}{
		{"success", diskHeader + "/dev/root 1000 900 100 90% /\n", nil},
		{"unchanged", diskHeader + "/dev/root 1000 950 50 95% /\n", nil},
		{"worse", diskHeader + "/dev/root 1000 960 40 96% /\n", nil},
		{"other-fs", diskHeader + "/dev/other 1000 900 100 90% /\n", nil},
		{"failed-action", diskHeader + "/dev/root 1000 900 100 90% /\n", func(x *fixture, a *ent.Command) { a.Update().SetStatus("failed").SetExitCode(1).ExecX(x.ctx) }},
		{"old-after", diskHeader + "/dev/root 1000 900 100 90% /\n", func(x *fixture, a *ent.Command) { a.Update().SetCompletedAt(time.Now().Add(time.Second)).ExecX(x.ctx) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, action := issuedDisk(t)
			if tc.mutate != nil {
				tc.mutate(x, action)
			}
			if err := x.store.VerifyDisk(x.ctx, x.session, x.f, []uuid.UUID{x.probe.ID}); err == nil {
				t.Fatal("前探针充当后探针")
			}
			after := x.db.Command.Create().SetAssetID(x.f.AssetID).SetKind("exec").SetCmd("df -P /").SetStatus("succeeded").SetExitCode(0).SetStdout(tc.out).SetCreatedAt(time.Now()).SetCompletedAt(time.Now()).SaveX(x.ctx)
			if err := x.store.RecordProbe(x.ctx, x.session, after); err != nil {
				t.Fatal(err)
			}
			err := x.store.VerifyDisk(x.ctx, x.session, x.f, []uuid.UUID{after.ID})
			if (err == nil) != (tc.name == "success") {
				t.Fatal(err)
			}
			var u use
			if err := strict(x.db.Setting.GetX(x.ctx, useKey(x.f.AssetID, ReclaimDisk)).Value, &u); err != nil {
				t.Fatal(err)
			}
			if (u.VerifiedAt != nil) != (tc.name == "success") {
				t.Fatal("错误的效果验证记录")
			}
		})
	}
}

func TestDiskRevalidateBindsOriginalCommandAndPolicy(t *testing.T) {
	for _, change := range []string{"command", "policy", "finding", "budget"} {
		t.Run(change, func(t *testing.T) {
			x := setupDisk(t, "apt-get clean")
			x.save(t)
			x.bind(t)
			if err := x.store.Authorize(x.ctx, x.session, x.f, x.cmd); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "command":
				x.cmd = "docker image prune -f"
			case "policy":
				x.grant.Paths = []string{"/srv/other"}
				x.save(t)
			case "finding":
				x.f.Update().SetTitle("服务失败").SetKey("service").ExecX(x.ctx)
			case "budget":
				x.f.Update().SetWork(findings.EncodeWork(findings.Work{RepairAttempts: 4})).ExecX(x.ctx)
			}
			if err := x.store.Revalidate(x.ctx, x.session, x.f, x.cmd); err == nil {
				t.Fatal("变化后仍下发")
			}
		})
	}
}
