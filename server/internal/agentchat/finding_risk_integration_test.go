//go:build integration

package agentchat

import (
	"encoding/json"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
	"testing"
	"time"
)

func TestFindingRiskScopeAndReceiptBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ent.Client, *ent.AgentSession, *ent.Finding, *ent.Command)
		want   string
		bad    bool
	}{
		{"pressure", nil, "disk_pressure", false},
		{"unknown", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetStatus("unknown").ExecX(t.Context())
		}, "", true},
		{"failed", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetStatus("failed").ExecX(t.Context())
		}, "", true},
		{"exit_nonzero", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetExitCode(1).ExecX(t.Context())
		}, "", true},
		{"truncated", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetTruncated(true).ExecX(t.Context())
		}, "", true},
		{"stderr", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetStderr("permission denied").ExecX(t.Context())
		}, "", true},
		{"empty", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetStdout("").ExecX(t.Context())
		}, "", true},
		{"malformed", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetStdout(findingDiskHeader + "/dev/root 1000 10 990 99% /\n").ExecX(t.Context())
		}, "", true},
		{"stale", func(db *ent.Client, s *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			s.CreatedAt = time.Now().Add(-time.Hour)
			db.Command.UpdateOneID(c.ID).SetCreatedAt(time.Now().Add(-12 * time.Minute)).SetCompletedAt(time.Now().Add(-11 * time.Minute)).ExecX(t.Context())
		}, "", true},
		{"before_session", func(db *ent.Client, s *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetCreatedAt(s.CreatedAt.Add(-time.Minute)).ExecX(t.Context())
		}, "", true},
		{"future_created", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetCreatedAt(time.Now().Add(time.Minute)).ExecX(t.Context())
		}, "", true},
		{"future_completed", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetCompletedAt(time.Now().Add(time.Minute)).ExecX(t.Context())
		}, "", true},
		{"completed_before_created", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetCompletedAt(c.CreatedAt.Add(-time.Second)).ExecX(t.Context())
		}, "", true},
		{"asset_moved_group", func(db *ent.Client, _ *ent.AgentSession, f *ent.Finding, _ *ent.Command) {
			g := db.Group.Create().SetName("other").SaveX(t.Context())
			db.Asset.UpdateOneID(f.AssetID).SetGroupID(g.ID).ExecX(t.Context())
		}, "", true},
		{"wrong_finding_group", func(_ *ent.Client, _ *ent.AgentSession, f *ent.Finding, _ *ent.Command) { f.GroupID = uuid.New() }, "", true},
		{"wrong_target_asset", func(_ *ent.Client, _ *ent.AgentSession, f *ent.Finding, _ *ent.Command) {
			f.Work = json.RawMessage(`{"risk_target":{"kind":"disk_root","mount":"/","asset_id":"` + uuid.NewString() + `"}}`)
		}, "", true},
		{"wrong_target_mount", func(_ *ent.Client, _ *ent.AgentSession, f *ent.Finding, _ *ent.Command) {
			f.Work = json.RawMessage(`{"risk_target":{"kind":"disk_root","mount":"/var","asset_id":"` + f.AssetID.String() + `"}}`)
		}, "", true},
		{"missing_target", func(_ *ent.Client, _ *ent.AgentSession, f *ent.Finding, _ *ent.Command) {
			f.Work = json.RawMessage(`{}`)
		}, "", false},
		{"unrelated_probe", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetCmd("df -P /var").ExecX(t.Context())
		}, "", false},
		{"shell_appended", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetCmd("df -P /; true").ExecX(t.Context())
		}, "", false},
		{"whitespace_variant", func(db *ent.Client, _ *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			db.Command.UpdateOneID(c.ID).SetCmd(" df -P / ").ExecX(t.Context())
		}, "", false},
		{"wrong_asset_receipt", func(db *ent.Client, s *ent.AgentSession, _ *ent.Finding, c *ent.Command) {
			a := db.Asset.Create().SetHostname("other").SetGroupID(s.GroupID).SaveX(t.Context())
			db.Command.UpdateOneID(c.ID).SetAssetID(a.ID).ExecX(t.Context())
		}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, db := testdb.New(t)
			now := time.Now().UTC().Truncate(time.Microsecond)
			g := db.Group.Create().SetName("risk").SaveX(ctx)
			a := db.Asset.Create().SetHostname("risk-host").SetGroupID(g.ID).SaveX(ctx)
			session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetModel("test").SetGroupID(g.ID).SetCreatedAt(now.Add(-5 * time.Minute)).SaveX(ctx)
			f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("disk").SetTitle("磁盘").SetWork(json.RawMessage(`{"risk_target":{"kind":"disk_root","mount":"/","asset_id":"` + a.ID.String() + `"}}`)).SaveX(ctx)
			c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("df -P /").SetStatus("succeeded").SetExitCode(0).SetCreatedAt(now.Add(-2 * time.Minute)).SetCompletedAt(now.Add(-time.Minute)).SetStdout(findingDiskHeader + "/dev/root 1000 950 50 95% /\n").SaveX(ctx)
			if tc.change != nil {
				tc.change(db, session, f, c)
			}
			kind, at, err := (&Service{DB: db}).findingRisk(ctx, session, f, []uuid.UUID{c.ID})
			if (err != nil) != tc.bad || kind != tc.want {
				t.Fatalf("kind=%q at=%v err=%v want=%q bad=%t", kind, at, err, tc.want, tc.bad)
			}
			if kind != "" && !at.Equal(*c.CompletedAt) {
				t.Fatalf("观测时间不是回执完成时间 %v", at)
			}
			if kind == "" && !at.IsZero() {
				t.Fatal("无风险结论不应伪造观测时刻")
			}
		})
	}
}

func TestFindingRiskUsesNewestExactProbe(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	g := db.Group.Create().SetName("risk").SaveX(ctx)
	a := db.Asset.Create().SetHostname("risk-host").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetModel("test").SetGroupID(g.ID).SetCreatedAt(now.Add(-5 * time.Minute)).SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("disk").SetTitle("磁盘").SetWork(json.RawMessage(`{"risk_target":{"kind":"disk_root","mount":"/","asset_id":"` + a.ID.String() + `"}}`)).SaveX(ctx)
	create := func(out string, at time.Time) *ent.Command {
		return db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("df -P /").SetStatus("succeeded").SetExitCode(0).SetCreatedAt(now.Add(-2 * time.Minute)).SetCompletedAt(at).SetStdout(findingDiskHeader + out).SaveX(ctx)
	}
	old := create("/dev/root 1000 950 50 95% /\n", now.Add(-time.Minute))
	newer := create("/dev/root 1000 500 500 50% /\n", now.Add(-30*time.Second))
	svc := &Service{DB: db}
	for _, ids := range [][]uuid.UUID{{old.ID, newer.ID}, {newer.ID, old.ID}} {
		kind, at, err := svc.findingRisk(ctx, session, f, ids)
		if err != nil || kind != "disk_ok" || !at.Equal(*newer.CompletedAt) {
			t.Fatalf("未使用最新完整探针: %q %v %v", kind, at, err)
		}
	}
	if _, _, err := svc.findingRisk(ctx, session, f, []uuid.UUID{old.ID, old.ID}); err == nil {
		t.Fatal("重复引用应拒绝")
	}
	conflict := create("/dev/root 1000 950 50 95% /\n", *newer.CompletedAt)
	if _, _, err := svc.findingRisk(ctx, session, f, []uuid.UUID{newer.ID, conflict.ID}); err == nil {
		t.Fatal("同刻矛盾探针不能支持恢复")
	}
}

func TestFindingRiskMemoryReceipts(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	g := db.Group.Create().SetName("risk").SaveX(ctx)
	a := db.Asset.Create().SetHostname("memory-host").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetModel("test").SetGroupID(g.ID).SetCreatedAt(now.Add(-5 * time.Minute)).SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("memory").SetTitle("内存").SetWork(json.RawMessage(`{"risk_target":{"kind":"memory","asset_id":"` + a.ID.String() + `"}}`)).SaveX(ctx)
	for _, tc := range []struct{ name, out, want string }{
		{"pressure", findingMemoryHeader + "Mem: 1000 0 0 0 0 100\nSwap: 1000 950 50\n", "memory_pressure"},
		{"memory_recovered", findingMemoryHeader + "Mem: 1000 0 0 0 0 101\nSwap: 1000 950 50\n", "memory_ok"},
		{"swap_recovered", findingMemoryHeader + "Mem: 1000 0 0 0 0 100\nSwap: 1000 949 51\n", "memory_ok"},
		{"no_swap_not_recovered", findingMemoryHeader + "Mem: 1000 0 0 0 0 100\nSwap: 0 0 0\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("free -b").SetStatus("succeeded").SetExitCode(0).SetCreatedAt(now.Add(-2 * time.Minute)).SetCompletedAt(now.Add(-time.Minute)).SetStdout(tc.out).SaveX(ctx)
			got, at, err := (&Service{DB: db}).findingRisk(ctx, session, f, []uuid.UUID{c.ID})
			if err != nil || got != tc.want {
				t.Fatalf("kind=%q at=%v err=%v", got, at, err)
			}
			if got == "" && !at.IsZero() {
				t.Fatal("不可用不是恢复")
			}
		})
	}
}

func TestFindingRiskNewestUnavailableDoesNotRestore(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	g := db.Group.Create().SetName("risk").SaveX(ctx)
	a := db.Asset.Create().SetHostname("memory-host").SetGroupID(g.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetModel("test").SetGroupID(g.ID).SetCreatedAt(now.Add(-5 * time.Minute)).SaveX(ctx)
	f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("memory").SetTitle("内存").SetWork(json.RawMessage(`{"risk_target":{"kind":"memory","asset_id":"` + a.ID.String() + `"}}`)).SaveX(ctx)
	makeProbe := func(out string, at time.Time) *ent.Command {
		return db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("free -b").SetStatus("succeeded").SetExitCode(0).SetCreatedAt(now.Add(-2 * time.Minute)).SetCompletedAt(at).SetStdout(out).SaveX(ctx)
	}
	old := makeProbe(findingMemoryHeader+"Mem: 1000 0 0 0 0 800\nSwap: 1000 100 900\n", now.Add(-time.Minute))
	newest := makeProbe(findingMemoryHeader+"Mem: 1000 0 0 0 0 1\nSwap: 0 0 0\n", now.Add(-30*time.Second))
	for _, ids := range [][]uuid.UUID{{old.ID, newest.ID}, {newest.ID, old.ID}} {
		kind, at, err := (&Service{DB: db}).findingRisk(ctx, session, f, ids)
		if err != nil || kind != "" || !at.IsZero() {
			t.Fatalf("旧健康回执不可遮盖最新不可用状态 %q %v %v", kind, at, err)
		}
	}
}

func TestFindingRiskCannotCherryPickOldCriticalProbe(t *testing.T) {
	for _, tc := range []struct {
		name, status, cmd string
		complete          bool
		bad               bool
	}{
		{"newer_healthy", "succeeded", "df -P /", true, true},
		{"newer_failed", "failed", "df -P /", true, true},
		{"newer_unknown", "unknown", "df -P /", false, true},
		{"newer_pending", "pending", "df -P /", false, true},
		{"newer_sent", "sent", "df -P /", false, true},
		{"other_probe_not_equivalent", "succeeded", "df -P /var", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, db := testdb.New(t)
			now := time.Now().UTC().Truncate(time.Microsecond)
			g := db.Group.Create().SetName("risk").SaveX(ctx)
			a := db.Asset.Create().SetHostname("disk-host").SetGroupID(g.ID).SaveX(ctx)
			session := db.AgentSession.Create().SetKind("task").SetInitiator("system").SetModel("test").SetGroupID(g.ID).SetCreatedAt(now.Add(-5 * time.Minute)).SaveX(ctx)
			f := db.Finding.Create().SetGroupID(g.ID).SetAssetID(a.ID).SetKey("disk").SetTitle("磁盘").SetWork(json.RawMessage(`{"risk_target":{"kind":"disk_root","mount":"/","asset_id":"` + a.ID.String() + `"}}`)).SaveX(ctx)
			old := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd("df -P /").SetStatus("succeeded").SetExitCode(0).SetCreatedAt(now.Add(-2 * time.Minute)).SetCompletedAt(now.Add(-time.Minute)).SetStdout(findingDiskHeader + "/dev/root 1000 950 50 95% /\n").SaveX(ctx)
			next := db.Command.Create().SetAssetID(a.ID).SetKind("exec").SetCmd(tc.cmd).SetStatus(tc.status).SetCreatedAt(now.Add(-45 * time.Second))
			if tc.complete {
				next.SetCompletedAt(now.Add(-30 * time.Second)).SetExitCode(0).SetStdout(findingDiskHeader + "/dev/root 1000 500 500 50% /\n")
			}
			next.ExecX(ctx)
			kind, at, err := (&Service{DB: db}).findingRisk(ctx, session, f, []uuid.UUID{old.ID})
			if tc.bad {
				if err == nil || kind != "" || !at.IsZero() {
					t.Fatalf("不可选择旧危急回执制造紧急：kind=%q at=%v err=%v", kind, at, err)
				}
			} else if err != nil || kind != "disk_pressure" || !at.Equal(*old.CompletedAt) {
				t.Fatalf("无关探针不得影响目标：kind=%q at=%v err=%v", kind, at, err)
			}
		})
	}
}
