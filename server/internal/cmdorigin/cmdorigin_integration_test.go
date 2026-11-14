//go:build integration

package cmdorigin

import (
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/testdb"
)

// 标记只有在"确实发给这台资产的 exec 指令、且事件落在执行期间（含后代进程余留期）"时才认
func TestOfVerifiesAgainstCommands(t *testing.T) {
	ctx, db := testdb.New(t)
	sqlDB, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()

	host := db.Asset.Create().SetHostname("web-1").SaveX(ctx)
	other := db.Asset.Create().SetHostname("web-2").SaveX(ctx)
	start := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	end := start.Add(10 * time.Minute)

	// 已完成的 exec：start 下发，end 结束
	done := db.Command.Create().SetKind("exec").SetAssetID(host.ID).SetCreatedAt(start).SetCompletedAt(end).SetStatus("succeeded").SaveX(ctx)
	// 仍在执行的 exec
	running := db.Command.Create().SetKind("exec").SetAssetID(host.ID).SetCreatedAt(start).SetStatus("sent").SaveX(ctx)
	// 结束进程指令不是 exec，不能被当作指令来源
	kill := db.Command.Create().SetKind("kill_process").SetAssetID(host.ID).SetCreatedAt(start).SetCompletedAt(end).SaveX(ctx)

	tag := func(id uuid.UUID) map[string]any {
		return map[string]any{"platform_command": map[string]any{"uid": id.String()}}
	}
	cases := []struct {
		name  string
		cmd   uuid.UUID
		asset uuid.UUID
		ts    time.Time
		want  bool
	}{
		{"执行期间", done.ID, host.ID, start.Add(time.Minute), true},
		{"下发前一分钟内（时钟偏差容忍）", done.ID, host.ID, start.Add(-30 * time.Second), true},
		{"下发前超过一分钟", done.ID, host.ID, start.Add(-2 * time.Minute), false},
		{"结束后余留期内", done.ID, host.ID, end.Add(Linger - time.Minute), true},
		{"结束后余留期边界", done.ID, host.ID, end.Add(Linger), true},
		{"结束后超出余留期", done.ID, host.ID, end.Add(Linger + time.Minute), false},
		{"仍在执行，远晚于下发", running.ID, host.ID, start.Add(2 * time.Hour), true},
		{"指令发给了别的资产", done.ID, other.ID, start.Add(time.Minute), false},
		{"非 exec 指令", kill.ID, host.ID, start.Add(time.Minute), false},
		{"伪造的不存在指令 ID", uuid.New(), host.ID, start.Add(time.Minute), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Of(ctx, sqlDB, tag(c.cmd), &c.asset, c.ts)
			if err != nil {
				t.Fatal(err)
			}
			if c.want {
				if got == nil || *got != c.cmd {
					t.Fatalf("应认出指令 %s，实际 %v", c.cmd, got)
				}
			} else if got != nil {
				t.Fatalf("核对不上应返回 nil，实际 %v", *got)
			}
		})
	}
}

// 宿主机观测的 LXC 进程没有标记：只认 agent 拉起的 sh -c <指令原文> 及其后代，原文、父进程、时间、资产任一对不上都不认
func TestOfHostObservedShell(t *testing.T) {
	ctx, db := testdb.New(t)
	sqlDB, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()

	guest := db.Asset.Create().SetHostname("gateway").SaveX(ctx)
	other := db.Asset.Create().SetHostname("dns").SaveX(ctx)
	start := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	end := start.Add(5 * time.Second)
	line := "date -Is\necho \"--- DNS ---\"\ngrep -n oneedu /etc/caddy/Caddyfile"
	cmd := db.Command.Create().SetKind("exec").SetAssetID(guest.ID).SetCmd(line).SetCreatedAt(start).SetCompletedAt(end).SetStatus("succeeded").SaveX(ctx)

	proc := func(guid, parentGUID uuid.UUID, cmdLine, parentExe string) map[string]any {
		return map[string]any{
			"observed_by": map[string]any{"asset_id": uuid.NewString()},
			"container":   map[string]any{"uid": "203", "name": "gateway", "runtime": "lxc"},
			"process": map[string]any{
				"uid": guid.String(), "cmd_line": cmdLine,
				"parent_process": map[string]any{"uid": parentGUID.String(), "file": map[string]any{"path": parentExe}},
			},
		}
	}
	launch := func(asset uuid.UUID, ts time.Time, raw map[string]any) {
		b, _ := json.Marshal(raw)
		guid := uuid.MustParse(raw["process"].(map[string]any)["uid"].(string))
		db.Event.Create().SetTs(ts).SetClassUID(1007).SetSource("agent").SetAssetID(asset).SetProcessGUID(guid).SetRaw(b).SaveX(ctx)
	}

	agentGUID := uuid.New()
	shGUID, childGUID, grandGUID := uuid.New(), uuid.New(), uuid.New()
	sh := proc(shGUID, agentGUID, "sh -c "+line, "/usr/local/bin/openxdr-agent")
	child := proc(childGUID, shGUID, "grep -n oneedu /etc/caddy/Caddyfile", "/usr/bin/sh")
	grand := proc(grandGUID, childGUID, "cat", "/usr/bin/grep")
	launch(guest.ID, start.Add(time.Second), sh)
	launch(guest.ID, start.Add(2*time.Second), child)
	launch(guest.ID, start.Add(3*time.Second), grand)

	// 父进程启动事件落在别的资产上：追溯不能跨资产
	strayGUID := uuid.New()
	launch(other.ID, start.Add(time.Second), proc(strayGUID, agentGUID, "sh -c "+line, "/usr/local/bin/openxdr-agent"))
	stray := proc(uuid.New(), strayGUID, "id", "/usr/bin/sh")

	noObserved := proc(uuid.New(), agentGUID, "sh -c "+line, "/usr/local/bin/openxdr-agent")
	delete(noObserved, "observed_by")

	cases := []struct {
		name  string
		raw   map[string]any
		asset uuid.UUID
		ts    time.Time
		want  bool
	}{
		{"指令的 sh 本身", sh, guest.ID, start.Add(time.Second), true},
		{"sh 的子进程", child, guest.ID, start.Add(2 * time.Second), true},
		{"sh 的孙进程", grand, guest.ID, start.Add(3 * time.Second), true},
		{"原文差一个字", proc(uuid.New(), agentGUID, "sh -c "+line+" ", "/usr/local/bin/openxdr-agent"), guest.ID, start.Add(time.Second), false},
		{"父进程不是 agent", proc(uuid.New(), agentGUID, "sh -c "+line, "/tmp/openxdr-agent.sh"), guest.ID, start.Add(time.Second), false},
		{"指令结束一分钟后才出现的 sh", sh, guest.ID, end.Add(2 * time.Minute), false},
		{"同样原文但发给别的资产", sh, other.ID, start.Add(time.Second), false},
		{"父进程启动事件在别的资产", stray, guest.ID, start.Add(2 * time.Second), false},
		{"父进程找不到启动事件", proc(uuid.New(), uuid.New(), "id", "/usr/bin/sh"), guest.ID, start.Add(2 * time.Second), false},
		{"没有宿主机观测标记的不走这条路", noObserved, guest.ID, start.Add(time.Second), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Of(ctx, sqlDB, c.raw, &c.asset, c.ts)
			if err != nil {
				t.Fatal(err)
			}
			if c.want {
				if got == nil || *got != cmd.ID {
					t.Fatalf("应认出指令 %s，实际 %v", cmd.ID, got)
				}
			} else if got != nil {
				t.Fatalf("核对不上应返回 nil，实际 %v", *got)
			}
		})
	}
}
