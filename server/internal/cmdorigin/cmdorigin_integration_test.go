//go:build integration

package cmdorigin

import (
	"database/sql"
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

	// docker exec 进容器执行的平台指令：容器内进程无 platform_command 标记，按正在执行的命令文本与容器标识归属
	dockerCmd := db.Command.Create().SetKind("exec").SetAssetID(host.ID).
		SetCmd("docker exec openxdr-ha-patroni-1 sh -c 'tail -20 /var/lib/postgresql/.psql_history'").
		SetCreatedAt(start).SetCompletedAt(start.Add(3 * time.Second)).SetStatus("succeeded").SaveX(ctx)
	inContainer := map[string]any{
		"container": map[string]any{"name": "openxdr-ha-patroni-1", "uid": "67ed3549d9589297"},
		"process":   map[string]any{"cmd_line": "tail -20 /var/lib/postgresql/.psql_history"},
	}
	if got, err := Of(ctx, sqlDB, inContainer, &host.ID, start.Add(2*time.Second)); err != nil || got == nil || *got != dockerCmd.ID {
		t.Fatalf("docker exec 容器内命令应归属到平台指令 %s，实际 %v %v", dockerCmd.ID, got, err)
	}
	if got, err := Of(ctx, sqlDB, inContainer, &host.ID, start.Add(20*time.Second)); err != nil || got != nil {
		t.Fatalf("超出执行窗口不应归属，实际 %v %v", got, err)
	}
}
