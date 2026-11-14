// Package cmdorigin 认出平台自己下发的指令触发的事件。
//
// agent 给它执行指令时拉起的进程及其后代打上指令 ID（raw.platform_command.uid）。server 不盲信这个标记：
// 指令必须确实发给了这台资产，事件也必须发生在指令执行期间（后代进程允许多活一段时间）。
// 核对不上的当没有标记，照常告警——标记只能让告警挂到指令上，不能让它消失。
//
// 宿主机 agent 从外面看到的 LXC 里的进程（server 改归到 LXC 资产、补上 observed_by）没有这个标记：
// 标记是容器里执行指令的那个 agent 打的，宿主机的 agent 不知道这条指令。这类事件只认确定性对得上的——
// 进程就是 agent 拉起的 sh -c <指令原文>（父进程是 openxdr-agent，原文与这台资产上同一时段的 exec 指令逐字相同），
// 或沿父进程追溯到这样的 sh。
package cmdorigin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Linger 指令结束后，它拉起的后代进程还能被算作指令的时长（nohup、后台任务）
const Linger = time.Hour

type Querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// maxAncestors 宿主机观测的事件沿父进程最多追溯几代去找指令的 sh
const maxAncestors = 6

// Of 事件所属的平台指令；没有标记或核对不上返回 nil
func Of(ctx context.Context, q Querier, raw map[string]any, asset *uuid.UUID, ts time.Time) (*uuid.UUID, error) {
	if asset == nil || q == nil {
		return nil, nil
	}
	id, ok := Tag(raw)
	if !ok {
		if _, observed := raw["observed_by"].(map[string]any); observed {
			return viaShell(ctx, q, raw, *asset, ts, maxAncestors)
		}
		return nil, nil
	}
	var one int
	err := q.QueryRowContext(ctx, `SELECT 1 FROM commands
WHERE id=$1 AND asset_id=$2 AND kind='exec' AND created_at <= $3::timestamptz + interval '1 minute'
  AND (completed_at IS NULL OR completed_at + make_interval(secs => $4) >= $3::timestamptz)`,
		id, *asset, ts, Linger.Seconds()).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// Tag 事件体上 agent 打的指令 ID
func Tag(raw map[string]any) (uuid.UUID, bool) {
	pc, _ := raw["platform_command"].(map[string]any)
	s, _ := pc["uid"].(string)
	id, err := uuid.Parse(s)
	return id, err == nil
}

// viaShell 宿主机观测的进程：自己就是指令的 sh，或某一代祖先是
func viaShell(ctx context.Context, q Querier, raw map[string]any, asset uuid.UUID, ts time.Time, depth int) (*uuid.UUID, error) {
	proc, _ := raw["process"].(map[string]any)
	parent, _ := proc["parent_process"].(map[string]any)
	if line, ok := shellLine(proc, parent); ok {
		var id uuid.UUID
		err := q.QueryRowContext(ctx, `SELECT id FROM commands
WHERE asset_id=$1 AND kind='exec' AND cmd=$2 AND created_at <= $3::timestamptz + interval '1 minute'
  AND (completed_at IS NULL OR completed_at + interval '1 minute' >= $3::timestamptz)
ORDER BY created_at DESC LIMIT 1`, asset, line, ts).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &id, nil
	}
	guid, _ := parent["uid"].(string)
	if depth == 0 || guid == "" {
		return nil, nil
	}
	// 父进程的启动事件：同一资产、不晚于本事件、不早于指令后代的余留期
	var body []byte
	var pts time.Time
	err := q.QueryRowContext(ctx, `SELECT raw, ts FROM events
WHERE process_guid=$1 AND asset_id=$2 AND class_uid=1007
  AND ts BETWEEN $3::timestamptz - make_interval(secs => $4) AND $3::timestamptz + interval '1 minute'
ORDER BY ts LIMIT 1`, guid, asset, ts, Linger.Seconds()).Scan(&body, &pts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var praw map[string]any
	if json.Unmarshal(body, &praw) != nil {
		return nil, nil
	}
	return viaShell(ctx, q, praw, asset, pts, depth-1)
}

// shellLine agent 执行指令的形态：父进程是 openxdr-agent，命令行是 sh -c <指令原文>
func shellLine(proc, parent map[string]any) (string, bool) {
	cmd, _ := proc["cmd_line"].(string)
	file, _ := parent["file"].(map[string]any)
	exe, _ := file["path"].(string)
	line, ok := strings.CutPrefix(cmd, "sh -c ")
	return line, ok && line != "" && path.Base(exe) == "openxdr-agent"
}
