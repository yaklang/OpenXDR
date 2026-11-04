// Package cmdorigin 认出平台自己下发的指令触发的事件。
//
// agent 给它执行指令时拉起的进程及其后代打上指令 ID（raw.platform_command.uid）。server 不盲信这个标记：
// 指令必须确实发给了这台资产，事件也必须发生在指令执行期间（后代进程允许多活一段时间）。
// 核对不上的当没有标记，照常告警——标记只能让告警挂到指令上，不能让它消失。
package cmdorigin

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Linger 指令结束后，它拉起的后代进程还能被算作指令的时长（nohup、后台任务）
const Linger = time.Hour

type Querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Of 事件所属的平台指令；没有标记或核对不上返回 nil。
// 若平台指令通过 docker/pct/crictl exec 进入容器执行，容器内进程由 containerd-shim 拉起、脱离了 agent 子进程树而无标记，
// 此时按同一资产正在执行的 exec 指令文本（须同时包含容器标识与当前命令行）兜底归属。
func Of(ctx context.Context, q Querier, raw map[string]any, asset *uuid.UUID, ts time.Time) (*uuid.UUID, error) {
	if asset == nil || q == nil {
		return nil, nil
	}
	if id, ok := Tag(raw); ok {
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
	if cname, cuid, inner, ok := containerExec(raw); ok {
		var id uuid.UUID
		err := q.QueryRowContext(ctx, `SELECT id FROM commands
WHERE asset_id=$1 AND kind='exec'
  AND created_at <= $2::timestamptz + interval '5 seconds'
  AND (completed_at IS NULL OR completed_at + interval '5 seconds' >= $2::timestamptz)
  AND cmd LIKE '%exec%'
  AND (($3 <> '' AND position($3 in cmd) > 0) OR ($4 <> '' AND position($4 in cmd) > 0))
  AND position($5 in cmd) > 0
ORDER BY created_at DESC LIMIT 1`,
			*asset, ts, cname, cuid, inner).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &id, nil
	}
	if prog, token, ok := subshellExec(raw); ok {
		var id uuid.UUID
		err := q.QueryRowContext(ctx, `SELECT id FROM commands
WHERE asset_id=$1 AND kind='exec'
  AND created_at <= $2::timestamptz + interval '5 seconds'
  AND (completed_at IS NULL OR completed_at + interval '5 seconds' >= $2::timestamptz)
  AND position($3 in cmd) > 0
  AND position($4 in cmd) > 0
ORDER BY created_at DESC LIMIT 1`,
			*asset, ts, prog, token).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &id, nil
	}
	return nil, nil
}

// subshellExec 识别由 sh/bash 管道或 $(...) 命令替换 fork 出的未登记子 shell 拉起的子进程：
// 特征是 parent_process 有 pid 但无 uid/name（父进程只 fork 未 exec），提取进程名与首个特征参数（≥6 字符）核对正在执行的指令文本
func subshellExec(raw map[string]any) (prog, token string, ok bool) {
	if raw["container"] != nil {
		return "", "", false
	}
	p, _ := raw["process"].(map[string]any)
	pp, _ := p["parent_process"].(map[string]any)
	if pp == nil || pp["pid"] == nil || pp["uid"] != nil || pp["name"] != nil {
		return "", "", false
	}
	prog, _ = p["name"].(string)
	cmd, _ := p["cmd_line"].(string)
	fields := strings.Fields(cmd)
	if prog == "" || len(fields) < 2 {
		return "", "", false
	}
	for _, f := range fields[1:] {
		f = strings.Trim(f, `'"`)
		if len(f) >= 6 {
			return prog, f, true
		}
	}
	return "", "", false
}

// containerExec 提取容器内进程的容器名、短 ID 与剥去外层 sh -c 后的命令行（至少 8 字符才算具体命令）
func containerExec(raw map[string]any) (name, uid, inner string, ok bool) {
	c, _ := raw["container"].(map[string]any)
	if c == nil {
		return "", "", "", false
	}
	name, _ = c["name"].(string)
	uid, _ = c["uid"].(string)
	if len(uid) > 12 {
		uid = uid[:12]
	}
	if name == "" && uid == "" {
		return "", "", "", false
	}
	p, _ := raw["process"].(map[string]any)
	cmd, _ := p["cmd_line"].(string)
	cmd = strings.TrimSpace(cmd)
	for _, prefix := range []string{"/bin/sh -c ", "sh -c ", "/bin/bash -c ", "bash -c "} {
		if after, found := strings.CutPrefix(cmd, prefix); found {
			cmd = strings.Trim(strings.TrimSpace(after), `'"`)
			break
		}
	}
	if len(cmd) < 8 {
		return "", "", "", false
	}
	return name, uid, cmd, true
}

// Tag 事件体上 agent 打的指令 ID
func Tag(raw map[string]any) (uuid.UUID, bool) {
	pc, _ := raw["platform_command"].(map[string]any)
	s, _ := pc["uid"].(string)
	id, err := uuid.Parse(s)
	return id, err == nil
}
