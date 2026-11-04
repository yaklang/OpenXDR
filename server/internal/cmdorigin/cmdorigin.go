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
	"time"

	"github.com/google/uuid"
)

// Linger 指令结束后，它拉起的后代进程还能被算作指令的时长（nohup、后台任务）
const Linger = time.Hour

type Querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Of 事件所属的平台指令；没有标记或核对不上返回 nil
func Of(ctx context.Context, q Querier, raw map[string]any, asset *uuid.UUID, ts time.Time) (*uuid.UUID, error) {
	id, ok := Tag(raw)
	if !ok || asset == nil || q == nil {
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
