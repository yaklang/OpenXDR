// 爆破得手跨事件升级：登录成功前的时间窗内，同资产同用户已有多次登录失败。
// 单条失败只是 medium 噪声，"失败 N 次后成功"才是凭据已失守的信号。
// 跨事件计数超出单事件 Sigma 引擎的能力，而成功登录足够稀少——
// 在 ingest 侧对每条成功登录回查一次数据库，就是这条检测的全部成本。
package grpcsvc

import (
	"context"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/google/uuid"

	"openxdr/server/ent/event"
)

// OCSF Authentication 及其 status_id 取值
const (
	classAuth         = 3002
	authStatusSuccess = 1
	authStatusFailure = 2
)

// 爆破判定：窗口内失败达到阈值后出现成功
const (
	bruteforceWindow    = 10 * time.Minute
	bruteforceThreshold = 5
)

// authStatus 从原始事件取 status_id，取不到返回 0。
func authStatus(raw map[string]any) int {
	v, _ := raw["status_id"].(float64)
	return int(v)
}

// countAuthFailures 数出成功登录前时间窗内同资产同用户的失败次数。
func (s *Server) countAuthFailures(ctx context.Context, assetID uuid.UUID, user string, ts time.Time) int {
	n, err := s.DB.Event.Query().
		Where(
			event.ClassUIDEQ(classAuth),
			event.AssetIDEQ(assetID),
			event.UsernameEQ(user),
			event.TsGTE(ts.Add(-bruteforceWindow)),
			func(sel *sql.Selector) {
				sel.Where(sqljson.ValueEQ(event.FieldRaw, authStatusFailure, sqljson.Path("status_id")))
			},
		).
		Count(ctx)
	if err != nil {
		return 0
	}
	return n
}
