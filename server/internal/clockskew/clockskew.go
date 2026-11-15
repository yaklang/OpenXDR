// Package clockskew 定义有界墙钟偏斜容差与统一数据库时钟读取。
package clockskew

import (
	"context"
	"fmt"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"openxdr/server/ent"
)

// Max 有界墙钟偏斜容差。
//
// 来源：跨节点 Server 之间、Server 与被监控端点之间的时钟偏差、PostgreSQL timestamptz 微秒取整、
// 以及单机或虚拟化环境下的 NTP 校时调整。
//
// 使用边界：只用于两类比较——
//  1. 「属于本轮 / 本会话」的下界（例如 command.CreatedAt >= session.CreatedAt - Max）；
//  2. 「不晚于现在」的上界（例如 CompletedAt <= now + Max、检索热表的 until = now + Max）。
//
// 安全因果门禁（复查之后不能再有写操作、批准与执行的先后、一次性预留与绑定、同一指令创建与完成的先后）
// 一律不放宽，并尽量使用同一来源的时间（数据库 clock_timestamp() 或同一条记录上的字段）严格比较。
const Max = 5 * time.Second

// DBNow 读取 PostgreSQL 主库当前瞬时时钟（clock_timestamp()，微秒精度，随真实时间推进而不像 now() 冻结在事务起点），
// 使跨节点的指令创建/完成、一次性维护预留/二次复核共享同一时钟源与微秒精度，避免拿不同节点各自的 time.Now() 互相比。
func DBNow(ctx context.Context, db *ent.Client) (time.Time, error) {
	if db == nil {
		return time.Now().UTC().Truncate(time.Microsecond), nil
	}
	var rows []struct {
		Now time.Time `sql:"now"`
	}
	err := db.Setting.Query().
		Where(func(s *entsql.Selector) { s.Where(entsql.False()) }).
		Aggregate(func(*entsql.Selector) string {
			return "clock_timestamp() + (COUNT(*) * interval '0 second') AS now"
		}).
		Scan(ctx, &rows)
	if err != nil {
		return time.Time{}, err
	}
	if len(rows) != 1 {
		return time.Time{}, fmt.Errorf("clock_timestamp 返回 %d 行", len(rows))
	}
	return rows[0].Now, nil
}
