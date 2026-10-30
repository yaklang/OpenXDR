package eventsearch

import (
	"context"
	"errors"
	"time"

	"openxdr/server/ent"
	entevent "openxdr/server/ent/event"
)

// 规划器估不准子串关键词的命中率（生产 6600 万行上把 dockerd 估成 5858 行），会只走 trgm 索引、把时间范围
// 当事后过滤：整个保留期的候选行都要重算检索函数，常见词几分钟都返回不了。检索因此按开销可控的三档走：
//  1. 只看最近 recentRows 行：btree 定出这些行的时间下界，关键词用索引用不上的等价写法逐行过滤，高频词这一步就凑够；
//  2. trgm 索引全量查，限时 indexBudget（不超过总时限的 1/4）：罕见词候选少，很快查完；
//  3. 索引查不完说明词不罕见，改为逐行过滤最近 wideRows 行，用完剩余时间为止。
//
// 总时限 budget（调用方自己有期限时最多用剩余时间的 2/3），超时的那档取消数据库查询；
// 只有覆盖了整个时间窗口的那档查完才算完整，否则返回已有结果并标为不完整。
var (
	recentRows  = 10000
	wideRows    = 200000
	budget      = 20 * time.Second
	indexBudget = 5 * time.Second
)

// Search 按时间倒序取前 limit 条匹配 m 的事件。query 每次返回一个带好其他条件（时间、范围、预加载）的新查询。
// complete 为假表示没能覆盖整个时间窗口，可能还有更早的匹配。
func Search(ctx context.Context, query func() *ent.EventQuery, m Match, limit int) (rows []*ent.Event, complete bool, err error) {
	total := budget
	if deadline, ok := ctx.Deadline(); ok {
		total = min(total, time.Until(deadline)*2/3)
	}
	ctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()

	rows, complete, err = recent(ctx, query, m, limit, recentRows)
	if err != nil || complete || len(rows) == limit {
		return rows, err == nil, err
	}
	indexed, cancelIndex := context.WithTimeout(ctx, min(indexBudget, total/4))
	defer cancelIndex()
	all, err := query().Where(m.Predicate()).Order(ent.Desc(entevent.FieldTs)).Limit(limit).All(indexed)
	if err == nil {
		return all, true, nil
	}
	if !timedOut(indexed) {
		return nil, false, err
	}
	wide, covered, err := recent(ctx, query, m, limit, wideRows)
	if err != nil {
		if timedOut(ctx) {
			return rows, false, nil
		}
		return nil, false, err
	}
	return wide, covered, nil
}

// recent 只在最近 n 行里找；covered 表示时间窗口内总共不到 n 行，即已查全。
func recent(ctx context.Context, query func() *ent.EventQuery, m Match, limit, n int) (rows []*ent.Event, covered bool, err error) {
	var edge []struct {
		Ts time.Time `json:"ts"`
	}
	if err := query().Order(ent.Desc(entevent.FieldTs)).Offset(n-1).Limit(1).Select(entevent.FieldTs).Scan(ctx, &edge); err != nil {
		return nil, false, err
	}
	q := query().Where(m.scan())
	if len(edge) > 0 {
		q = q.Where(entevent.TsGTE(edge[0].Ts))
	}
	rows, err = q.Order(ent.Desc(entevent.FieldTs)).Limit(limit).All(ctx)
	return rows, len(edge) == 0, err
}

// timedOut 是这一档自己的时限到了，而不是调用方取消。
func timedOut(ctx context.Context) bool {
	return errors.Is(ctx.Err(), context.DeadlineExceeded)
}
