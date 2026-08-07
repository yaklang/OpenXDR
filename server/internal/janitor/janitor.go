// Package janitor 数据保留：按期清理过期的原始事件。
//
// 策略：只删没有被任何告警引用的事件。被引用的事件是 incident 的证据，
// 跟着 incident 的生命周期走，不能因为到期就抹掉。
// 存储膨胀的主体本来就是无人问津的原始遥测，删掉它们即可。
package janitor

import (
	"context"
	"log/slog"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/event"
)

// 单批删除量：太大容易长事务锁表，太小则清理跟不上写入
const batchSize = 10000

type Janitor struct {
	DB        *ent.Client
	Retention time.Duration
	Interval  time.Duration
}

func (j *Janitor) Run(ctx context.Context) {
	if j.Retention <= 0 {
		slog.Warn("事件保留策略未启用：RETENTION_DAYS 为 0，events 表会持续增长")
		return
	}
	ticker := time.NewTicker(j.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := j.sweep(ctx)
			if err != nil {
				slog.Error("清理过期事件失败", "err", err)
			} else if deleted > 0 {
				slog.Info("清理过期事件", "deleted", deleted)
			}
		}
	}
}

func (j *Janitor) sweep(ctx context.Context) (int, error) {
	cutoff := time.Now().Add(-j.Retention)
	total := 0
	for {
		ids, err := j.DB.Event.Query().
			Where(event.TsLT(cutoff), event.Not(event.HasAlerts())).
			Limit(batchSize).
			IDs(ctx)
		if err != nil || len(ids) == 0 {
			return total, err
		}
		n, err := j.DB.Event.Delete().Where(event.IDIn(ids...)).Exec(ctx)
		total += n
		if err != nil {
			return total, err
		}
		// 不足一批说明已清完，避免空转
		if len(ids) < batchSize {
			return total, nil
		}
		// 让出时间片，别把连接池和 CPU 占满
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
