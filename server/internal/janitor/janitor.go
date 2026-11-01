// Package janitor 数据保留：按期清理过期的原始事件。
//
// 策略：只删没有被告警或时序证据引用的事件。被引用的事件是 incident 的证据，
// 跟着 incident 的生命周期走，不能因为到期就抹掉。
// 存储膨胀的主体本来就是无人问津的原始遥测，删掉它们即可。
//
// events 是分区表时，过期的日分区整体退役（证据并进月归档分区，其余随分区删除），
// 逐行删除只剩归档与默认分区里的少量行（迟到事件、异常时间戳、引用已解除的证据）。
package janitor

import (
	"context"
	stdsql "database/sql"
	"entgo.io/ent/dialect/sql"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/decoyobservation"
	"openxdr/server/ent/event"
	"openxdr/server/ent/session"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/temporal"
)

// 单批删除量：太大容易长事务锁表，太小则清理跟不上写入
const batchSize = 10000

type Janitor struct {
	DB  *ent.Client
	SQL *stdsql.DB
	// Retention 原始事件保留期（RETENTION_DAYS，0 关闭清理）
	Retention time.Duration
	// Interval 清理循环周期（RETENTION_INTERVAL_MINUTES）
	Interval time.Duration
	// GapRetention 时序求值缺口（temporal_evaluation_gaps，诊断记录）按自身 created_at
	// 的保留期（TEMPORAL_GAP_RETENTION_DAYS，默认 30 天，0 关闭）。与 Retention 相互独立：
	// swap 移出热表的事件的 gap 不随事件退役 / 删除走，只能按诊断时间清（R6）。
	GapRetention time.Duration
}

func (j *Janitor) Run(ctx context.Context) {
	if j.Retention <= 0 {
		slog.Warn("事件保留策略未启用：RETENTION_DAYS 为 0，events 表会持续增长")
	}
	ticker := time.NewTicker(j.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if j.Retention > 0 && j.SQL != nil {
				if n, dropped, err := j.retireExpired(ctx, retireCutoff(time.Now(), j.Retention)); err != nil {
					slog.Error("退役过期事件分区失败", "err", err)
				} else if n > 0 {
					slog.Info("退役过期事件分区", "partitions", n, "dropped", dropped)
				}
			}
			if j.Retention > 0 {
				deleted, err := j.sweep(ctx)
				if err != nil {
					slog.Error("清理过期事件失败", "err", err)
				} else if deleted > 0 {
					slog.Info("清理过期事件", "deleted", deleted)
				}
			}
			if j.Retention > 0 && j.SQL != nil {
				if n, err := temporal.PruneArchives(ctx, j.SQL, time.Now().Add(-j.Retention)); err != nil {
					slog.Error("清理无引用时序归档失败", "err", err)
				} else if n > 0 {
					slog.Info("清理无引用时序归档", "deleted", n)
				}
			}
			// 时序诊断缺口按自身的诊断保留期清理（R6），与 RETENTION_DAYS 无关：
			// swap 移出热表的事件的 gap 不随事件退役 / 删除走
			if n, err := j.sweepTemporalGaps(ctx); err != nil {
				slog.Error("清理过期时序诊断缺口失败", "err", err)
			} else if n > 0 {
				slog.Info("清理过期时序诊断缺口", "deleted", n)
			}
			if j.Retention > 0 {
				if n, err := j.sweepDecoys(ctx); err != nil {
					slog.Error("清理过期诱饵观察失败", "err", err)
				} else if n > 0 {
					slog.Info("清理过期诱饵观察", "deleted", n)
				}
			}
			// 过期会话是纯垃圾：认证早已拒绝它们，行却一直躺在表里
			if n, err := j.DB.Session.Delete().
				Where(session.ExpiresAtLT(time.Now())).
				Exec(ctx); err != nil {
				slog.Error("清理过期会话失败", "err", err)
			} else if n > 0 {
				slog.Info("清理过期会话", "deleted", n)
			}
		}
	}
}

// retireGuard 是时序证据可能引用的最老事件年龄：最大窗口 24 小时加迟到余量，再留一小时处理耗时。
// 退役分区不经外键或触发器兜底，必须只退役不会再被新证据引用的日子。
const retireGuard = 24*time.Hour + temporal.LateGrace + time.Hour

func retireCutoff(now time.Time, retention time.Duration) time.Time {
	return now.Add(-max(retention, retireGuard))
}

func (j *Janitor) sweep(ctx context.Context) (int, error) {
	cutoff := time.Now().Add(-j.Retention)
	// 分区表上逐行删除只碰最老日分区之前（归档与默认分区），日分区留给整体退役，免得删出一片死元组
	if j.SQL != nil {
		oldest, ok, err := eventpart.OldestDaily(ctx, j.SQL)
		if err != nil {
			return 0, err
		}
		if ok && oldest.Before(cutoff) {
			cutoff = oldest
		}
		return j.sweepDayLocked(ctx, cutoff)
	}
	// 没挂 *sql.DB 的部署（events 未分区、无分区维护）没有冷归档生命周期可言，
	// 沿用无锁的整批清理；生产形态（main.go）与分区部署都带 SQL，走上面的逐日上锁路径。
	return j.sweepBatched(ctx, cutoff)
}

// sweepDayLocked 是生产路径的到期清理（R1/R2）：先无锁预查本周期会删到行的 UTC 日集合，
// 再逐日取同日生命周期排他锁、锁内选批删批。
//
// 逐行 DELETE 会触发 events_release 触发器删派生表，且「选批 → 删除」之间可能插入新的
// 引用（alert / 时序证据 / 已出告警锚点）——先取该日排他锁再选删后：引用写入者要么在
// 本事务拿锁前提交（选批看得见，被引用的行不再入选），要么排队到该日清完之后（写入时
// 锁内重读发现热行缺失，走冷物化补链），不会交出「删除与引用交错」的悬空引用窗口。
// 预查的日集合有一个如实的边界：预查之后新落库的到期行若落在未列出的日子，本周期不碰
// 它（没上锁就不删），下个周期处理；落在已列出的日子则已被本日的锁覆盖。
func (j *Janitor) sweepDayLocked(ctx context.Context, cutoff time.Time) (int, error) {
	days, err := sweepDays(ctx, j.SQL, cutoff)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, day := range days {
		n, err := j.sweepDay(ctx, day, cutoff)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// sweepDays 无锁预查本周期会删到行的 UTC 日（升序去重），筛选与删除同一口径：
// 到期、无告警引用、无时序证据与已出告警锚点引用（withoutTemporalEvidence 的 SQL 形态）。
func sweepDays(ctx context.Context, db *stdsql.DB, cutoff time.Time) ([]time.Time, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT (ts AT TIME ZONE 'utc')::date FROM events e
 WHERE ts < $1
 AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.event_id = e.id)
 AND NOT EXISTS (SELECT 1 FROM temporal_detections d WHERE d.anchor_id = e.id AND d.alert_id IS NOT NULL)
 AND NOT EXISTS (SELECT 1 FROM temporal_evidence v WHERE v.event_id = e.id)`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var days []time.Time
	for rows.Next() {
		var day time.Time
		if err := rows.Scan(&day); err != nil {
			return nil, err
		}
		day = day.UTC()
		if !slices.Contains(days, day) {
			days = append(days, day)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(days, func(a, b int) bool { return days[a].Before(days[b]) })
	return days, nil
}

// sweepDay 清理单独一天：该日的排他生命周期锁由独立事务全程持有（覆盖全部批次），
// 选批与删除沿用 ent 的自动提交（与无锁路径同一语句），锁不在批事务里但由外层事务罩住。
// 一天拿一次锁（逐日升序、一次一日，不存在跨日持锁），批间让出时间片。
func (j *Janitor) sweepDay(ctx context.Context, day, cutoff time.Time) (int, error) {
	lockTx, err := j.SQL.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = lockTx.Rollback() }()
	if _, err := lockTx.ExecContext(ctx, `SET LOCAL lock_timeout = '`+eventpart.LockTimeout+`'`); err != nil {
		return 0, err
	}
	if err := eventpart.LifecycleLockExclusive(ctx, lockTx, day); err != nil {
		return 0, err
	}
	lo, hi := day, day.AddDate(0, 0, 1)
	total := 0
	for {
		ids, err := j.DB.Event.Query().
			Where(event.TsGTE(lo), event.TsLT(hi), event.TsLT(cutoff),
				event.Not(event.HasAlerts()), withoutTemporalEvidence).
			Limit(batchSize).
			IDs(ctx)
		if err != nil || len(ids) == 0 {
			return total, err
		}
		n, err := j.DB.Event.Delete().Where(event.IDIn(ids...), event.TsLT(cutoff)).Exec(ctx)
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

// sweepBatched 是无 *sql.DB 部署的原有清理路径（整批选删，无生命周期锁），
// 语句与原实现一致，仅从 sweep 拆出。
func (j *Janitor) sweepBatched(ctx context.Context, cutoff time.Time) (int, error) {
	total := 0
	for {
		ids, err := j.DB.Event.Query().
			Where(event.TsLT(cutoff), event.Not(event.HasAlerts()), withoutTemporalEvidence).
			Order(ent.Asc(event.FieldTs)).
			Limit(batchSize).
			IDs(ctx)
		if err != nil || len(ids) == 0 {
			return total, err
		}
		n, err := j.DB.Event.Delete().Where(event.IDIn(ids...), event.TsLT(cutoff)).Exec(ctx)
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

// retireExpired 是 Run 里退役步骤的包装：先取到期日子的同日生命周期排他锁，再跑
// eventpart.Retire（R1/R2）。
//
// Retire 自己不取生命周期锁（裸语义供测试与在线迁移直接使用）；janitor 把「上界不晚于
// cutoff 的日分区」按 UTC 日升序取齐事务级排他锁，在锁内跑完整个 Retire 再释放：
//   - 与当日引用写入者（共享锁）互斥：退役复制 pinned 集合（PinnedIDs）期间不会再有新
//     alert / evidence 指向将被丢弃的行，复制出的证据集合在删除前不再变化；
//   - 与 restore（会话级排他锁）、swap（重写事务排他锁）互斥：不会穿进 restore 的块间隙
//     （R2），也不会与分区重建交错。
//
// 锁与 Retire 各用各的连接（锁在独立短事务里持有，Retire 内部自管分区事务）。等待带
// lock_timeout 防呆：当日有 restore 在跑就本次失败，下个周期重试，不无限堵住清理循环。
func (j *Janitor) retireExpired(ctx context.Context, cutoff time.Time) (int, int64, error) {
	days, err := retireWindowDays(ctx, j.SQL, cutoff)
	if err != nil {
		return 0, 0, err
	}
	if len(days) == 0 {
		return eventpart.Retire(ctx, j.SQL, cutoff)
	}
	tx, err := j.SQL.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout = '`+eventpart.LockTimeout+`'`); err != nil {
		return 0, 0, err
	}
	if err := eventpart.LifecycleLockExclusive(ctx, tx, days...); err != nil {
		return 0, 0, err
	}
	n, dropped, err := eventpart.Retire(ctx, j.SQL, cutoff)
	if err != nil {
		return n, dropped, err
	}
	return n, dropped, tx.Commit()
}

// retireWindowDays 列出上界不晚于 cutoff 的日分区（与 eventpart.Retire 的判定同式），
// 按升序。锁集与 Retire 的作用集在这里对齐；对齐之后新出现的到期分区（正常运维不会
// 有）由 Retire 照常处理但不在锁内，留给下个周期收敛。
func retireWindowDays(ctx context.Context, db *stdsql.DB, cutoff time.Time) ([]time.Time, error) {
	rows, err := db.QueryContext(ctx, `SELECT c.relname FROM pg_inherits i
 JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = to_regclass($1)`, eventpart.Parent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var days []time.Time
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		day, ok := dailyPartitionDay(name)
		if !ok || day.AddDate(0, 0, 1).After(cutoff) {
			continue
		}
		days = append(days, day)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(days, func(a, b int) bool { return days[a].Before(days[b]) })
	return days, nil
}

// dailyPartitionDay 解析 events_pYYYYMMDD 形态的日分区名（UTC 零点）；其余分区名
// （默认分区、月归档、暂存表）返回 false。
func dailyPartitionDay(name string) (time.Time, bool) {
	const prefix = "events_p"
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+8 {
		return time.Time{}, false
	}
	day, err := time.Parse("20060102", strings.TrimPrefix(name, prefix))
	if err != nil {
		return time.Time{}, false
	}
	return day.UTC(), true
}

// 时序前序事件不一定直接挂告警，仍属于告警证据。并发删除的最终保护：老表靠外键，分区表靠 openxdr_events_release 触发器。
func withoutTemporalEvidence(selector *sql.Selector) {
	detections := sql.Table("temporal_detections")
	selector.Where(sql.NotExists(sql.Select(detections.C("anchor_id")).From(detections).
		Where(sql.And(sql.ColumnsEQ(detections.C("anchor_id"), selector.C(event.FieldID)), sql.NotNull(detections.C("alert_id"))))))
	evidence := sql.Table("temporal_evidence")
	selector.Where(sql.NotExists(sql.Select(evidence.C("event_id")).From(evidence).
		Where(sql.ColumnsEQ(evidence.C("event_id"), selector.C(event.FieldID)))))
}

// sweepTemporalGaps 清理过期的时序求值缺口（temporal_evaluation_gaps，R6）。
// gap 是诊断记录，按自身 created_at 的保留期（GapRetention）清理，不 JOIN events：
// 冷归档 swap 把事件移出热表后，retire 的「日分区 − 暂存」差集清理与逐行删除触发器
// （只在热行 DELETE 时触发）都看不到这些事件的 gap，清理责任在这里按诊断时间独立执行。
// GapRetention ≤ 0（TEMPORAL_GAP_RETENTION_DAYS=0）关闭。
func (j *Janitor) sweepTemporalGaps(ctx context.Context) (int64, error) {
	if j.GapRetention <= 0 || j.SQL == nil {
		return 0, nil
	}
	return temporal.PruneGaps(ctx, j.SQL, j.GapRetention)
}

// 至少保留 48 小时，覆盖 24 小时运行令牌、去重和事件配额窗口；复核证据不清理。
func (j *Janitor) sweepDecoys(ctx context.Context) (int, error) {
	if j.Retention <= 0 {
		return 0, nil
	}
	retention := max(j.Retention, 48*time.Hour)
	cutoff := time.Now().Add(-retention)
	total := 0
	for {
		ids, err := j.DB.DecoyObservation.Query().Where(decoyobservation.ReceivedAtLT(cutoff), decoyobservation.IncidentIDIsNil()).Limit(batchSize).IDs(ctx)
		if err != nil || len(ids) == 0 {
			return total, err
		}
		// 删除时再次检查复核引用，避免查询与删除之间人工提交的证据被清掉。
		n, err := j.DB.DecoyObservation.Delete().Where(decoyobservation.IDIn(ids...), decoyobservation.ReceivedAtLT(cutoff), decoyobservation.IncidentIDIsNil()).Exec(ctx)
		total += n
		if err != nil || len(ids) < batchSize {
			return total, err
		}
	}
}
