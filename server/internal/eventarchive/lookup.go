package eventarchive

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/eventpart"
)

// 阶段 B2（按 ID 定位）+ P2（locator 索引）。
//
// 每块冷块的事件 id → 块映射记在 event_archive_locator（主键 (event_id, chunk_id)），
// Locate / Exists 先在主键上做一次 btree 探查拿到候选块（同一事件跨 run 多副本时是几行，
// 不是全库块元数据），再逐块 load/Decode/check 后精确比对 id：
//   - 索引只负责「找到候选块」，不证明载荷健康——命中必须以「块解出来确实是这条事件」为准；
//   - 块自洽校验（check）与逐事件精确比对**保留**：索引行指向的块解不出该 id 是数据不一致，
//     如实报错，不当作「不存在」。
//
// 本文件与阶段 A/B1 的关系：
//   - 只读 event_archive_chunks / event_archive_locator（`Materialize` 额外往 events 插入
//     缺失的行，不删不改）；
//   - 不产告警、不动派生表：证据物化是复制，不是重放。
//
// 重传判重（阶段 C 已接线，见 docs/event-archive.md 第 9 节）的调用方是接入路径：
// 它只经 main.go 的适配器调用 Exists 与 Boundary，且只在「事件时间不晚于归档边界」时
// 发按 ID 查询；本包不知道自己被谁调用。

// ErrLocatorIncomplete 表示「冷层的 locator 覆盖性没有证明（持久完成标记未发布，且
// 反连接仍发现没有 locator 行的块），探查未命中时**不能**断言冷层没有这条事件」。
// 覆盖性见 backfill.go：标记 archive.locator.complete 未发布时退回反连接推导。
// 未回填期间未命中一律返回本错误，由调用方决定怎么处理（接入判重按既有策略 fail-open）。
// 命中语义不受覆盖性影响：索引行指向的块解出该 id 就是命中。
var ErrLocatorIncomplete = errors.New("locator 索引不完整（存在未回填的冷块），无法确认事件不存在")

// Locate 按事件 ID 找一条冷事件。found=false 且 err=nil 表示冷层确实没有这条事件。
// 冷层不可用（没有表）返回 ErrNoSchema；块损坏返回错误（带块 id），不得当作「没有这条事件」。
//
// 候选块来自 event_archive_locator 主键探查（event_id = $1），按索引顺序逐块解压比对；
// 同一 id 的跨 run 多副本内容一致（都是从同一条热行编码的），命中任一副本即可。
//
// 判定的强度分三档，调用方必须分清：
//   - found=true：确定存在，返回的就是冷块里的那条事件；
//   - found=false + err=nil：locator 覆盖完整（持久完成标记为 true，或反连接推导无缺行块），
//     且索引里没有这个 id，确定冷层没有——R4 起证明从「每次未命中全库反连接」变为
//     「持久标记 + 写入原子性」（新块经 writeChunk 同事务携带 locator，删块连带 CASCADE）；
//   - err=ErrLocatorIncomplete：标记未发布，索引未命中且反连接仍发现缺行块，**无法确认**不存在。
//
// 与 Query 一样，块损坏整体报错、不跳过：跳过坏块等于把「查不到」伪装成「不存在」。
func Locate(ctx context.Context, db *sql.DB, id uuid.UUID) (Event, bool, error) {
	if db == nil {
		return Event{}, false, errors.New("冷归档定位需要数据库连接")
	}
	return locate(ctx, db, id)
}

// LocateTx 是 Locate 的事务内版本（R1 引用补链用）：在引用写入事务自己的快照里定位，
// 保证「冷层有这条事件」与随后同事务的物化、引用写入看到同一份状态。
// 语义与 Locate 一致（含三档判定强度）。
func LocateTx(ctx context.Context, tx *sql.Tx, id uuid.UUID) (Event, bool, error) {
	if tx == nil {
		return Event{}, false, errors.New("冷归档定位需要事务")
	}
	return locate(ctx, tx, id)
}

// dbQueryer 是 locate 的最小查询接口，*sql.DB 与 *sql.Tx 都满足。
type dbQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func locate(ctx context.Context, q dbQueryer, id uuid.UUID) (Event, bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT chunk_id FROM event_archive_locator WHERE event_id = $1`, id)
	if err != nil {
		return Event{}, false, wrapErr(err, "探查 locator 索引")
	}
	var chunkIDs []uuid.UUID
	for rows.Next() {
		var cid uuid.UUID
		if err := rows.Scan(&cid); err != nil {
			rows.Close()
			return Event{}, false, wrapErr(err, "读取 locator 候选块")
		}
		chunkIDs = append(chunkIDs, cid)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Event{}, false, wrapErr(err, "探查 locator 索引")
	}
	rows.Close()

	if len(chunkIDs) == 0 {
		// 索引未命中：在「确定不存在」之前先证明覆盖了全部冷块。R4 起先读持久完成标记
		//（settings 一次主键探查）——true 表示全库块都已带 locator（回填收尾核验过，
		// 之后新块原子携带、删块 CASCADE），未命中即可确定不存在，不再对全部块元数据做
		// 反连接（3.8 万块规模下每次未命中都全扫，D1 复活）。标记缺失/false 时保持原判定：
		// 反连接查出缺口报 ErrLocatorIncomplete，由调用方按既有策略处理（接入 fail-open）。
		complete, err := locatorComplete(ctx, q)
		if err != nil {
			return Event{}, false, err
		}
		if complete {
			return Event{}, false, nil
		}
		missing, _, err := locatorIncompleteCount(ctx, q, 1)
		if err != nil {
			return Event{}, false, err
		}
		if missing > 0 {
			return Event{}, false, fmt.Errorf("%w：事件 %s 不在索引里，且仍有冷块没有 locator 行（先跑 eventarchive backfill-locator）",
				ErrLocatorIncomplete, id)
		}
		return Event{}, false, nil
	}

	for _, cid := range chunkIDs {
		ch, err := loadChunkByID(ctx, q, cid)
		if err != nil {
			return Event{}, false, err
		}
		events, err := ch.Block.Decode()
		if err != nil {
			return Event{}, false, fmt.Errorf("解码冷块 %s（seq %d，%s/%s）: %w",
				ch.ID, ch.Seq, ch.Day.Format(time.DateOnly), ch.Source, err)
		}
		// 块自洽同样要核：列与内容不符说明归档被改过，此时「解出来没有」不足以支撑「不存在」。
		if err := ch.check(events); err != nil {
			return Event{}, false, fmt.Errorf("冷块 %s（seq %d）内容与头部不符: %w", ch.ID, ch.Seq, err)
		}
		for _, e := range events {
			if e.ID == id {
				return e, true, nil
			}
		}
	}
	// 索引说这个 id 在这些块里，块解出来却没有：locator 与载荷不一致（错指块 / 改过的块）。
	// 这不是「不存在」，是数据不一致，必须报错。
	return Event{}, false, fmt.Errorf("locator 与冷块内容不一致：事件 %s 的索引行指向 %d 块（%s 等），"+
		"逐块解压比对都没有这条事件", id, len(chunkIDs), chunkIDs[0])
}

// Exists 是 Locate 的便捷包装：存在返回 true。错误语义同 Locate——块损坏、冷层不可用
// 与 ErrLocatorIncomplete 都是错误，只有「确实没有」才返回 (false, nil)。
//
// 重传判重（阶段 C 已接线）只接受这种口径：拿 false 就必须能确定冷层没有，
// 拿不准时报错比静默当成新事件安全（接入侧对错误按 fail-open 处理，见 ingest/archive.go）。
func Exists(ctx context.Context, db *sql.DB, id uuid.UUID) (bool, error) {
	_, found, err := Locate(ctx, db, id)
	return found, err
}

// Boundary 返回冷层最晚的事件时间（max(last_ts)）以及归档是否非空。它是接入侧
// 「时间闸门」的唯一依据：事件时间晚于这个边界就不可能在冷块里，连 Exists 都不用发
// （接入峰值约 3000 条/秒，逐条查块元数据不可接受）。
//
// 只读一条聚合，不解压、不读 locator，也不缓存：边界该由调用方按自己的节奏缓存
// （ingest 侧 60 秒），这里保持无状态、与 Locate / Query 一样只报告当下的事实。
// 冷层没有表时返回 ErrNoSchema（部署状态，不是数据错误）；ok=false 只表示还没有任何块。
func Boundary(ctx context.Context, db *sql.DB) (last time.Time, ok bool, err error) {
	if db == nil {
		return time.Time{}, false, errors.New("冷归档边界查询需要数据库连接")
	}
	var latest sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT max(last_ts) FROM event_archive_chunks`).Scan(&latest); err != nil {
		return time.Time{}, false, wrapErr(err, "查询冷归档边界")
	}
	if !latest.Valid {
		return time.Time{}, false, nil
	}
	return latest.Time.UTC(), true, nil
}

// Materialize 把一条冷事件物化回 events 普通行，供「冷事件重新成为证据」时使用。
// 返回 inserted=false 表示 events 里本来就有（幂等）。
// 不经过检测器：不产规则命中、不产告警、不改任何派生表。
//
// 冷层找不到这条事件时返回 (false, nil)，**不插入任何行**；此时它与「events 里本来就有」
// 的返回值相同，要区分两者用 Locate / Exists 另查一次（插入后 events 里必有该行，
// 冷层有则 Locate 仍能命中）。索引覆盖不完整时未命中会返回 ErrLocatorIncomplete
// （拿不准就不动 events）。
//
// 冷块保持不可变：物化是复制，不回写、不删块、不改 run。插入是单事务里的一条
// `INSERT ... ON CONFLICT DO NOTHING`，并发重复物化最多插一行，不会产生第二行，
// 也不会覆盖 events 里已有的行。events 的 foreign key（asset_id → assets）与分区路由
// 仍由数据库判定：目标资产已不存在时报错，不静默丢字段。
//
// R1 起，独立调用本入口（CLI materialize）也取该事件归属日的共享生命周期锁：
// 与同日 swap / retire 的排他锁互斥，插入不会恰好落进某次切换的暂存复制与分区替换之间，
// 被「物化完成但随即随旧分区消失」吃掉。锁在插入前、定位后取（ts 要先从冷层拿到）。
func Materialize(ctx context.Context, db *sql.DB, id uuid.UUID) (inserted bool, err error) {
	e, found, err := Locate(ctx, db, id)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("物化事件 %s: %w", id, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := eventpart.LifecycleLockShared(ctx, tx, e.Ts); err != nil {
		return false, fmt.Errorf("物化事件 %s: %w", id, err)
	}
	inserted, err = insertEventTx(ctx, tx, e)
	if err != nil {
		return false, fmt.Errorf("物化事件 %s: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("物化事件 %s: %w", id, err)
	}
	return inserted, nil
}

// MaterializeTx 在调用方事务内把一条冷事件物化回 events（R1 引用补链的事务内版本）。
// 定位与插入同事务：调用方快照里「冷层有这条事件」与随后的物化、引用写入一致。
// 不取生命周期锁——调用方（引用写入事务）必须已经持有该事件归属日的共享锁。
func MaterializeTx(ctx context.Context, tx *sql.Tx, id uuid.UUID) (inserted bool, err error) {
	e, found, err := LocateTx(ctx, tx, id)
	if err != nil || !found {
		return false, err
	}
	return insertEventTx(ctx, tx, e)
}

// insertEventTx 是单行物化插入的主体（Materialize 与 MaterializeTx 共用）：
// 一条 INSERT ... ON CONFLICT DO NOTHING，列映射与 Restore 的批量路径一致。
func insertEventTx(ctx context.Context, tx *sql.Tx, e Event) (bool, error) {
	res, err := tx.ExecContext(ctx, `INSERT INTO events
 (id, ts, class_uid, source, asset_id, process_guid, parent_process_guid, username, conn_tuple, raw)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,
		e.ID, e.Ts, e.ClassUID, e.Source, nullableUUID(e.AssetID), nullableUUID(e.ProcessGUID),
		nullableUUID(e.ParentProcessGUID), nullableString(e.Username), nullableString(e.ConnTuple), e.Raw)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// EnsureHotEvents 确保将要被引用（alerts / temporal_evidence / 已出告警的时序锚点）的
// 事件都在热表（R1 引用补链）。调用方必须已持有这些事件归属日的共享生命周期锁
// （LockDaysShared）——锁内重读才作数：
//
//   - 热行在 → 照常写引用；
//   - 热行不在 → 按经 LocateTx 在冷层定位，并在**同一事务**物化回热表（单行幂等插入，
//     引用随之指向热行，证据页面对热表查询可访问）；
//   - 冷层也没有 / 定位状态说不清（ErrLocatorIncomplete）/ 块损坏 → 返回错误，
//     调用方必须让整个引用事务失败，**不提交悬空引用**。
//
// ingest 热路径下目标事件是本事务刚插入的行，热行必命中，本函数退化为一次存在性核对，
// 零行为差异；锁由调用方在插入事件前取（store 的时序窗口 span），这里只补「锁内重读」
// 这一步对老事件（时序候选/锚点）才有实际作用的补链。
func EnsureHotEvents(ctx context.Context, tx *sql.Tx, ids ...uuid.UUID) error {
	seen := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		var hot bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE id = $1)`, id).
			Scan(&hot); err != nil {
			return fmt.Errorf("核对引用目标 %s 是否在热表: %w", id, err)
		}
		if hot {
			continue
		}
		e, found, err := LocateTx(ctx, tx, id)
		if err != nil {
			return fmt.Errorf("引用目标 %s 不在热表且冷层定位失败，拒绝写入悬空引用: %w", id, err)
		}
		if !found {
			return fmt.Errorf("引用目标 %s 既不在热表也没有冷副本，拒绝写入悬空引用", id)
		}
		if _, err := insertEventTx(ctx, tx, e); err != nil {
			return fmt.Errorf("把冷事件 %s 物化回热表失败，拒绝写入悬空引用: %w", id, err)
		}
	}
	return nil
}

// nullableUUID / nullableString 把可空列原样交给 database/sql：nil 就是 SQL NULL，
// 不把 NULL 折成零值。
func nullableUUID(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return *id
}

func nullableString(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
