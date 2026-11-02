package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// P2 的一次性迁移：给「locator 索引出现之前」写入的冷块补 event_archive_locator 行。
//
// 迁移完成态不建新状态表，第一层用覆盖性推导表达：
//
//	「没有缺 locator 行的块」 == 「迁移完成」
//
// 即反连接 `chunks LEFT JOIN locator ... WHERE l IS NULL` 数量为 0。它便宜的原因：
//   - chunks 是 hash/seq 扫一遍元数据（不碰 payload，不 TOAST 解压）；
//   - locator 的 chunk_id 上有 btree 索引（event_archive_locator_chunk），probe 一行
//     索引就能判断「该块有没有行」；每块至少 1 条事件，因此有行的块一定不缺、没行的块
//     一定是没回填过（或回填被回滚）——不存在「部分块回填了一半行还成立」的中间态：
//     每块的回填是单事务（见下），回滚后整块回到 0 行；
//   - 该推导同时是显式诊断入口（LocatorMissing / BackfillLocator 收尾核验）。
//
// 但 R4 之前该推导还被挂在 Locate/Exists 的**每次未命中**路径上：优化器无法用 LIMIT 1
// 短路「存在无 locator 行的块」的全量判定，3.8 万块规模下每次未命中都扫全部块元数据
//（D1 复活）。R4 起未命中路径只读一个持久完成标记，反连接退回迁移与诊断用途：
//
//	标记 settings[archive.locator.complete] = true：
//	  由 BackfillLocator 收尾核验（覆盖性推导成立）通过后发布；此后新块经 writeChunk
//	  与 locator 行同事务写入（原子携带），删块连带 CASCADE，覆盖性天然维持——
//	  标记不需要随块写入刷新。
//	标记缺失 / false：
//	  未命中回到反连接判定：查出缺行块报 ErrLocatorIncomplete（保守，接入 fail-open）。
//
// 已知风险（接受）：任何人手工 DELETE locator 行而不经过回填，标记不会自动失效，
// 未命中仍答「确定不存在」。操作规程：动过 locator 行（手工增删）后必须重跑
// `eventarchive backfill-locator` 校正标记——它会重列缺行块、重走收尾核验后重发布。
// CLI 的 backfill-locator 输出会显式打印标记状态提醒这一点。

// locatorCompleteKey 是 locator 覆盖完成标记的 settings 键（bool）。
const locatorCompleteKey = "archive.locator.complete"

// locatorComplete 读 locator 覆盖完成标记。行缺失或载荷不是布尔都按 false 处理：
// 保守方向是走反连接推导（旧路径），不会把「读不懂的标记」当成已完成。
// 查询句柄同时覆盖 *sql.DB 与 *sql.Tx（LocateTx 在引用事务内做同样的判定）。
func locatorComplete(ctx context.Context, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}) (bool, error) {
	var raw []byte
	err := q.QueryRowContext(ctx, `SELECT value FROM settings WHERE id = $1`, locatorCompleteKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("读 locator 完成标记: %w", err)
	}
	var done bool
	if json.Unmarshal(raw, &done) != nil {
		return false, nil
	}
	return done, nil
}

// LocatorComplete 是 locatorComplete 的只读导出版（CLI backfill-locator 输出用）。
func LocatorComplete(ctx context.Context, db *sql.DB) (bool, error) {
	return locatorComplete(ctx, db)
}

// setLocatorComplete 置 locator 覆盖完成标记。true 只能由 BackfillLocator 的收尾核验
// 发布；发现缺口（待回填清单非空、收尾核验失败）先撤成 false，让未命中路径回到
// 反连接的保守判定。单行 upsert，不与块写入同事务：标记晚于事实置位只会更保守
// （ErrLocatorIncomplete），绝不会单独放行错误的「确定不存在」。
func setLocatorComplete(ctx context.Context, db *sql.DB, done bool) error {
	value := "false"
	if done {
		value = "true"
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO settings (id, value, updated_at)
 VALUES ($1, $2::jsonb, now())
 ON CONFLICT (id) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		locatorCompleteKey, value); err != nil {
		return fmt.Errorf("写 settings[%s]: %w", locatorCompleteKey, err)
	}
	return nil
}

// locatorIncompleteCount 数「没有任何 locator 行的块」（覆盖性推导的反连接）。
// limit<=0 数全量；>0 时最多查 limit 行就停（只用于「是否存在」的判定，LIMIT 1 即可）。
// 查询句柄同时覆盖 *sql.DB 与 *sql.Tx（LocateTx 在引用事务内做同样的覆盖性判定）。
// 返回 (数量, 是否被 limit 截断, 错误)；表不存在时包成 ErrNoSchema。
func locatorIncompleteCount(ctx context.Context, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}, limit int) (int64, bool, error) {
	query := `SELECT count(*) FROM (
 SELECT c.id FROM event_archive_chunks c
 LEFT JOIN event_archive_locator l ON l.chunk_id = c.id
 WHERE l.chunk_id IS NULL`
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}
	query += ") t"
	var n int64
	if err := q.QueryRowContext(ctx, query).Scan(&n); err != nil {
		return 0, false, wrapErr(err, "判定 locator 覆盖性")
	}
	return n, limit > 0 && n >= int64(limit), nil
}

// LocatorMissing 返回当前没有任何 locator 行的冷块数量（覆盖性推导的反连接，
// 只读，不回填）。CLI 的 backfill-locator 在不加 -confirm 时用它报告缺口。
func LocatorMissing(ctx context.Context, db *sql.DB) (int64, bool, error) {
	return locatorIncompleteCount(ctx, db, 0)
}

// BackfillLocator 给所有缺 locator 行的冷块一次性回填索引行，返回补了索引的块数。
//
// 流程：列出无 locator 行的块 → 逐块 load/Decode/check（成员集合与块内容自洽才可用）
// → 每块一个事务 INSERT 该块的 locator 行 → 全部完成后重新核对覆盖性推导成立。
//
//   - 幂等：已回填的块不会再出现在「缺行」清单里，重跑直接返回 0；
//   - 不要求热行存在：块直接解码回填，已 swap（events 里已删）的旧块同样处理；
//   - 空冷库（没有任何块）直接完成，返回 (0, nil)；
//   - 块解码或校验失败：返回错误并带上块 id，**该块一行不写**（单块事务）；
//     已完成的其他块保留，重跑只处理剩余的块；
//   - 每块的行一次性写入：中途任何失败都是整块回滚，不会留下「半份索引」，
//     覆盖性推导因此始终可用（见函数头）。
//
// 已有 locator 行的块不重算（不重复插入、不修正既有行）；既有行的正确性由 Verify
// 的集合校验负责。跨 run 重复副本（同一 event_id 在多个块）天然满足主键约束，
// 每块写自己的 (event_id, chunk_id)。
//
// 前提（P6 的运维手册写死，这里只声明）：执行回填时**并发新块写入必须已经走原子
// 新路径**（writeChunk 同事务写 locator）——旧版本写入进程必须先退出，否则发布完成
// 标记之后又出现无索引新块，收尾核验会失败（如实报错，不宣布完成）。
//
// 标记生命周期（R4）：待回填清单非空时先撤完成标记（此后任一步失败，标记保持
// false，未命中维持反连接判定）；收尾核验通过才发布 true。
func BackfillLocator(ctx context.Context, db *sql.DB) (blocks int64, err error) {
	if db == nil {
		return 0, fmt.Errorf("locator 回填需要数据库连接")
	}
	// 只列缺行的块 id（反连接），顺序读块表 + locator 索引 probe，不碰 payload。
	rows, err := db.QueryContext(ctx, `SELECT c.id FROM event_archive_chunks c
 LEFT JOIN event_archive_locator l ON l.chunk_id = c.id
 WHERE l.chunk_id IS NULL ORDER BY c.id`)
	if err != nil {
		return 0, wrapErr(err, "列出缺 locator 行的冷块")
	}
	var pending []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, wrapErr(err, "读取缺 locator 行的块 id")
		}
		pending = append(pending, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, wrapErr(err, "列出缺 locator 行的冷块")
	}
	rows.Close()

	if len(pending) > 0 {
		// 有缺口：先撤完成标记。这一步之后无论解码、回填还是收尾核验失败，
		// 标记都保持 false——未命中路径维持反连接/ErrLocatorIncomplete 的保守行为。
		if err := setLocatorComplete(ctx, db, false); err != nil {
			return 0, err
		}
	}

	src := &sqlSource{db: db}
	for _, id := range pending {
		ch, err := src.load(ctx, id)
		if err != nil {
			return blocks, err
		}
		events, err := ch.Block.Decode()
		if err != nil {
			return blocks, fmt.Errorf("解码冷块 %s（seq %d，%s）: %w",
				ch.ID, ch.Seq, ch.Day.Format("2006-01-02"), err)
		}
		if err := ch.check(events); err != nil {
			return blocks, fmt.Errorf("冷块 %s（seq %d）内容与头部不符: %w", ch.ID, ch.Seq, err)
		}
		ids := make([]uuid.UUID, len(events))
		for i, e := range events {
			ids[i] = e.ID
		}
		if err := insertLocator(ctx, db, ch.ID, ids); err != nil {
			return blocks, fmt.Errorf("回填冷块 %s（seq %d）的 locator 行: %w", ch.ID, ch.Seq, err)
		}
		blocks++
	}

	// 收尾核对：覆盖性推导必须成立（0 块缺行）。中途有并发旧路径写入新块时这里会失败，
	// 如实报错而不是宣布迁移完成。
	missing, _, err := locatorIncompleteCount(ctx, db, 0)
	if err != nil {
		return blocks, err
	}
	if missing != 0 {
		// 覆盖性被打破（并发旧路径写入/手工删除后未回填）：先撤标记再报错。
		if serr := setLocatorComplete(ctx, db, false); serr != nil {
			return blocks, fmt.Errorf("回填后仍有 %d 块没有 locator 行，且撤销完成标记失败: %w", missing, serr)
		}
		return blocks, fmt.Errorf("回填后仍有 %d 块没有 locator 行（并发写入或手工动过 locator），迁移未完成", missing)
	}
	// 覆盖性成立：发布完成标记。此后未命中路径读这一个键即可确定不存在（R4）。
	if err := setLocatorComplete(ctx, db, true); err != nil {
		return blocks, fmt.Errorf("发布 locator 覆盖完成标记: %w", err)
	}
	return blocks, nil
}

// insertLocator 在单个事务里写一块的全部 locator 行（typed unnest，参数个数固定为 2，
// 与 writeChunk / insertEvents 同风格）。不加 ON CONFLICT：主键 (event_id, chunk_id)
// 撞行说明这块已经回填过或数据不一致，宁可失败暴露，也不静默覆盖。
func insertLocator(ctx context.Context, db *sql.DB, chunkID uuid.UUID, eventIDs []uuid.UUID) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO event_archive_locator (event_id, chunk_id)
 SELECT u.event_id, $2::uuid FROM unnest($1::uuid[]) AS u(event_id)`, eventIDs, chunkID); err != nil {
		return err
	}
	return tx.Commit()
}
