package eventarchive

import (
	"context"
	"database/sql"
	"fmt"
)

// 运行状态。影子构建结束仍是 building（等对拍），对拍通过才 verified；
// 构建或对拍出错记 failed，error 列写原因。
const (
	StatusBuilding = "building"
	StatusVerified = "verified"
	StatusFailed   = "failed"
)

// schemaDDL 建冷归档的三张表：chunks（块）、runs（一轮影子归档的账）、locator（P2 的
// 「事件 id → 块」索引，见下方结构注释）。这些表都不引用 events（冷归档与 events 没有
// 任何外键或触发器关系）：阶段 A 只读 events，写这三张表；events 的行、索引与分区一概不碰。
//
// id_bloom 是阶段 B2 加的**可空**列（块内事件 id 的 Bloom filter）；老库靠后面那条
// ADD COLUMN IF NOT EXISTS 幂等补上。P2 起 Locate/Exists 走 locator 索引，不再读块元数据
// 逐块过滤，该列只作为块的随行过滤元数据继续写入（不参与读取路径）。
// 已有列、已有约束一概不动，也不加 NOT NULL。
const schemaDDL = `CREATE TABLE IF NOT EXISTS event_archive_chunks (
 id uuid PRIMARY KEY,
 run_id uuid NOT NULL,
 seq int NOT NULL,
 day date NOT NULL,
 class_uid int NOT NULL,
 source text NOT NULL,
 first_ts timestamptz NOT NULL,
 last_ts timestamptz NOT NULL,
 event_count int NOT NULL,
 format smallint NOT NULL,
 codec smallint NOT NULL,
 plain_len bigint NOT NULL,
 payload_len bigint NOT NULL,
 plain_sha256 bytea NOT NULL,
 payload bytea NOT NULL,
 id_bloom bytea,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE (run_id, seq));
ALTER TABLE event_archive_chunks ADD COLUMN IF NOT EXISTS id_bloom bytea;
CREATE INDEX IF NOT EXISTS event_archive_chunks_day ON event_archive_chunks (day, class_uid, source);
CREATE INDEX IF NOT EXISTS event_archive_chunks_ts ON event_archive_chunks (first_ts, last_ts);
CREATE TABLE IF NOT EXISTS event_archive_runs (
 id uuid PRIMARY KEY,
 started_at timestamptz,
 finished_at timestamptz,
 status text NOT NULL,
 day_from date NOT NULL,
 day_to date NOT NULL,
 classes int[] NOT NULL,
 sources text[] NOT NULL,
 scanned bigint NOT NULL DEFAULT 0,
 archived bigint NOT NULL DEFAULT 0,
 pinned_skipped bigint NOT NULL DEFAULT 0,
 chunks int NOT NULL DEFAULT 0,
 error text,
 detail jsonb);
CREATE TABLE IF NOT EXISTS event_archive_locator (
    event_id uuid NOT NULL,
    chunk_id uuid NOT NULL REFERENCES event_archive_chunks(id) ON DELETE CASCADE,
    PRIMARY KEY (event_id, chunk_id));
CREATE INDEX IF NOT EXISTS event_archive_locator_chunk ON event_archive_locator (chunk_id)`

// event_archive_locator 是 P2 加的「事件 id → 块」索引表：主键 (event_id, chunk_id) 让
// 按事件 id 定位从「扫全部块元数据 + Bloom 过滤」变成一次 btree 探查；chunk_id 上的
// 第二索引服务于按块查成员（Verify 的集合校验与覆盖性推导的反连接）。
//
// 结构上刻意不冗余 run_id：按 run/day 列块经 event_archive_chunks 取，主键已覆盖
// event_id 前缀探查，不再建同前缀的单列索引。同一事件 id 跨 run 多副本合法
// （多次 shadow 重叠归档），每副本一行；同块内 (event_id, chunk_id) 唯一。
// locator 行与块 INSERT 在同一事务写入（shadow.go 的 writeChunk），块删掉时 CASCADE 连带消失。
// 老库升级同样走 EnsureSchema：新表 CREATE IF NOT EXISTS 幂等补上，历史块由
// backfill-locator 一次性回填。

// EnsureSchema 建冷归档的三张表与索引，幂等，可重复执行；老库上补加 `id_bloom` 列
// （`ADD COLUMN IF NOT EXISTS`，只加可空列，不改已有列、不加约束），
// event_archive_locator 直接 CREATE IF NOT EXISTS 补表（新表，无需 ALTER）。
// 不改 events、不加指向 events 的外键；payload 允许 TOAST，不给大字段建索引。
func EnsureSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, schemaDDL); err != nil {
		return fmt.Errorf("建冷归档表: %w", err)
	}
	return nil
}
