package eventarchive

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/eventpart"
)

// idBatch 是向 events 回查整行字节时每批的事件数：不把全量 id 装进内存。
const idBatch = 500

// Report 是一轮影子归档的空间度量。数字全部来自真实查询，不做估算。
type Report struct {
	Run     Run
	Archive ArchiveSize
	Live    LiveSize
}

// ArchiveSize 是冷归档一侧：明文、payload 与两张新表的实际大小。
type ArchiveSize struct {
	Chunks          int64
	Events          int64
	PlainBytes      int64 // sum(plain_len)：未压缩明文
	PayloadBytes    int64 // sum(payload_len)：实际落盘的载荷字节
	Ratio           float64
	ChunkTotalBytes int64 // pg_total_relation_size：表 + TOAST + 索引
	ChunkDataBytes  int64 // pg_table_size：表 + TOAST
	ChunkIndexBytes int64 // pg_indexes_size
	RunsTotalBytes  int64
}

// LiveSize 是 events 一侧：被归档事件当前还在 events 里的整行字节，以及它们所在日分区的大小。
// Partitions 是**整分区**口径（含同一天没归档的事件与全部索引），与冷归档不是同一个分母。
type LiveSize struct {
	Events         int64
	Missing        int64
	RowBytes       int64
	Partitions     []PartitionSize
	PartitionBytes int64
}

// PartitionSize 是某一天的分区大小。日分区已退役（换成月归档分区或被清掉）时 Exists 为 false。
type PartitionSize struct {
	Day    time.Time
	Name   string
	Exists bool
	Rows   int64
	Bytes  int64
}

// Measure 统计一轮影子归档的前后数字（CLI 的 report 子命令；名为 Report 的类型即返回值）：
//
//   - 归档前：被归档的事件在 events 里还剩多少条、整行字节 sum(pg_column_size(t.*))，
//     以及它们所在日分区的 pg_total_relation_size（整分区口径）；
//   - 归档后：sum(plain_len)、sum(payload_len)、压缩比 ratio = plain/payload，
//     以及 event_archive_chunks 的 pg_total_relation_size（含 TOAST 与索引）。
//
// 全程只读。归档后 events 仍未被删，所以两个数字可以并列看，等阶段 B/C 才真正释放空间。
func Measure(ctx context.Context, db *sql.DB, runID uuid.UUID) (Report, error) {
	run, err := LoadRun(ctx, db, runID)
	if err != nil {
		return Report{}, err
	}
	r := Report{Run: run}
	if err := r.archive(ctx, db, runID); err != nil {
		return r, err
	}
	if err := r.live(ctx, db, runID); err != nil {
		return r, err
	}
	return r, nil
}

func (r *Report) archive(ctx context.Context, db *sql.DB, runID uuid.UUID) error {
	a := &r.Archive
	if err := db.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(event_count), 0),
 COALESCE(sum(plain_len), 0), COALESCE(sum(payload_len), 0)
 FROM event_archive_chunks WHERE run_id = $1`, runID).
		Scan(&a.Chunks, &a.Events, &a.PlainBytes, &a.PayloadBytes); err != nil {
		return fmt.Errorf("统计冷块: %w", err)
	}
	if a.PayloadBytes > 0 {
		a.Ratio = float64(a.PlainBytes) / float64(a.PayloadBytes)
	}
	if err := db.QueryRowContext(ctx, `SELECT
 COALESCE(pg_total_relation_size(to_regclass('event_archive_chunks')), 0),
 COALESCE(pg_table_size(to_regclass('event_archive_chunks')), 0),
 COALESCE(pg_indexes_size(to_regclass('event_archive_chunks')), 0),
 COALESCE(pg_total_relation_size(to_regclass('event_archive_runs')), 0)`).
		Scan(&a.ChunkTotalBytes, &a.ChunkDataBytes, &a.ChunkIndexBytes, &a.RunsTotalBytes); err != nil {
		return fmt.Errorf("统计冷归档表大小: %w", err)
	}
	return nil
}

// live 按块顺序取出被归档事件的 id，分批回查 events 的整行字节与条数；
// 再按块上的 day 查一次所在日分区的整分区大小。
func (r *Report) live(ctx context.Context, db *sql.DB, runID uuid.UUID) error {
	it := &chunkIter{db: db, runID: runID}
	batch := make([]string, 0, idBatch)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		var events, bytes int64
		if err := db.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(pg_column_size(e.*)), 0)
 FROM events e WHERE e.id = ANY($1::uuid[])`, literalUUIDs(batch)).Scan(&events, &bytes); err != nil {
			return fmt.Errorf("回查 events 整行字节: %w", err)
		}
		r.Live.Events += events
		r.Live.RowBytes += bytes
		batch = batch[:0]
		return nil
	}
	for {
		e, ok, err := it.next(ctx)
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		batch = append(batch, e.ID.String())
		if len(batch) >= idBatch {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	if r.Archive.Events > r.Live.Events {
		r.Live.Missing = r.Archive.Events - r.Live.Events
	}

	rows, err := db.QueryContext(ctx, `SELECT DISTINCT day FROM event_archive_chunks
 WHERE run_id = $1 ORDER BY day`, runID)
	if err != nil {
		return fmt.Errorf("列出冷块所在日: %w", err)
	}
	var days []time.Time
	for rows.Next() {
		var day time.Time
		if err := rows.Scan(&day); err != nil {
			rows.Close()
			return fmt.Errorf("读取冷块所在日: %w", err)
		}
		days = append(days, day.UTC())
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("列出冷块所在日: %w", err)
	}
	for _, day := range days {
		ps, err := partitionSize(ctx, db, day)
		if err != nil {
			return err
		}
		r.Live.Partitions = append(r.Live.Partitions, ps)
		r.Live.PartitionBytes += ps.Bytes
	}
	return nil
}

// partitionSize 取某天日分区的大小。分区名由 UTC 日推出（events_pYYYYMMDD），
// 已退役的日不再有日分区，就记 Exists=false、大小 0。
func partitionSize(ctx context.Context, db *sql.DB, day time.Time) (PartitionSize, error) {
	ps := PartitionSize{Day: day, Name: eventpart.DailyName(day)}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, ps.Name).Scan(&exists); err != nil {
		return ps, fmt.Errorf("查找分区 %s: %w", ps.Name, err)
	}
	ps.Exists = exists
	if !exists {
		return ps, nil
	}
	// 表名由 UTC 日推出，不是外部输入；大小与行数仍然走真实查询
	if err := db.QueryRowContext(ctx, fmt.Sprintf(`SELECT COALESCE(pg_total_relation_size('%[1]s'::regclass), 0),
 COALESCE((SELECT count(*) FROM %[1]s), 0)`, ps.Name)).Scan(&ps.Bytes, &ps.Rows); err != nil {
		return ps, fmt.Errorf("统计分区 %s: %w", ps.Name, err)
	}
	return ps, nil
}

// literalUUIDs 拼出 '{uuid,uuid}' 数组字面量：id 都是 uuid.UUID 生成的字符串，不含需要转义的字符。
func literalUUIDs(ids []string) string {
	return "{" + strings.Join(ids, ",") + "}"
}

// String 把度量排成可直接对比的一段文字。
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "run %s  状态 %s\n", r.Run.ID, r.Run.Status)
	fmt.Fprintf(&b, "口径：%s..%s（UTC 日闭区间），类别 %v，来源 %v\n",
		r.Run.DayFrom.Format(time.DateOnly), r.Run.DayTo.Format(time.DateOnly), r.Run.Classes, r.Run.Sources)
	fmt.Fprintf(&b, "候选 %d 条：归档 %d 条 / 被钉住跳过 %d 条\n", r.Run.Scanned, r.Run.Archived, r.Run.PinnedSkip)
	a := r.Archive
	fmt.Fprintf(&b, "冷归档：%d 块 / %d 条事件\n", a.Chunks, a.Events)
	fmt.Fprintf(&b, "  未压缩明文 sum(plain_len) = %d 字节（%s）\n", a.PlainBytes, humanBytes(a.PlainBytes))
	fmt.Fprintf(&b, "  实际载荷 sum(payload_len) = %d 字节（%s）\n", a.PayloadBytes, humanBytes(a.PayloadBytes))
	fmt.Fprintf(&b, "  压缩比 ratio = sum(plain_len)/sum(payload_len) = %s\n", ratioText(a.Ratio))
	fmt.Fprintf(&b, "  event_archive_chunks 总大小 %d 字节（%s，含 TOAST 与索引：表 %s + 索引 %s）\n",
		a.ChunkTotalBytes, humanBytes(a.ChunkTotalBytes), humanBytes(a.ChunkDataBytes), humanBytes(a.ChunkIndexBytes))
	fmt.Fprintf(&b, "  event_archive_runs 总大小 %d 字节（%s）\n", a.RunsTotalBytes, humanBytes(a.RunsTotalBytes))
	l := r.Live
	fmt.Fprintf(&b, "events 侧（同一批被归档事件，仍在 events 里）：%d 条，整行 sum(pg_column_size(t.*)) = %d 字节（%s），已不在 events %d 条\n",
		l.Events, l.RowBytes, humanBytes(l.RowBytes), l.Missing)
	fmt.Fprintf(&b, "  所在日分区（整分区口径：含当天未归档事件与全部索引）：\n")
	for _, p := range l.Partitions {
		if !p.Exists {
			fmt.Fprintf(&b, "    %s %s 不存在（当天没有日分区：行在默认分区，或日分区已退役/已删）\n",
				p.Day.Format(time.DateOnly), p.Name)
			continue
		}
		fmt.Fprintf(&b, "    %s %s %d 行，pg_total_relation_size = %d 字节（%s）\n",
			p.Day.Format(time.DateOnly), p.Name, p.Rows, p.Bytes, humanBytes(p.Bytes))
	}
	fmt.Fprintf(&b, "  日分区合计（整分区口径）= %d 字节（%s）\n", l.PartitionBytes, humanBytes(l.PartitionBytes))
	fmt.Fprintf(&b, "对比：events 日分区合计 %s / event_archive_chunks 总大小 %s = %s\n",
		humanBytes(l.PartitionBytes), humanBytes(a.ChunkTotalBytes), ratioText(div(l.PartitionBytes, a.ChunkTotalBytes)))
	b.WriteString("注意：日分区合计是整分区口径，包含同一天未归档的类别与全部索引；与冷归档表的分子不是同一批事件，只作量级参考。\n")
	return b.String()
}

func div(a, b int64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func ratioText(r float64) string {
	if r == 0 {
		return "n/a（分母为 0）"
	}
	return fmt.Sprintf("%.2fx", r)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
