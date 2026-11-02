package eventarchive

import (
	"bytes"
	"container/heap"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	// defaultLimit 是 Filter.Limit 未指定时的返回上限。
	defaultLimit = 1000
	// maxScannedChunks 是单次查询最多解压的块数：每块都要整块解压（zstd frame 不支持
	// 随机访问），不设上限时一个宽时间窗会把整个归档读进内存。预算用完就停，
	// 并如实标记 Coverage.Truncated，不假装结果完整。
	maxScannedChunks = 200
)

// Filter 是冷数据查询条件。零值表示不限。
//
// AssetIDs 的 nil 与空切片含义不同，调用方必须分清：
//   - nil：不限资产（全局 admin）；
//   - 非 nil：只返回这些资产的事件，事件 AssetID 为 nil 或不在集合里的一律丢弃；
//     空切片表示「一无所见」，直接返回空结果。这与热表 AssetIDIn() 的空集合口径一致：
//     没有可见资产的用户不能因为传了个空集合就变成不限。
type Filter struct {
	From, To time.Time   // 按 ts，左闭右开
	AssetIDs []uuid.UUID // 组权限过滤：nil 不限，非 nil 受限（见类型注释）
	Classes  []int
	Sources  []string
	IDs      []uuid.UUID // 按事件 ID 精确定位（优先级最高，可与其它条件叠加）
	Limit    int         // 返回上限，<=0 用 1000
}

// Coverage 说明本次结果覆盖了哪些范围，调用方据此判断「没查到」是否等于「不存在」。
type Coverage struct {
	ScannedChunks int
	// Matched 是扫描中命中的**去重后**事件数（截断前）：冷块按 run 叠加时会重复归档同一事件。
	Matched int
	// Truncated 为真表示结果被截断：命中数超过 Limit，或有候选块因预算（maxScannedChunks）没扫。
	Truncated bool
	// ScanIncomplete 为真表示**扫描**本身没有完成：还有候选块因预算（maxScannedChunks）没解压，
	// 与「命中太多被 Limit 挤掉」的 Truncated 是两回事。查询覆盖度要把这两种缺口分开表达——
	// 前者是「该范围没扫完」，后者只是「结果条数到了上限」。
	ScanIncomplete bool
	// ChunkErrors 保留给「部分块被跳过」的诊断场景。当前实现里块解码失败一律整体报错，
	// 不会降级成部分结果，所以正常路径上它始终为空。
	ChunkErrors []string
}

// Extent 是冷归档现有的时间范围。
//
// Schema 为 false 表示 event_archive_chunks 这张表还不存在（没跑过 EnsureSchema）：
// 这是部署状态，不是数据损坏，调用方要按「没有冷数据」处理而不是报错整页。
// Has 为 false 表示表在、但一条冷块都没有。
type Extent struct {
	Schema      bool
	Has         bool
	First, Last time.Time
}

// ErrNoSchema 表示冷归档表还不存在。开着冷读开关、但还没跑过 ensure-schema 的部署会碰到。
var ErrNoSchema = errors.New("冷归档表不存在（先跑 eventarchive ensure-schema）")

// ArchiveExtent 取冷归档的时间范围与有无。两条语句都是索引上的极值查询，不扫表。
func ArchiveExtent(ctx context.Context, db *sql.DB) (Extent, error) {
	if db == nil {
		return Extent{}, nil
	}
	var exists bool
	if err := db.QueryRowContext(ctx,
		`SELECT to_regclass('event_archive_chunks') IS NOT NULL`).Scan(&exists); err != nil {
		return Extent{}, wrapErr(err, "检查冷归档表")
	}
	if !exists {
		return Extent{}, nil
	}
	var first, last sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT
 (SELECT first_ts FROM event_archive_chunks ORDER BY first_ts LIMIT 1),
 (SELECT last_ts FROM event_archive_chunks ORDER BY last_ts DESC LIMIT 1)`).Scan(&first, &last); err != nil {
		return Extent{}, wrapErr(err, "读取冷归档时间范围")
	}
	if !first.Valid || !last.Valid {
		return Extent{Schema: true}, nil
	}
	return Extent{Schema: true, Has: true, First: first.Time.UTC(), Last: last.Time.UTC()}, nil
}

// isUndefinedTable 判断错误是不是「表不存在」（PostgreSQL SQLSTATE 42P01）。
// 这属于部署状态而不是数据损坏：不能让事件页因为还没建表就整页 500。
func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

// wrapErr 把「表不存在」统一包成 ErrNoSchema，其余错误原样带上上下文。
func wrapErr(err error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if isUndefinedTable(err) {
		return fmt.Errorf("%w：%s（%v）", ErrNoSchema, msg, err)
	}
	return fmt.Errorf("%s: %w", msg, err)
}

// Query 读冷块，返回匹配的事件（按 ts 倒序）。任何块解码失败都必须返回错误，
// 不得用「跳过坏块」换来一份看起来完整的结果。
//
// 冷块按 (日, 类别, 来源) 切分、块内 ts 递增，所以先按块元数据收窄候选、只解压可能命中的块，
// 解压后再逐事件精确匹配。结果是 (ts, id) 倒序、按 (ts, id) 去重，最多 Limit 条；
//
// 表还不存在时返回 ErrNoSchema：那是部署状态（没跑过 EnsureSchema），调用方应按「没有冷数据」
// 处理；表在但没有块则返回空结果、不报错。
// 内存只有一批候选块的元数据加当前这一块，不随归档规模增长。
func Query(ctx context.Context, db *sql.DB, f Filter) ([]Event, Coverage, error) {
	if db == nil {
		return nil, Coverage{}, errors.New("冷归档查询需要数据库连接")
	}
	// 表还不存在 / 一条冷块都没有：冷层没有可查的东西
	ext, err := ArchiveExtent(ctx, db)
	if err != nil {
		return nil, Coverage{}, err
	}
	if !ext.Schema {
		return nil, Coverage{}, ErrNoSchema
	}
	if !ext.Has {
		return nil, Coverage{}, nil
	}
	return query(ctx, &sqlSource{db: db}, f)
}

// chunkMeta 是候选块的元数据（不含载荷）：收窄、预算与顺序只靠它，解压前不碰 payload。
type chunkMeta struct {
	ID       uuid.UUID
	Seq      int
	Day      time.Time
	ClassUID int
	Source   string
	FirstTs  time.Time
	LastTs   time.Time
	Count    int
}

// chunkSource 提供候选块与块载荷。Query 用数据库实现；单元测试用内存实现，
// 于是收窄、去重、排序、截断、预算这些行为不连库也能验证。
type chunkSource interface {
	// candidates 返回按 (first_ts, last_ts) 倒序的候选块，最多 want 个；
	// more 为真表示还有没返回的候选块（预算用尽，结果必然不完整）。
	candidates(ctx context.Context, f Filter, want int) ([]chunkMeta, bool, error)
	// load 取一块的完整内容，头部字段（含 sha256）与载荷都要在。
	load(ctx context.Context, id uuid.UUID) (Chunk, error)
}

// query 是 Query 的实现主体：不碰数据库，只依赖 chunkSource。
func query(ctx context.Context, src chunkSource, f Filter) ([]Event, Coverage, error) {
	var cov Coverage
	// 受限但一无所见：既不必碰库，也不能返回任何事件
	if f.AssetIDs != nil && len(f.AssetIDs) == 0 {
		return nil, cov, nil
	}
	limit := f.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	matches := newEventMatcher(f)
	keep := &collector{limit: limit, seen: map[eventKey]struct{}{}}

	cands, more, err := src.candidates(ctx, f, maxScannedChunks)
	if err != nil {
		return nil, cov, err
	}
	if more {
		cov.Truncated = true
		cov.ScanIncomplete = true
	}
	for _, cand := range cands {
		if cov.ScannedChunks >= maxScannedChunks {
			cov.Truncated = true
			cov.ScanIncomplete = true
			break
		}
		// 数据库已经按块元数据筛过一遍，这里再判一次：任何来源都绕不过时间窗与类别、来源条件
		if !f.allowsChunk(cand) {
			continue
		}
		ch, err := src.load(ctx, cand.ID)
		if err != nil {
			return nil, cov, err
		}
		events, err := ch.Block.Decode()
		if err != nil {
			return nil, cov, fmt.Errorf("解码冷块 %s（seq %d，%s/%s）: %w",
				ch.ID, ch.Seq, ch.Day.Format(time.DateOnly), ch.Source, err)
		}
		// 块的列与内容必须自洽，否则按 first_ts/last_ts 收窄就可能漏事件——那会把「查不到」
		// 说成「不存在」，比直接报错更糟。
		if err := ch.check(events); err != nil {
			return nil, cov, fmt.Errorf("冷块 %s（seq %d）内容与头部不符: %w", ch.ID, ch.Seq, err)
		}
		cov.ScannedChunks++
		for _, e := range events {
			if matches.match(e) {
				keep.add(e)
			}
		}
	}
	events, dropped := keep.result()
	cov.Matched = keep.matched
	cov.Truncated = cov.Truncated || dropped
	return events, cov, nil
}

// eventMatcher 把 Filter 预处理成集合，逐事件匹配时不做线性扫描。
type eventMatcher struct {
	f       Filter
	classes map[int64]struct{}
	sources map[string]struct{}
	ids     map[uuid.UUID]struct{}
	assets  map[uuid.UUID]struct{}
	// restricted 为真表示 AssetIDs 非 nil：无归属事件一律丢弃（与热表 AssetIDIn 口径一致）
	restricted bool
}

func newEventMatcher(f Filter) eventMatcher {
	m := eventMatcher{f: f, restricted: f.AssetIDs != nil}
	if len(f.Classes) > 0 {
		m.classes = make(map[int64]struct{}, len(f.Classes))
		for _, c := range f.Classes {
			m.classes[int64(c)] = struct{}{}
		}
	}
	if len(f.Sources) > 0 {
		m.sources = make(map[string]struct{}, len(f.Sources))
		for _, s := range f.Sources {
			m.sources[s] = struct{}{}
		}
	}
	if len(f.IDs) > 0 {
		m.ids = make(map[uuid.UUID]struct{}, len(f.IDs))
		for _, id := range f.IDs {
			m.ids[id] = struct{}{}
		}
	}
	if m.restricted {
		m.assets = make(map[uuid.UUID]struct{}, len(f.AssetIDs))
		for _, id := range f.AssetIDs {
			m.assets[id] = struct{}{}
		}
	}
	return m
}

// match 逐事件精确匹配。资产条件最要紧：受限时 AssetID 为 nil 的事件也必须丢弃，
// 否则非 admin 能从冷块里看到无归属的事件。
func (m eventMatcher) match(e Event) bool {
	if !m.f.From.IsZero() && e.Ts.Before(m.f.From) {
		return false
	}
	if !m.f.To.IsZero() && !e.Ts.Before(m.f.To) {
		return false
	}
	if m.classes != nil {
		if _, ok := m.classes[e.ClassUID]; !ok {
			return false
		}
	}
	if m.sources != nil {
		if _, ok := m.sources[e.Source]; !ok {
			return false
		}
	}
	if m.ids != nil {
		if _, ok := m.ids[e.ID]; !ok {
			return false
		}
	}
	if m.restricted {
		if e.AssetID == nil {
			return false
		}
		if _, ok := m.assets[*e.AssetID]; !ok {
			return false
		}
	}
	return true
}

// allowsChunk 是候选块在 Go 侧的同一份收窄：块按 (日, 类别, 来源) 切分、块内 ts 递增，
// 所以块与 [From, To) 有交集等价于 last_ts >= From 且 first_ts < To。
//
// 不单独比 day：day 就是块内事件的 UTC 日，被这两个条件完全覆盖（块内 ts 全在 day 当天，
// 也因此不会跨日）。多传一个 date 参数只会在 date/timestamptz 之间加一层隐式转换。
func (f Filter) allowsChunk(c chunkMeta) bool {
	if !f.From.IsZero() && c.LastTs.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && !c.FirstTs.Before(f.To) {
		return false
	}
	if len(f.Classes) > 0 && !slices.Contains(f.Classes, c.ClassUID) {
		return false
	}
	if len(f.Sources) > 0 && !slices.Contains(f.Sources, c.Source) {
		return false
	}
	return true
}

// eventKey 是去重口径：同一个 id 同一个 ts 只留一条。
type eventKey struct {
	ts int64
	id uuid.UUID
}

func keyOf(e Event) eventKey { return eventKey{ts: e.Ts.UnixNano(), id: e.ID} }

// later 报告 a 在 (ts, id) 倒序结果里排在 b 之后。
func later(a, b Event) bool {
	if !a.Ts.Equal(b.Ts) {
		return a.Ts.Before(b.Ts)
	}
	return bytes.Compare(a.ID[:], b.ID[:]) < 0
}

// collector 保留 (ts, id) 倒序的前 limit 条：命中再多，占内存的也只有 limit 条事件，
// 被挤掉的数量记在 dropped 里，用作「结果已被截断」的依据。
type collector struct {
	limit   int
	best    eventHeap
	seen    map[eventKey]struct{}
	matched int
	dropped int
}

func (c *collector) add(e Event) {
	k := keyOf(e)
	if _, ok := c.seen[k]; ok {
		return
	}
	c.seen[k] = struct{}{}
	c.matched++
	if len(c.best) < c.limit {
		heap.Push(&c.best, e)
		return
	}
	// 堆顶是已保留里最差的一条：新来的比它还差就直接丢，否则换掉它
	if later(e, c.best[0]) {
		c.dropped++
		return
	}
	heap.Pop(&c.best)
	heap.Push(&c.best, e)
	c.dropped++
}

// result 返回 (ts, id) 倒序的结果，以及是否有命中因上限被丢弃。
func (c *collector) result() ([]Event, bool) {
	out := make([]Event, len(c.best))
	copy(out, c.best)
	sort.Slice(out, func(i, j int) bool { return later(out[j], out[i]) })
	return out, c.dropped > 0
}

// eventHeap 是「最差的在前」的小顶堆，堆顶即达到上限后最先被淘汰的那条。
type eventHeap []Event

func (h eventHeap) Len() int           { return len(h) }
func (h eventHeap) Less(i, j int) bool { return later(h[i], h[j]) }
func (h eventHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)        { *h = append(*h, x.(Event)) }

func (h *eventHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	*h = old[:n-1]
	return e
}

// sqlSource 从 event_archive_chunks 读候选块与载荷。
type sqlSource struct {
	db *sql.DB
}

// candidates 先只取元数据（不取 payload），用块上的时间范围、类别与来源收窄，
// 按 (first_ts, last_ts) 倒序 —— 结果本身是 ts 倒序，新块优先扫。
// 多取一条用来判断「还有没扫完的块」，不会把整张表拉进内存。
func (s *sqlSource) candidates(ctx context.Context, f Filter, want int) ([]chunkMeta, bool, error) {
	where, args := f.chunkWhere()
	query := `SELECT id, seq, day, class_uid, source, first_ts, last_ts, event_count
 FROM event_archive_chunks`
	if where != "" {
		query += " WHERE " + where
	}
	query += fmt.Sprintf(` ORDER BY first_ts DESC, last_ts DESC, id LIMIT %d`, want+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, wrapErr(err, "按元数据收窄冷块")
	}
	defer rows.Close()
	out := make([]chunkMeta, 0, want)
	more := false
	for rows.Next() {
		var c chunkMeta
		if err := rows.Scan(&c.ID, &c.Seq, &c.Day, &c.ClassUID, &c.Source, &c.FirstTs, &c.LastTs, &c.Count); err != nil {
			return nil, false, wrapErr(err, "读取冷块元数据")
		}
		c.Day, c.FirstTs, c.LastTs = c.Day.UTC(), c.FirstTs.UTC(), c.LastTs.UTC()
		if len(out) == want {
			more = true
			break
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, false, wrapErr(err, "按元数据收窄冷块")
	}
	return out, more, nil
}

// chunkWhere 拼候选块的 SQL 收窄条件。参数按出现顺序编号，值都走占位符。
func (f Filter) chunkWhere() (string, []any) {
	var (
		conds []string
		args  []any
	)
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if !f.From.IsZero() {
		add("last_ts >= $%d", f.From)
	}
	if !f.To.IsZero() {
		add("first_ts < $%d", f.To)
	}
	if len(f.Classes) > 0 {
		classes := make([]int32, len(f.Classes))
		for i, c := range f.Classes {
			classes[i] = int32(c)
		}
		add("class_uid = ANY($%d)", classes)
	}
	if len(f.Sources) > 0 {
		add("source = ANY($%d)", f.Sources)
	}
	return strings.Join(conds, " AND "), args
}

// load 按块 id 取完整内容：一读一块，内存里只有当前这一块（明文上限 16 MiB，见 MaxPlainLen）。
func (s *sqlSource) load(ctx context.Context, id uuid.UUID) (Chunk, error) {
	return loadChunkByID(ctx, s.db, id)
}

// loadChunkByID 是按 id 读块的主体：查询句柄同时覆盖 *sql.DB 与 *sql.Tx——事务内定位
// （lookup.go 的 LocateTx，R1 引用补链）与库级定位读同一份块载荷与同一套校验，不分叉。
// （verify.go 另有一个按 run/seq 迭代的 loadChunk，语义不同，不要合并。）
func loadChunkByID(ctx context.Context, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}, id uuid.UUID) (Chunk, error) {
	var ch Chunk
	var format, codec int16
	var sha, payload []byte
	err := q.QueryRowContext(ctx, `SELECT id, run_id, seq, day, class_uid, source, first_ts, last_ts,
 event_count, format, codec, plain_len, payload_len, plain_sha256, payload
 FROM event_archive_chunks WHERE id = $1`, id).
		Scan(&ch.ID, &ch.RunID, &ch.Seq, &ch.Day, &ch.ClassUID, &ch.Source, &ch.FirstTs, &ch.LastTs,
			&ch.EventCount, &format, &codec, &ch.PlainLen, &ch.PayloadLen, &sha, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return ch, fmt.Errorf("冷块 %s 在查询期间被删除", id)
	}
	if err != nil {
		return ch, wrapErr(err, "读取冷块 %s", id)
	}
	ch.Day, ch.FirstTs, ch.LastTs = ch.Day.UTC(), ch.FirstTs.UTC(), ch.LastTs.UTC()
	ch.Block = Block{Format: uint8(format), Codec: uint8(codec), Count: ch.EventCount,
		PlainLen: ch.PlainLen, Payload: payload}
	if len(sha) != len(ch.PlainSHA256) {
		return ch, fmt.Errorf("冷块 %s 的 plain_sha256 长度 %d 不是 32 字节", id, len(sha))
	}
	copy(ch.PlainSHA256[:], sha)
	if int64(len(payload)) != ch.PayloadLen {
		return ch, fmt.Errorf("冷块 %s 的 payload_len 记 %d 字节，实际 %d 字节", id, ch.PayloadLen, len(payload))
	}
	return ch, nil
}
