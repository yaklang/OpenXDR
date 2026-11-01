package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

const (
	// DefaultChunkEvents / DefaultChunkBytes 是封块阈值：先到者生效。1 MiB 未压缩明文
	// 是压缩率与块数量的折中；块越小，后续阶段的重放粒度越细，索引越大。
	DefaultChunkEvents = 2048
	DefaultChunkBytes  = 1 << 20
)

// DefaultClasses 是默认归档的类别：4001 网络会话、4003 文件活动。
// 进程与登录事件（1007 等）量小、查询热，阶段 A 不碰。
var DefaultClasses = []int{4001, 4003}

// Options 是影子构建的输入。From / To 是 UTC 日闭区间（含两端整天）。
type Options struct {
	From, To    time.Time
	Classes     []int
	Sources     []string // 空 = 范围内的全部来源（构建开始时固定下来）
	ChunkEvents int
	ChunkBytes  int
	Confirm     bool
}

// Shadow 执行影子归档：只读地扫 events，把候选事件编码进 event_archive_chunks，
// 计数写 event_archive_runs。**不改动 events 的任何一行**，也不碰分区。
//
// 扫描不追求与线上写入强一致（不加锁、不冻结事务）：快照固定在一个只读 REPEATABLE READ
// 事务里，因此 scanned / archived / pinned_skipped 三个数彼此自洽；构建之后 events 的
// 新增或清理由 Verify 如实报成「候选集已变化」。
//
// 扫描期间用一条连接持有只读快照，写冷块走池里的其他连接，所以 db 至少要允许两个连接。
func Shadow(ctx context.Context, db *sql.DB, opt Options) (uuid.UUID, error) {
	p, err := newPlan(opt)
	if err != nil {
		return uuid.Nil, err
	}
	if len(p.sources) == 0 {
		if p.sources, err = distinctSources(ctx, db, p); err != nil {
			return uuid.Nil, err
		}
	}
	runID := uuid.New()
	if _, err := db.ExecContext(ctx, `INSERT INTO event_archive_runs
 (id, started_at, status, day_from, day_to, classes, sources) VALUES ($1, now(), $2, $3, $4, $5, $6)`,
		runID, StatusBuilding, p.from, p.to, p.classes, p.sources); err != nil {
		return uuid.Nil, fmt.Errorf("创建归档 run: %w", err)
	}
	w := &shadowWriter{db: db, runID: runID, p: p}
	st, err := scanCandidates(ctx, db, p, func(e Event) error { return w.add(ctx, e) })
	if err == nil {
		err = w.flush(ctx)
	}
	if err != nil {
		return uuid.Nil, failRun(ctx, db, runID, err)
	}
	// 同一快照里数出来的候选必须恰好分成「归档、被钉住、超大跳过」三类，
	// 对不上说明扫描口径有漏洞：宁可让这轮失败，也不留一份解释不清的归档。
	if sum := w.archived + st.Pinned + w.oversized; sum != st.Scanned {
		return uuid.Nil, failRun(ctx, db, runID, fmt.Errorf(
			"候选计数不一致：scanned=%d，archived=%d + pinned=%d + oversized=%d = %d",
			st.Scanned, w.archived, st.Pinned, w.oversized, sum))
	}
	detail := buildDetail{
		Classes:      intsOf(p.classes),
		Sources:      p.sources,
		Groups:       groupNames(p),
		ChunkEvents:  p.chunkEvents,
		ChunkBytes:   p.chunkBytes,
		Scanned:      st.Scanned,
		Archived:     w.archived,
		PinnedSkip:   st.Pinned,
		Oversized:    w.oversized,
		OversizedIDs: w.oversizedIDs,
		Chunks:       int64(w.seq),
	}
	detail.CandidateFirstTs = stamp(st.First)
	detail.CandidateLastTs = stamp(st.Last)
	detail.ArchivedFirstTs = stamp(w.firstTs)
	detail.ArchivedLastTs = stamp(w.lastTs)
	encoded, err := json.Marshal(detail)
	if err != nil {
		return uuid.Nil, failRun(ctx, db, runID, fmt.Errorf("序列化构建明细: %w", err))
	}
	if _, err := db.ExecContext(ctx, `UPDATE event_archive_runs
 SET scanned = $2, pinned_skipped = $3, detail = $4, finished_at = now() WHERE id = $1`,
		runID, st.Scanned, st.Pinned, encoded); err != nil {
		return uuid.Nil, failRun(ctx, db, runID, fmt.Errorf("写入构建统计: %w", err))
	}
	return runID, nil
}

// buildDetail 是 run 的 detail：对拍时要用 scanned 与首末 ts 判断一致性，
// 超大事件单独记 id，不静默丢。
type buildDetail struct {
	Classes          []int    `json:"classes"`
	Sources          []string `json:"sources"`
	Groups           []string `json:"groups"`
	ChunkEvents      int      `json:"chunk_events"`
	ChunkBytes       int      `json:"chunk_bytes"`
	Scanned          int64    `json:"scanned"`
	Archived         int64    `json:"archived"`
	PinnedSkip       int64    `json:"pinned_skipped"`
	Oversized        int64    `json:"oversized"`
	OversizedIDs     []string `json:"oversized_ids,omitempty"`
	Chunks           int64    `json:"chunks"`
	CandidateFirstTs string   `json:"candidate_first_ts,omitempty"`
	CandidateLastTs  string   `json:"candidate_last_ts,omitempty"`
	ArchivedFirstTs  string   `json:"archived_first_ts,omitempty"`
	ArchivedLastTs   string   `json:"archived_last_ts,omitempty"`
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func intsOf(in []int32) []int {
	out := make([]int, len(in))
	for i, v := range in {
		out[i] = int(v)
	}
	return out
}

func groupNames(p plan) []string {
	out := make([]string, 0, len(p.classes)*len(p.sources))
	for _, g := range p.groups() {
		out = append(out, fmt.Sprintf("%d/%s", g.class, g.source))
	}
	return out
}

// newPlan 校验并归一化 Options：不确认就拒绝，日期按 UTC 日取整，阈值有默认值与上限。
func newPlan(opt Options) (plan, error) {
	if !opt.Confirm {
		return plan{}, errors.New("影子归档会写入 event_archive_chunks / event_archive_runs，必须显式确认（-confirm）")
	}
	if opt.From.IsZero() || opt.To.IsZero() {
		return plan{}, errors.New("必须给出起止日期（-from / -to）")
	}
	from, to := dayStart(opt.From), dayStart(opt.To)
	if to.Before(from) {
		return plan{}, fmt.Errorf("-to（%s）早于 -from（%s）", to.Format(time.DateOnly), from.Format(time.DateOnly))
	}
	classes := opt.Classes
	if len(classes) == 0 {
		classes = DefaultClasses
	}
	seen := map[int32]bool{}
	var list []int32
	for _, c := range classes {
		if c <= 0 || c > 1<<31-1 {
			return plan{}, fmt.Errorf("class_uid %d 非法", c)
		}
		if !seen[int32(c)] {
			seen[int32(c)] = true
			list = append(list, int32(c))
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })

	sources := make([]string, 0, len(opt.Sources))
	srcSeen := map[string]bool{}
	for _, s := range opt.Sources {
		if s == "" {
			return plan{}, errors.New("-sources 里有空来源")
		}
		if !srcSeen[s] {
			srcSeen[s] = true
			sources = append(sources, s)
		}
	}
	sort.Strings(sources)

	chunkEvents := opt.ChunkEvents
	if chunkEvents == 0 {
		chunkEvents = DefaultChunkEvents
	}
	if chunkEvents < 0 || chunkEvents > MaxCount {
		return plan{}, fmt.Errorf("单块事件条数 %d 不合法（1..%d）", chunkEvents, MaxCount)
	}
	chunkBytes := opt.ChunkBytes
	if chunkBytes == 0 {
		chunkBytes = DefaultChunkBytes
	}
	if chunkBytes < 0 || chunkBytes > MaxPlainLen {
		return plan{}, fmt.Errorf("单块明文字节 %d 不合法（1..%d）", chunkBytes, MaxPlainLen)
	}
	return plan{from: from, to: to, classes: list, sources: sources, chunkEvents: chunkEvents, chunkBytes: chunkBytes}, nil
}

func dayStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func failRun(ctx context.Context, db *sql.DB, runID uuid.UUID, cause error) error {
	if _, err := db.ExecContext(ctx, `UPDATE event_archive_runs
 SET status = $2, error = $3, finished_at = now() WHERE id = $1`, runID, StatusFailed, cause.Error()); err != nil {
		return fmt.Errorf("%w（并且没能把 run %s 标记为失败: %v）", cause, runID, err)
	}
	return cause
}

// shadowWriter 边扫边封块：攒到阈值就编码写入，内存里只有当前这块。
type shadowWriter struct {
	db    *sql.DB
	runID uuid.UUID
	p     plan

	seq       int // 已写入的块数，也是下一块的序号（从 1 开始）
	plain     []byte
	count     int
	ids       []uuid.UUID // 当前块里的事件 id，封块时建 ID Bloom filter
	day       time.Time
	class     int32
	source    string
	firstTs   time.Time
	lastTs    time.Time
	archived  int64
	oversized int64

	oversizedIDs []string
}

// add 收一条候选事件。超大事件不封块、直接计入 oversized 并记 id；
// 其余按 (日, 类别, 来源) 与两个阈值封块。
func (w *shadowWriter) add(ctx context.Context, e Event) error {
	line := e.appendJSON(nil)
	if len(line) > MaxEventBytes {
		w.oversized++
		if len(w.oversizedIDs) < 20 {
			w.oversizedIDs = append(w.oversizedIDs, e.ID.String())
		}
		return nil
	}
	day := dayStart(e.Ts)
	if w.count > 0 && (!day.Equal(w.day) || e.ClassUID != int64(w.class) || e.Source != w.source ||
		w.count >= w.p.chunkEvents || len(w.plain)+1+len(line) > w.p.chunkBytes) {
		if err := w.flush(ctx); err != nil {
			return err
		}
	}
	if w.count == 0 {
		w.day, w.class, w.source, w.firstTs = day, int32(e.ClassUID), e.Source, e.Ts
	} else {
		w.plain = append(w.plain, '\n')
	}
	w.plain = append(w.plain, line...)
	w.ids = append(w.ids, e.ID)
	w.count++
	w.lastTs = e.Ts
	return nil
}

// flush 编码当前块并写库：块、该块的 locator 行与 run 的计数在同一个事务里
// （writeChunk），崩在中途不会留下对不上的账，也不会留下没有索引的块。
func (w *shadowWriter) flush(ctx context.Context) error {
	if w.count == 0 {
		return nil
	}
	block, err := seal(w.plain, w.count)
	if err != nil {
		return fmt.Errorf("编码第 %d 块: %w", w.seq+1, err)
	}
	w.seq++
	chunk := chunkRow{
		ID: uuid.New(), RunID: w.runID, Seq: w.seq, Day: w.day,
		ClassUID: int(w.class), Source: w.source, FirstTs: w.firstTs, LastTs: w.lastTs,
		EventCount: w.count, Block: block,
		// ID Bloom filter 与块一起落库：只用来排除不可能命中的块，漏报会让按 ID 定位
		// 与重传判重失效，所以按实际写进块里的 id 建（与 event_count 一致）。
		// P2 起 locator 行同样从这份 w.ids 生成（writeChunk），与块同事务。
		Bloom:    BuildIDBloom(w.ids, w.count),
		EventIDs: w.ids,
	}
	if err := writeChunk(ctx, w.db, chunk); err != nil {
		return err
	}
	w.archived += int64(w.count)
	w.plain, w.count, w.ids = nil, 0, nil
	return nil
}

// chunkRow 是 event_archive_chunks 的一行。Bloom 是阶段 B2 的 ID Bloom filter（可空列），
// EventIDs 是实际编码进这块的事件 id（P2 起与块同事务写进 event_archive_locator）。
type chunkRow struct {
	ID         uuid.UUID
	RunID      uuid.UUID
	Seq        int
	Day        time.Time
	ClassUID   int
	Source     string
	FirstTs    time.Time
	LastTs     time.Time
	EventCount int
	Bloom      []byte
	EventIDs   []uuid.UUID
	Block
}

// shadowTestHook 只用于测试：非 nil 时在「块已 INSERT、locator 尚未 INSERT」的确切位置
// （stage == "locator_before_insert"）回调，返回错误即让该事务回滚，用来确定性验证
// 「块行、run 计数、locator 行」三者同事务原子（T07）。生产恒为 nil，零行为差异。
var shadowTestHook func(stage string) error

// writeChunk 在一个事务里写块、写该块的 locator 行并累加 run 的 archived / chunks：
// 三者必须同生共死，崩在中途不会留下「有块没索引」或「计数对不上」的账。
func writeChunk(ctx context.Context, db *sql.DB, ch chunkRow) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("写第 %d 块: %w", ch.Seq, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO event_archive_chunks
 (id, run_id, seq, day, class_uid, source, first_ts, last_ts, event_count, format, codec,
  plain_len, payload_len, plain_sha256, payload, id_bloom)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		ch.ID, ch.RunID, ch.Seq, ch.Day, ch.ClassUID, ch.Source, ch.FirstTs, ch.LastTs, ch.EventCount,
		int16(ch.Format), int16(ch.Codec), ch.PlainLen, len(ch.Payload), ch.PlainSHA256[:], ch.Payload,
		ch.Bloom); err != nil {
		return fmt.Errorf("写第 %d 块: %w", ch.Seq, err)
	}
	if shadowTestHook != nil {
		if err := shadowTestHook("locator_before_insert"); err != nil {
			return fmt.Errorf("写第 %d 块（locator 插入前注入）: %w", ch.Seq, err)
		}
	}
	// locator 行来自实际编码进块的 id 集合（w.ids），不是重新扫 events：块里有什么就索引什么。
	// 一条 typed unnest 的 INSERT，参数个数固定为 2，与块内条数无关（同 insertEvents 的风格）。
	// 不加 ON CONFLICT：块内 id 天然唯一（events 主键 + 单趟扫描），撞主键说明编码口径出了问题，
	// 宁可整块失败也不静默吞掉。
	if _, err := tx.ExecContext(ctx, `INSERT INTO event_archive_locator (event_id, chunk_id)
 SELECT u.event_id, $2::uuid FROM unnest($1::uuid[]) AS u(event_id)`, ch.EventIDs, ch.ID); err != nil {
		return fmt.Errorf("写第 %d 块的 locator 行: %w", ch.Seq, err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE event_archive_runs
 SET archived = archived + $2, chunks = chunks + 1 WHERE id = $1`, ch.RunID, ch.EventCount); err != nil {
		return fmt.Errorf("累加第 %d 块的计数: %w", ch.Seq, err)
	}
	return tx.Commit()
}
