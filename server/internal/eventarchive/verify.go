package eventarchive

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrCandidatesChanged 表示 events 里的候选集在影子构建之后变了（新写入、被清理、或被钉住），
// 不是编码或块损坏。对拍报这个错时只能重新跑一轮影子构建。
var ErrCandidatesChanged = errors.New("候选集已变化，请重新运行")

// Run 是一行 event_archive_runs 的只读快照。
type Run struct {
	ID         uuid.UUID
	Status     string
	StartedAt  time.Time
	FinishedAt sql.NullTime
	DayFrom    time.Time
	DayTo      time.Time
	Classes    []int
	Sources    []string
	Scanned    int64
	Archived   int64
	PinnedSkip int64
	Chunks     int64
	Error      sql.NullString
	Detail     json.RawMessage
}

// LoadRun 读一轮归档的状态。只读。
func LoadRun(ctx context.Context, db *sql.DB, id uuid.UUID) (Run, error) {
	var r Run
	var classes, sources sql.NullString
	var detail []byte
	err := db.QueryRowContext(ctx, `SELECT id, status, started_at, finished_at, day_from, day_to,
 to_json(classes)::text, to_json(sources)::text, scanned, archived, pinned_skipped, chunks, error, detail
 FROM event_archive_runs WHERE id = $1`, id).
		Scan(&r.ID, &r.Status, &r.StartedAt, &r.FinishedAt, &r.DayFrom, &r.DayTo,
			&classes, &sources, &r.Scanned, &r.Archived, &r.PinnedSkip, &r.Chunks, &r.Error, &detail)
	if errors.Is(err, sql.ErrNoRows) {
		return r, fmt.Errorf("归档 run %s 不存在", id)
	}
	if err != nil {
		return r, fmt.Errorf("读取归档 run %s: %w", id, err)
	}
	r.DayFrom, r.DayTo = r.DayFrom.UTC(), r.DayTo.UTC()
	if classes.String != "" {
		if err := json.Unmarshal([]byte(classes.String), &r.Classes); err != nil {
			return r, fmt.Errorf("解析 run %s 的 classes: %w", id, err)
		}
	}
	if sources.String != "" {
		if err := json.Unmarshal([]byte(sources.String), &r.Sources); err != nil {
			return r, fmt.Errorf("解析 run %s 的 sources: %w", id, err)
		}
	}
	r.Detail = json.RawMessage(detail)
	return r, nil
}

// plan 按 run 行里记下的口径重建扫描计划：对拍完全按构建时的类别、来源与日期重查。
func (r Run) plan() (plan, error) {
	p := plan{from: dayStart(r.DayFrom), to: dayStart(r.DayTo), sources: r.Sources,
		chunkEvents: DefaultChunkEvents, chunkBytes: DefaultChunkBytes}
	if len(r.Classes) == 0 {
		return p, fmt.Errorf("run %s 没有类别口径", r.ID)
	}
	for _, c := range r.Classes {
		p.classes = append(p.classes, int32(c))
	}
	return p, nil
}

// Chunk 是 event_archive_chunks 的一行。
type Chunk struct {
	ID         uuid.UUID
	RunID      uuid.UUID
	Seq        int
	Day        time.Time
	ClassUID   int
	Source     string
	FirstTs    time.Time
	LastTs     time.Time
	EventCount int
	PayloadLen int64
	Block
}

// Verify 重新按 run 的口径只读重扫 events，与所有冷块解出来的事件逐条全字段比对：
// 条数、id 序列、每个字段（raw 逐字节）任一不符都返回错误并给出首个差异。
//
// P2 起对拍还核 locator：每块解出的成员集合必须与 event_archive_locator 里该块的
// 成员集合**精确相等**（缺行、多行、错指块都报错，不以条数相同代替集合相同；
// 见 checkLocatorMembers）。同一 id 跨 run 多副本合法（不同块各有一行），同 run 内
// 集合必须精确——因为块解码顺序按 seq 全量遍历，任何一块的索引偏差都会在这里露出来。
//
// 两侧顺序一致（类别、来源、ts、id 升序），所以可以边扫边比，内存里只有一批事件加一块冷块。
// 单条编码后超过 4 MiB 的事件与影子构建同规则跳过（它们本来就不在冷块里），不是遗漏。
// 通过后 run 置 verified；候选集变了则报 ErrCandidatesChanged，不会误报成编码错误。
//
// 老块（P2 之前写的、没有 locator 行）对拍会在这里报错：它们必须先跑 backfill-locator。
func Verify(ctx context.Context, db *sql.DB, runID uuid.UUID) error {
	run, err := LoadRun(ctx, db, runID)
	if err != nil {
		return err
	}
	if run.Status == StatusFailed {
		return fmt.Errorf("run %s 状态是 failed（%s），不能对拍", runID, run.Error.String)
	}
	p, err := run.plan()
	if err != nil {
		return err
	}
	// 先核 run 自己的账：块数、条数必须与 run 行一致，免得对拍一半才发现 run 行被改过
	var chunks, events int64
	if err := db.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(event_count), 0)
 FROM event_archive_chunks WHERE run_id = $1`, runID).Scan(&chunks, &events); err != nil {
		return fmt.Errorf("统计 run %s 的冷块: %w", runID, err)
	}
	if chunks != run.Chunks || events != run.Archived {
		return fmt.Errorf("run %s 的计数与冷块不符：run 记 %d 块 / %d 条，实际 %d 块 / %d 条",
			runID, run.Chunks, run.Archived, chunks, events)
	}

	it := &chunkIter{db: db, runID: runID}
	var compared, oversized int64
	var scratch []byte
	st, err := scanCandidates(ctx, db, p, func(fresh Event) error {
		// 与影子构建同一条规则：编码后超过 4 MiB 的事件不进冷块，对拍时同样跳过，
		// 否则这类事件永远对不上。条数仍然核对（见下面的不变量）。
		line := fresh.appendJSON(scratch[:0])
		scratch = line
		if len(line) > MaxEventBytes {
			oversized++
			return nil
		}
		old, ok, err := it.next(ctx)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w：events 里的候选事件 %s（ts=%s）不在任何冷块中，是影子构建之后写入的",
				ErrCandidatesChanged, fresh.ID, stamp(fresh.Ts))
		}
		compared++
		return diffEvent(compared, old, fresh)
	})
	if err != nil {
		return err
	}
	if old, ok, err := it.next(ctx); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("%w：冷块里的事件 %s（ts=%s）已不在 events 中，应该是构建之后被清理了",
			ErrCandidatesChanged, old.ID, stamp(old.Ts))
	}
	if want := st.Scanned - st.Pinned - oversized; compared != want {
		return fmt.Errorf("%w：events 里现有 %d 条候选事件（其中 %d 条超过单条上限被跳过），逐条比对只有 %d 条",
			ErrCandidatesChanged, want, oversized, compared)
	}
	if _, err := db.ExecContext(ctx, `UPDATE event_archive_runs SET status = $2, error = NULL,
 detail = jsonb_set(COALESCE(detail, '{}'::jsonb), '{verified_at}', to_jsonb(now()::text), true)
 WHERE id = $1`, runID, StatusVerified); err != nil {
		return fmt.Errorf("把 run %s 置为 verified: %w", runID, err)
	}
	return nil
}

// chunkIter 按 seq 顺序逐块解码，内存里只留一块。P2 起 next 解出的每块同时做
// locator 成员集合校验（checkLocatorMembers）：块解码成员集合 == locator 成员集合，
// 缺行、多行或错指块都是数据不一致，不以条数相同代替集合相同。
type chunkIter struct {
	db    *sql.DB
	runID uuid.UUID
	after int
	done  bool
	seq   int
	items []Event
	pos   int
}

func (it *chunkIter) next(ctx context.Context) (Event, bool, error) {
	for it.pos >= len(it.items) {
		if it.done {
			return Event{}, false, nil
		}
		ch, ok, err := loadChunk(ctx, it.db, it.runID, it.after)
		if err != nil {
			return Event{}, false, err
		}
		if !ok {
			it.done = true
			return Event{}, false, nil
		}
		it.after, it.seq = ch.Seq, ch.Seq
		items, err := ch.Block.Decode()
		if err != nil {
			return Event{}, false, fmt.Errorf("解码第 %d 块 %s: %w", ch.Seq, ch.ID, err)
		}
		if err := ch.check(items); err != nil {
			return Event{}, false, fmt.Errorf("第 %d 块 %s: %w", ch.Seq, ch.ID, err)
		}
		if err := checkLocatorMembers(ctx, it.db, ch, items); err != nil {
			return Event{}, false, fmt.Errorf("第 %d 块 %s: %w", ch.Seq, ch.ID, err)
		}
		it.items, it.pos = items, 0
	}
	e := it.items[it.pos]
	it.pos++
	return e, true, nil
}

func loadChunk(ctx context.Context, db *sql.DB, runID uuid.UUID, after int) (Chunk, bool, error) {
	var ch Chunk
	var format, codec int16
	var sha []byte
	var payload []byte
	err := db.QueryRowContext(ctx, `SELECT id, run_id, seq, day, class_uid, source, first_ts, last_ts,
 event_count, format, codec, plain_len, payload_len, plain_sha256, payload
 FROM event_archive_chunks WHERE run_id = $1 AND seq > $2 ORDER BY seq LIMIT 1`, runID, after).
		Scan(&ch.ID, &ch.RunID, &ch.Seq, &ch.Day, &ch.ClassUID, &ch.Source, &ch.FirstTs, &ch.LastTs,
			&ch.EventCount, &format, &codec, &ch.PlainLen, &ch.PayloadLen, &sha, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return ch, false, nil
	}
	if err != nil {
		return ch, false, fmt.Errorf("读取 run %s seq>%d 的冷块: %w", runID, after, err)
	}
	ch.Day, ch.FirstTs, ch.LastTs = ch.Day.UTC(), ch.FirstTs.UTC(), ch.LastTs.UTC()
	ch.Block = Block{Format: uint8(format), Codec: uint8(codec), Count: ch.EventCount,
		PlainLen: ch.PlainLen, Payload: payload}
	if len(sha) != len(ch.PlainSHA256) {
		return ch, false, fmt.Errorf("plain_sha256 长度 %d 不是 32 字节", len(sha))
	}
	copy(ch.PlainSHA256[:], sha)
	if int64(len(payload)) != ch.PayloadLen {
		return ch, false, fmt.Errorf("payload_len 记 %d 字节，实际 %d 字节", ch.PayloadLen, len(payload))
	}
	return ch, true, nil
}

// checkLocatorMembers 核对一块的 locator 成员集合与块解码成员集合是否**精确相等**：
// 读出该块的全部 locator 行（chunk_id 索引上的顺序读），与解码成员做成两个 set 后
// 双向求差。缺行（在块里、不在索引里）、多行（在索引里、不在块里——含错指块的行）
// 都如实报差异数量与样本 id；条数相同但成员错位同样会在这里露出来，不以条数代替集合。
//
// 同一 id 跨 run 多副本不受影响：那是「同一 event_id 在别的块也有行」，这里只看本块的行。
func checkLocatorMembers(ctx context.Context, db *sql.DB, ch Chunk, events []Event) error {
	rows, err := db.QueryContext(ctx,
		`SELECT event_id FROM event_archive_locator WHERE chunk_id = $1`, ch.ID)
	if err != nil {
		return wrapErr(err, "读块 %s 的 locator 成员", ch.ID)
	}
	defer rows.Close()
	indexed := make(map[uuid.UUID]struct{}, ch.EventCount)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return wrapErr(err, "读块 %s 的 locator 成员行", ch.ID)
		}
		indexed[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return wrapErr(err, "读块 %s 的 locator 成员", ch.ID)
	}
	decoded := make(map[uuid.UUID]struct{}, len(events))
	for _, e := range events {
		decoded[e.ID] = struct{}{}
	}
	var missing, extra []string
	for _, e := range events {
		if _, ok := indexed[e.ID]; !ok {
			missing = append(missing, e.ID.String())
		}
	}
	for id := range indexed {
		if _, ok := decoded[id]; !ok {
			extra = append(extra, id.String())
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	const sample = 5
	if len(missing) > 0 || len(extra) > 0 {
		return fmt.Errorf("locator 成员集合与块解码成员不一致：块里有而索引缺 %d 行（%s），"+
			"索引里有而块里没有 %d 行（%s）", len(missing), firstN(missing, sample),
			len(extra), firstN(extra, sample))
	}
	return nil
}

func firstN(list []string, n int) string {
	if len(list) == 0 {
		return ""
	}
	if len(list) > n {
		return strings.Join(list[:n], ",")
	}
	return strings.Join(list, ",")
}

// check 核对块的列与解出来的内容自洽：块内只有一个 (日, 类别, 来源)，首末 ts 与事件顺序一致。
func (ch Chunk) check(events []Event) error {
	if len(events) != ch.EventCount {
		return fmt.Errorf("event_count 记 %d 条，块里解出 %d 条", ch.EventCount, len(events))
	}
	if len(events) == 0 {
		return errors.New("空块")
	}
	for i, e := range events {
		if !dayStart(e.Ts).Equal(ch.Day) {
			return fmt.Errorf("第 %d 条事件 ts=%s 不在 day=%s 内", i+1, stamp(e.Ts), ch.Day.Format(time.DateOnly))
		}
		if e.ClassUID != int64(ch.ClassUID) || e.Source != ch.Source {
			return fmt.Errorf("第 %d 条事件是 class=%d source=%s，与块上的 %d/%s 不符",
				i+1, e.ClassUID, e.Source, ch.ClassUID, ch.Source)
		}
		if i > 0 && events[i].Ts.Before(events[i-1].Ts) {
			return fmt.Errorf("第 %d 条事件 ts 早于上一条，块内顺序不对", i+1)
		}
	}
	if !events[0].Ts.Equal(ch.FirstTs) {
		return fmt.Errorf("first_ts 记 %s，块里第一条是 %s", stamp(ch.FirstTs), stamp(events[0].Ts))
	}
	if !events[len(events)-1].Ts.Equal(ch.LastTs) {
		return fmt.Errorf("last_ts 记 %s，块里最后一条是 %s", stamp(ch.LastTs), stamp(events[len(events)-1].Ts))
	}
	return nil
}

// diffEvent 逐字段比对一条事件；raw 逐字节比。首个差异就返回，带上是第几条与哪一侧的值。
func diffEvent(n int64, old, fresh Event) error {
	if old.ID != fresh.ID {
		return fmt.Errorf("%w：第 %d 个候选事件在冷块里是 %s，在 events 里是 %s（ts=%s）",
			ErrCandidatesChanged, n, old.ID, fresh.ID, stamp(fresh.Ts))
	}
	mismatch := func(field string, a, b any) error {
		return fmt.Errorf("事件 %s 的 %s 不一致：冷块 %v，events %v（冷块可能已损坏）", fresh.ID, field, a, b)
	}
	if !old.Ts.Equal(fresh.Ts) {
		return mismatch("ts", stamp(old.Ts), stamp(fresh.Ts))
	}
	if old.ClassUID != fresh.ClassUID {
		return mismatch("class_uid", old.ClassUID, fresh.ClassUID)
	}
	if old.Source != fresh.Source {
		return mismatch("source", old.Source, fresh.Source)
	}
	if !uuidPtrEqual(old.AssetID, fresh.AssetID) {
		return mismatch("asset_id", uuidPtrText(old.AssetID), uuidPtrText(fresh.AssetID))
	}
	if !uuidPtrEqual(old.ProcessGUID, fresh.ProcessGUID) {
		return mismatch("process_guid", uuidPtrText(old.ProcessGUID), uuidPtrText(fresh.ProcessGUID))
	}
	if !uuidPtrEqual(old.ParentProcessGUID, fresh.ParentProcessGUID) {
		return mismatch("parent_process_guid", uuidPtrText(old.ParentProcessGUID), uuidPtrText(fresh.ParentProcessGUID))
	}
	if !strPtrEqual(old.Username, fresh.Username) {
		return mismatch("username", strPtrText(old.Username), strPtrText(fresh.Username))
	}
	if !strPtrEqual(old.ConnTuple, fresh.ConnTuple) {
		return mismatch("conn_tuple", strPtrText(old.ConnTuple), strPtrText(fresh.ConnTuple))
	}
	if !bytes.Equal(old.Raw, fresh.Raw) {
		return mismatch("raw", snippet(old.Raw), snippet(fresh.Raw))
	}
	return nil
}

func uuidPtrEqual(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func strPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func uuidPtrText(id *uuid.UUID) string {
	if id == nil {
		return "NULL"
	}
	return id.String()
}

func strPtrText(s *string) string {
	if s == nil {
		return "NULL"
	}
	return *s
}

func snippet(b []byte) string {
	const max = 120
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + fmt.Sprintf("…(共 %d 字节)", len(b))
}
