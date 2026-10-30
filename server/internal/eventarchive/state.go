package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// P6：run 的三类校验/操作状态分层汇总（只读）。
//
// 冷归档对一个 run 有三种时间点不同、含义不同的「状态」，它们会被同一份数据的意外损坏
// 分别影响，不能塞进一个值里（COLD_ARCHIVE_EVOLUTION.SCRATCH.md §P6「三类校验分开」）：
//
//  1. 构建期对拍（verify）：run.status == verified，粘性资格——对拍通过过一次就保持，
//     之后冷块被改坏不会让 status 自动回退。它证明「对拍那一刻冷块与热表逐字段一致」，
//     不证明此后仍然一致；
//  2. 冷副本自校验（现在时刻）：逐块 Decode + 头部/摘要核对 + locator 成员集合核对。
//     它证明「此刻块还自洽、索引还能对上块」，不证明与热表一致（swap 之后热行已删，
//     对拍口径本来就不成立，见 verify.go 的 ErrCandidatesChanged）；
//  3. 操作记录（detail.days）：swap 的逐日实测结果（kept/dropped），与分区替换同一事务
//     写入。它证明「那一天真的切过、事务内实测是多少」，不证明冷块当前健康。
//
// RunState 把三者各自读出来放进同一个结构，调用方（CLI status、运维核对）据此区分
// 「曾经验证过」「现在自校验不过」「已经操作过」——任一组合都可能出现，例如：
// verified + 自校验失败 + 已操作 = 对拍后块被改坏、且那一天已经按它切换过。

// RunStateReport 是 RunState 的返回值。全部字段只读自库，不写任何东西。
type RunStateReport struct {
	Run Run
	// BuildVerified 表示构建期对拍通过过（run.status == verified）。粘性：不随后续损坏回退。
	BuildVerified bool
	// VerifiedAt 是对拍通过时间（detail.verified_at，verify 写入）；从未对拍过为空串。
	VerifiedAt string
	// SelfCheck 是现在时刻的冷副本自校验结果（逐块解码核对，见 ChunkSelfCheck）。
	SelfCheck ChunkSelfCheck
	// Days 是 detail.days 的逐日切换记录（按日期升序）。空切片 = 该 run 还没切过任何一天。
	Days []DayRecord
}

// ChunkSelfCheck 是「现在时刻」的冷副本自校验：按 seq 逐块 Decode、核对块列与内容
// （count / 首末 ts / 块内同日同类同源）并核对 locator 成员集合与块内容精确相等。
// 遇到第一块失败就停下：ChunksChecked 是失败前已通过的块数，Err 带原因与块 id。
// Err == nil 表示该 run 全部冷块当前自洽。
type ChunkSelfCheck struct {
	ChunksChecked int
	EventsChecked int64
	Err           error
	FailureChunk  uuid.UUID
	FailureSeq    int
}

// DayRecord 是 detail.days.<UTC 日> 的切换实测记录（swapDayRecord 的导出版，
// JSON 字段名一致）。Kept/Dropped 是重写事务内实测的保留/移出数，与分区替换同事务提交。
type DayRecord struct {
	Day            time.Time
	SwappedAt      string
	Kept           int64
	Dropped        int64
	RunDayVerified bool
	Note           string
}

// RunState 汇总一个 run 的三类校验/操作状态。只读；自校验失败不作为函数错误返回
// （那是数据状态，SelfCheck.Err 承载），只有读库失败才返回错误。
//
// 自校验要逐块解压整个 run，代价与归档条数成正比（同 report）：大 run 上低峰期跑。
func RunState(ctx context.Context, db *sql.DB, runID uuid.UUID) (RunStateReport, error) {
	run, err := LoadRun(ctx, db, runID)
	if err != nil {
		return RunStateReport{}, err
	}
	r := RunStateReport{Run: run, BuildVerified: run.Status == StatusVerified, Days: []DayRecord{}}
	if len(run.Detail) > 0 {
		var detail struct {
			VerifiedAt string                   `json:"verified_at"`
			Days       map[string]swapDayRecord `json:"days"`
		}
		if err := json.Unmarshal(run.Detail, &detail); err != nil {
			return r, fmt.Errorf("解析 run %s 的 detail: %w", runID, err)
		}
		r.VerifiedAt = detail.VerifiedAt
		for day, rec := range detail.Days {
			d, err := time.Parse(time.DateOnly, day)
			if err != nil {
				return r, fmt.Errorf("run %s 的 detail.days 有无法解析的日期键 %q: %w", runID, day, err)
			}
			r.Days = append(r.Days, DayRecord{Day: d, SwappedAt: rec.SwappedAt,
				Kept: rec.Kept, Dropped: rec.Dropped, RunDayVerified: rec.RunDayVerified, Note: rec.Note})
		}
		sort.Slice(r.Days, func(i, j int) bool { return r.Days[i].Day.Before(r.Days[j].Day) })
	}

	// 冷副本自校验（现在时刻）：按 seq 逐块 load → Decode → check → locator 集合核对。
	// 与 verify 的差别：不与热表对拍（swap 之后热行已移出，对拍口径不成立），只看冷层自身。
	sc := &r.SelfCheck
	after := 0
	for {
		ch, ok, err := loadChunk(ctx, db, runID, after)
		if err != nil {
			return r, err
		}
		if !ok {
			return r, nil
		}
		after = ch.Seq
		events, err := ch.Block.Decode()
		if err == nil {
			err = ch.check(events)
		}
		if err == nil {
			err = checkLocatorMembers(ctx, db, ch, events)
		}
		if err != nil {
			sc.Err = fmt.Errorf("冷块 %s（seq %d，%s/%s）: %w",
				ch.ID, ch.Seq, ch.Day.Format(time.DateOnly), ch.Source, err)
			sc.FailureChunk, sc.FailureSeq = ch.ID, ch.Seq
			return r, nil
		}
		sc.ChunksChecked++
		sc.EventsChecked += int64(len(events))
	}
}

// String 把三类状态排成可直接核对的一段文字（CLI status 的输出）。
func (r RunStateReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "run %s  状态 %s\n", r.Run.ID, r.Run.Status)
	fmt.Fprintf(&b, "口径：%s..%s（UTC 日闭区间），类别 %v，来源 %v\n",
		r.Run.DayFrom.Format(time.DateOnly), r.Run.DayTo.Format(time.DateOnly), r.Run.Classes, r.Run.Sources)
	fmt.Fprintf(&b, "候选 %d 条：归档 %d 条 / %d 块，被钉住跳过 %d 条\n",
		r.Run.Scanned, r.Run.Archived, r.Run.Chunks, r.Run.PinnedSkip)
	if r.Run.Error.Valid {
		fmt.Fprintf(&b, "run 错误记录：%s\n", r.Run.Error.String)
	}
	switch {
	case r.BuildVerified && r.VerifiedAt != "":
		fmt.Fprintf(&b, "构建期对拍：通过过（粘性资格，verified_at=%s；证明的是对拍那一刻与热表一致，不证明此后仍一致）\n", r.VerifiedAt)
	case r.BuildVerified:
		fmt.Fprintf(&b, "构建期对拍：通过过（粘性资格；detail 里没有 verified_at，属老数据）\n")
	default:
		fmt.Fprintf(&b, "构建期对拍：未通过（状态 %s，不能作为 swap 的删除依据）\n", r.Run.Status)
	}
	if r.SelfCheck.Err != nil {
		fmt.Fprintf(&b, "冷副本自校验（现在时刻）：失败——已核对 %d 块后在第 %d 块停下：%v\n",
			r.SelfCheck.ChunksChecked, r.SelfCheck.FailureSeq, r.SelfCheck.Err)
	} else {
		fmt.Fprintf(&b, "冷副本自校验（现在时刻）：%d 块全部自洽（%d 条事件；不与热表对拍，swap 后热行已移出）\n",
			r.SelfCheck.ChunksChecked, r.SelfCheck.EventsChecked)
	}
	if len(r.Days) == 0 {
		b.WriteString("逐日操作记录：无（该 run 还没有切过任何一天）\n")
	} else {
		fmt.Fprintf(&b, "逐日操作记录（detail.days，与分区替换同一事务写入）：\n")
		for _, d := range r.Days {
			line := fmt.Sprintf("  %s  kept=%d dropped=%d run_day_verified=%v swapped_at=%s",
				d.Day.Format(time.DateOnly), d.Kept, d.Dropped, d.RunDayVerified, d.SwappedAt)
			if d.Note != "" {
				line += "  note=" + d.Note
			}
			fmt.Fprintln(&b, line)
		}
	}
	return b.String()
}
