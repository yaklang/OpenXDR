// eventarchive 是冷归档的阶段 A（影子归档）的命令行：只写新建的 event_archive_chunks /
// event_archive_runs 两张表，**不改动 events 的任何一行**，也不 DETACH / ATTACH / DROP 分区。
//
// 用法: DATABASE_URL=... eventarchive <子命令>
//
//	ensure-schema                                    建两张新表（幂等）
//	shadow -from 2026-09-01 -to 2026-09-14 [-classes 4001,4003] [-sources agent,sensor]
//	       [-chunk-events 2048] [-chunk-bytes 1048576] -confirm
//	verify -run <uuid>                               按 run 口径重扫对拍，通过才置 verified
//	status -run <uuid>                               三类状态分层汇总：对拍资格 / 当前自校验 / 逐日操作记录（只读）
//	backfill-locator -confirm                        给缺索引的旧块一次性补 locator 行（幂等），
//	                                               成功后发布 settings[archive.locator.complete] 完成标记
//	report -run <uuid>                               归档前后的真实大小与压缩比
//	locate -id <uuid>                                按事件 ID 找一条冷事件（只读）
//	materialize -id <uuid> -confirm                  把一条冷事件物化回 events（幂等，不产告警）
//	plan -run <uuid> -day YYYY-MM-DD                 单日切换计划（只读，用于人工核对）
//	swap -run <uuid> -day YYYY-MM-DD -confirm        重建该日分区，移出有冷副本的归档行（阶段 C，P3 原子切换）
//	restore -run <uuid> -day YYYY-MM-DD -confirm     把该日冷事件物化回 events（幂等，用于回滚）
//
// shadow / materialize / swap / restore / backfill-locator 会写库，不加 -confirm 直接拒绝
// （没有演练模式）。verify 只改 run 的状态列；ensure-schema 只建冷归档表；
// locate / plan / status 只读。设计与阶段见 docs/event-archive.md；分区侧的工程口径见
// docs/event-partitioning.md。
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/internal/eventarchive"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "缺少 DATABASE_URL")
		usage()
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()
	if err := run(ctx, db, os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "失败:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法: DATABASE_URL=... eventarchive <子命令>
  ensure-schema                                     建 event_archive_chunks / event_archive_runs（幂等）
  shadow -from YYYY-MM-DD -to YYYY-MM-DD [选项] -confirm
                                                    影子归档：只读 events，写冷块（会写库）
       -classes 4001,4003     归档类别（默认 4001,4003）
       -sources agent,sensor  来源（默认范围内全部）
       -chunk-events 2048     单块事件条数上限
       -chunk-bytes 1048576   单块未压缩明文字节上限
  verify -run <uuid>                                重扫对拍，通过后置 verified
  status -run <uuid>                                三类状态分层：对拍资格 / 当前自校验 / 逐日记录（只读，自校验要解压全部块）
  backfill-locator -confirm                         给缺索引的旧冷块补 locator 行（一次性迁移，幂等）；
                                                    成功后发布完成标记 settings[archive.locator.complete]，
                                                    手工动过 locator 行后必须重跑本命令校正标记
  report -run <uuid>                                归档前后大小、压缩比与含索引对比
  locate -id <uuid>                                 按事件 ID 找一条冷事件（只读）
  materialize -id <uuid> -confirm                   把一条冷事件物化回 events（幂等，不产告警）
  plan -run <uuid> -day YYYY-MM-DD                  单日切换计划（只读估计，实际以事务内实测为准）
  swap -run <uuid> -day YYYY-MM-DD -confirm         重建该日分区：只保留钉住的、非归档类别/来源的、没有冷副本的行
  restore -run <uuid> -day YYYY-MM-DD -confirm      把该日冷事件物化回 events（幂等，用于回滚 swap）`)
	os.Exit(2)
}

func run(ctx context.Context, db *sql.DB, cmd string, args []string) error {
	switch cmd {
	case "ensure-schema":
		fs := flag.NewFlagSet("ensure-schema", flag.ExitOnError)
		fs.Parse(args)
		if err := eventarchive.EnsureSchema(ctx, db); err != nil {
			return err
		}
		fmt.Println("已确保冷归档表存在：event_archive_chunks、event_archive_runs")
		return nil

	case "shadow":
		fs := flag.NewFlagSet("shadow", flag.ExitOnError)
		from := fs.String("from", "", "起始日（YYYY-MM-DD，UTC，含）")
		to := fs.String("to", "", "结束日（YYYY-MM-DD，UTC，含）")
		classes := fs.String("classes", "4001,4003", "归档类别，逗号分隔")
		sources := fs.String("sources", "", "来源，逗号分隔；空为范围内全部")
		chunkEvents := fs.Int("chunk-events", eventarchive.DefaultChunkEvents, "单块事件条数上限")
		chunkBytes := fs.Int("chunk-bytes", eventarchive.DefaultChunkBytes, "单块未压缩明文字节上限")
		confirm := fs.Bool("confirm", false, "确认执行会写库的步骤")
		fs.Parse(args)
		dayFrom, err := parseDay(*from)
		if err != nil {
			return fmt.Errorf("-from: %w", err)
		}
		dayTo, err := parseDay(*to)
		if err != nil {
			return fmt.Errorf("-to: %w", err)
		}
		classList, err := parseClasses(*classes)
		if err != nil {
			return err
		}
		runID, err := eventarchive.Shadow(ctx, db, eventarchive.Options{
			From: dayFrom, To: dayTo, Classes: classList, Sources: parseList(*sources),
			ChunkEvents: *chunkEvents, ChunkBytes: *chunkBytes, Confirm: *confirm,
		})
		if err != nil {
			return err
		}
		runInfo, err := eventarchive.LoadRun(ctx, db, runID)
		if err != nil {
			return err
		}
		fmt.Printf("影子归档 run %s 完成（status=%s）\n", runID, runInfo.Status)
		fmt.Printf("  候选 %d 条：归档 %d 条（%d 块），被钉住跳过 %d 条\n",
			runInfo.Scanned, runInfo.Archived, runInfo.Chunks, runInfo.PinnedSkip)
		fmt.Printf("  口径 %s..%s（UTC），类别 %v，来源 %v\n",
			runInfo.DayFrom.Format(time.DateOnly), runInfo.DayTo.Format(time.DateOnly), runInfo.Classes, runInfo.Sources)
		fmt.Println("  下一步：eventarchive verify -run", runID)
		return nil

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		id := fs.String("run", "", "要核对的 run id（uuid）")
		fs.Parse(args)
		runID, err := parseRun(*id)
		if err != nil {
			return err
		}
		if err := eventarchive.Verify(ctx, db, runID); err != nil {
			return err
		}
		fmt.Printf("run %s 对拍通过：逐事件全字段一致，已置 verified\n", runID)
		return nil

	case "status":
		fs := flag.NewFlagSet("status", flag.ExitOnError)
		id := fs.String("run", "", "要查看的 run id（uuid）")
		fs.Parse(args)
		runID, err := parseRun(*id)
		if err != nil {
			return err
		}
		r, err := eventarchive.RunState(ctx, db, runID)
		if err != nil {
			return err
		}
		fmt.Print(r.String())
		fmt.Println("说明：verified 是对拍那一刻的粘性资格，不自证此后冷块未被改坏；")
		fmt.Println("      自校验失败时先按块 id 定位（eventarchive locate -id 逐条核对），修复原因后再评估是否重新 verify。")
		return nil

	case "backfill-locator":
		fs := flag.NewFlagSet("backfill-locator", flag.ExitOnError)
		confirm := fs.Bool("confirm", false, "确认执行会写库的步骤")
		fs.Parse(args)
		if !*confirm {
			// 先报当前缺口（只读），让运维知道要补多少，再决定加不加 -confirm。
			missing, _, err := eventarchive.LocatorMissing(ctx, db)
			if err != nil {
				return fmt.Errorf("回填需要 -confirm；查当前缺口也失败了: %w", err)
			}
			return fmt.Errorf("回填会往 event_archive_locator 写行，必须显式确认（-confirm）；当前有 %d 块缺 locator 行", missing)
		}
		blocks, err := eventarchive.BackfillLocator(ctx, db)
		if err != nil {
			return err
		}
		if blocks == 0 {
			fmt.Println("locator 已完整：没有任何冷块缺索引行（无需回填）")
		} else {
			fmt.Printf("已回填 %d 块的 locator 行，覆盖性核对通过（没有缺行的块）\n", blocks)
		}
		// R4：完成标记决定未命中路径是「确定不存在」还是反连接判定，必须打印让运维核对。
		complete, err := eventarchive.LocatorComplete(ctx, db)
		if err != nil {
			return fmt.Errorf("回填成功但读完成标记失败: %w", err)
		}
		if complete {
			fmt.Println("完成标记 settings[archive.locator.complete]=true：Locate/Exists 未命中为「确定不存在」，不再反连接全部块")
			fmt.Println("  注意：手工增删 locator 行（不经过本命令）不会使该标记失效——动过 locator 必须重跑 backfill-locator 校正")
		} else {
			fmt.Println("完成标记未发布（false/缺失）：未命中仍按反连接判定，有缺行块时报 ErrLocatorIncomplete")
		}
		fmt.Println("  重跑本命令幂等（返回 0 块）")
		return nil

	case "report":
		fs := flag.NewFlagSet("report", flag.ExitOnError)
		id := fs.String("run", "", "要度量的 run id（uuid）")
		fs.Parse(args)
		runID, err := parseRun(*id)
		if err != nil {
			return err
		}
		r, err := eventarchive.Measure(ctx, db, runID)
		if err != nil {
			return err
		}
		fmt.Print(r.String())
		return nil

	case "locate":
		fs := flag.NewFlagSet("locate", flag.ExitOnError)
		id := fs.String("id", "", "要定位的事件 id（uuid）")
		fs.Parse(args)
		eventID, err := parseID(*id)
		if err != nil {
			return err
		}
		e, found, err := eventarchive.Locate(ctx, db, eventID)
		if err != nil {
			return err
		}
		if !found {
			fmt.Printf("冷层命中：否（候选块全部解压比对过，冷层确实没有这条事件）\n")
			fmt.Printf("  id = %s\n", eventID)
			return nil
		}
		fmt.Printf("冷层命中：是（在冷块中找到）\n")
		fmt.Printf("  id        = %s\n", e.ID)
		fmt.Printf("  ts        = %s\n", e.Ts.Format(time.RFC3339Nano))
		fmt.Printf("  class_uid = %d\n", e.ClassUID)
		fmt.Printf("  source    = %s\n", e.Source)
		fmt.Printf("  asset_id  = %s\n", optionalUUID(e.AssetID))
		return nil

	case "materialize":
		fs := flag.NewFlagSet("materialize", flag.ExitOnError)
		id := fs.String("id", "", "要物化的事件 id（uuid）")
		confirm := fs.Bool("confirm", false, "确认执行会写库的步骤")
		fs.Parse(args)
		eventID, err := parseID(*id)
		if err != nil {
			return err
		}
		if !*confirm {
			return fmt.Errorf("物化会往 events 插入一行，必须显式确认（-confirm）")
		}
		inserted, err := eventarchive.Materialize(ctx, db, eventID)
		if err != nil {
			return err
		}
		if inserted {
			fmt.Printf("已物化事件 %s：往 events 插入 1 行（复制，不经过检测器，不产告警）\n", eventID)
			return nil
		}
		// inserted=false 有两种原因，用 Locate 分清：events 里本来就有（幂等），还是冷层没有。
		_, found, locateErr := eventarchive.Locate(ctx, db, eventID)
		switch {
		case locateErr != nil:
			fmt.Printf("未插入（inserted=false）：events 里已有这条事件，或冷层没有；复查冷层失败: %v\n", locateErr)
		case !found:
			fmt.Printf("冷层没有事件 %s：未插入任何行\n", eventID)
		default:
			fmt.Printf("事件 %s 已在 events 里：未插入（物化幂等，events 里只有这一行）\n", eventID)
		}
		return nil

	case "plan":
		fs := flag.NewFlagSet("plan", flag.ExitOnError)
		id := fs.String("run", "", "要核对的 run id（uuid）")
		day := fs.String("day", "", "要切换的 UTC 日（YYYY-MM-DD）")
		fs.Parse(args)
		runID, err := parseRun(*id)
		if err != nil {
			return err
		}
		d, err := parseDay(*day)
		if err != nil {
			return fmt.Errorf("-day: %w", err)
		}
		p, err := eventarchive.Plan(ctx, db, runID, d)
		if err != nil {
			return err
		}
		run, err := eventarchive.LoadRun(ctx, db, runID)
		if err != nil {
			return err
		}
		fmt.Printf("run %s 状态 %s；口径 %s..%s（UTC），类别 %v，来源 %v\n",
			run.ID, run.Status, run.DayFrom.Format(time.DateOnly), run.DayTo.Format(time.DateOnly),
			run.Classes, run.Sources)
		fmt.Printf("日 %s 的切换计划（只读，未写任何东西）：\n", p.Day.Format(time.DateOnly))
		fmt.Printf("  分区行数 %d = 将移出 %d（口径内已归档，估计）+ 钉住保留 %d + 其它类别/来源保留 %d\n",
			p.Total, p.Archived, p.KeepPinned, p.KeepOther)
		switch {
		case run.Status != eventarchive.StatusVerified:
			fmt.Printf("  swap 会拒绝：run 状态是 %s，不是 verified\n", run.Status)
		case p.Archived == 0:
			fmt.Println("  swap 会拒绝：这一天没有被归档的事件（Archived=0）")
		default:
			fmt.Println("  计划是事务外估计值，不是冻结快照：没有冷副本的行（超大、shadow 之后到达）执行时留热，")
			fmt.Println("  实际结果以事务内实测为准（写入 detail.days，与分区替换同一事务）")
			fmt.Printf("  下一步（会删数据，需 -confirm）：eventarchive swap -run %s -day %s -confirm\n",
				runID, p.Day.Format(time.DateOnly))
		}
		return nil

	case "swap":
		fs := flag.NewFlagSet("swap", flag.ExitOnError)
		id := fs.String("run", "", "要切换的 run id（uuid）")
		day := fs.String("day", "", "要切换的 UTC 日（YYYY-MM-DD）")
		confirm := fs.Bool("confirm", false, "确认执行会写库的步骤")
		fs.Parse(args)
		runID, err := parseRun(*id)
		if err != nil {
			return err
		}
		d, err := parseDay(*day)
		if err != nil {
			return fmt.Errorf("-day: %w", err)
		}
		if !*confirm {
			return fmt.Errorf("切换会重建该日分区并移出其中已归档的行，必须显式确认（-confirm）")
		}
		p, err := eventarchive.Swap(ctx, db, runID, d)
		if err != nil {
			return err
		}
		fmt.Printf("已切换 %s 的分区：事务内实测保留 %d 行、移出 %d 行（预检估计：口径内未钉住 %d、钉住 %d、其它 %d，共 %d）\n",
			p.Day.Format(time.DateOnly), p.Kept, p.Dropped, p.Archived, p.KeepPinned, p.KeepOther, p.Total)
		if p.Kept > p.KeepPinned+p.KeepOther {
			fmt.Printf("  保留数比预检多 %d 行：这些行没有冷副本（超大或 shadow 之后到达），按事务内核对留热\n",
				p.Kept-(p.KeepPinned+p.KeepOther))
		}
		fmt.Printf("  实际结果已写入 run 的 detail.days.%s（与分区替换同一事务提交）；移出的行仍在冷块，"+
			"可按 ID 定位（locate）或整日还原：eventarchive restore -run %s -day %s -confirm\n",
			p.Day.Format(time.DateOnly), runID, p.Day.Format(time.DateOnly))
		// 切走之后重放判重就落在冷层上，server 那边必须是开着的。CLI 读不到 server 的环境变量，
		// 所以这里只陈述要求，不去猜配置。
		fmt.Println("  提醒：此后重放已切走的事件，server 必须设 EVENT_ARCHIVE_DEDUP=1（与 EVENT_ARCHIVE_READ 独立），" +
			"否则迟到/重传会重新入库并重复告警；各节点还有最多 60 秒的归档边界缓存窗口")
		return nil

	case "restore":
		fs := flag.NewFlagSet("restore", flag.ExitOnError)
		id := fs.String("run", "", "要还原的 run id（uuid）")
		day := fs.String("day", "", "要还原的 UTC 日（YYYY-MM-DD）")
		confirm := fs.Bool("confirm", false, "确认执行会写库的步骤")
		fs.Parse(args)
		runID, err := parseRun(*id)
		if err != nil {
			return err
		}
		d, err := parseDay(*day)
		if err != nil {
			return fmt.Errorf("-day: %w", err)
		}
		if !*confirm {
			return fmt.Errorf("还原会往 events 插入行，必须显式确认（-confirm）")
		}
		n, err := eventarchive.Restore(ctx, db, runID, d)
		if err != nil {
			// 部分完成是合法结果（块级原子）：错误输出必须保留实际插入数——运维按热表
			// 事实与 run.detail 的恢复记录对账后幂等重跑，不能把错误读成一行都没插。
			return fmt.Errorf("还原 %s 失败：已插入 %d 行（部分完成，结果以热表与 detail.days 记录为准，可幂等重跑）: %w",
				d.Format(time.DateOnly), n, err)
		}
		fmt.Printf("已把 %s 的冷事件物化回 events：插入 %d 行（已存在的不计，重复执行返回 0）\n",
			d.Format(time.DateOnly), n)
		return nil
	}
	usage()
	return nil
}

func parseDay(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("必填（YYYY-MM-DD）")
	}
	return time.Parse(time.DateOnly, s)
}

func parseRun(s string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, fmt.Errorf("-run 必填（uuid）")
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("-run %q 不是 uuid: %w", s, err)
	}
	return id, nil
}

func parseID(s string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, fmt.Errorf("-id 必填（uuid）")
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("-id %q 不是 uuid: %w", s, err)
	}
	return id, nil
}

func optionalUUID(id *uuid.UUID) string {
	if id == nil {
		return "NULL"
	}
	return id.String()
}

func parseList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseClasses(s string) ([]int, error) {
	var out []int
	for _, part := range parseList(s) {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("-classes 里的 %q 不是整数: %w", part, err)
		}
		out = append(out, n)
	}
	return out, nil
}
