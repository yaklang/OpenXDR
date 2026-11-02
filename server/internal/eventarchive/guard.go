package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"openxdr/server/internal/temporal"
)

// P4：消费者窗口、追平条件与派生状态（COLD_ARCHIVE_EVOLUTION.SCRATCH.md §P4，V08–V10）。
//
// swap 把一天的事件移出热表后，还回读 events 的后台消费者（beacon / assetmap / ueba /
// automation / temporal）与派生表是两块余下的风险：
//
//   - 消费者按各自的窗口回读历史（beacon 无基线回放学习期、assetmap 无游标回填 7 天、
//     temporal 候选按最大窗口求值）。切走它们仍要读的日子，丢的不是数据（冷块还在），
//     而是基线与检测的覆盖：重启回放会静默跳过、候选窗口缺一角。这里用两道闸门挡住：
//     min-age 有效下限（下述 Guard）保证待切日落在所有回读窗口之外，
//     消费进度证明（ConsumedThrough）保证后台已经处理过待切日。
//   - 派生表不在冷块里，restore 不重建；哪些表允许 swap 顺带删、哪些必须留下，
//     见 swapDerivedSkip 前的逐表决策表（V09）。

// MinAgeEnv 是运营下限的环境变量：天数，默认 14。它只是运营纪律，不是正确性证明本身——
// 正确性来自有效下限（与回读窗口取最大）与消费进度证明。
const MinAgeEnv = "EVENT_ARCHIVE_MIN_AGE_DAYS"

const defaultMinAgeDays = 14

// 下列常量各自注明来源；对应包未导出或值来自环境变量时在这里按同口径复制，
// 改那边时必须同步这里（测试 T15 断言 beacon 项的默认值，漂移会被抓住）。
const (
	// temporalPruneSlack 与 temporal.pruneSlack 同值（未导出）：处理事务从开始到读窗口的耗时余量。
	temporalPruneSlack = 10 * time.Minute
	// temporalFallbackBound 规则目录读不到时的保守下限，与 janitor 的 retireGuard 同口径
	// （24h + LateGrace + 1h 处理余量）：假设其他节点还挂着窗口上限 24h 的旧规则版本。
	temporalFallbackBound = 24*time.Hour + temporal.LateGrace + time.Hour
	// assetmapBackfill 与 assetmap.backfill 同值（未导出）：无游标时的回填窗口。
	assetmapBackfill = 7 * 24 * time.Hour
	// beaconLearningDefault / beaconWindowDefault 与 main.go 里 BEACON_LEARNING_DAYS /
	// BEACON_WINDOW_HOURS 的默认值一致（那边用 getenvInt 读，未导出）。
	beaconLearningDefault = 7 * 24 * time.Hour
	beaconWindowDefault   = 12 * time.Hour
)

// GuardTerm 是有效下限里参与取最大的一项。Bound 是该项单独要求的下限；
// Applied=false 表示它与本次 run 的口径无关（例如 run 不含 4001 时 beacon 的回读窗口
// 不适用），只作展示，不参与取最大。
type GuardTerm struct {
	Name    string
	Bound   time.Duration
	Applied bool
	Source  string
}

// ConsumerCheck 是一个消费者相对待切日的进度核对结果。Relevant=false 的消费者
// 回读的类别/来源与 run 口径不相交：本次切走的事件它根本不读，不构成阻塞。
type ConsumerCheck struct {
	Name     string
	Relevant bool
	Known    bool      // false = 没有持久进度可读（unknown），Swap 拒绝
	Through  time.Time // 持久进度时间，语义逐消费者（见 ConsumedThrough 的逐项注释）
	OK       bool
	Reason   string
}

// GuardReport 是一次切换闸门评估（只读）。Swap 据此拒绝；Plan 原样带出供人核对。
type GuardReport struct {
	Day        time.Time // UTC 日（零点）
	DayEnd     time.Time // 日结束 = 次日零点（分区上界）。min-age 判它，不判日开始
	Now        time.Time // 数据库当前时间（与 PruneCandidates/Observe 的迟到判断同一时钟）
	MinAgeDays int
	Effective  time.Duration // 有效下限 = 适用项（Applied）取最大
	Terms      []GuardTerm
	AgeOK      bool
	Consumers  []ConsumerCheck
	Allow      bool // AgeOK 且全部相关消费者 OK
}

// Guard 评估 run 的某一天是否允许切换（只读，不写任何东西）。三个来源全部运行时读取：
//
//	min-age    EVENT_ARCHIVE_MIN_AGE_DAYS（默认 14 天），运营下限；
//	temporal   max(实际规则窗口, 24h) + LateGrace + pruneSlack。窗口从规则目录加载
//	           （与 server 相同的 RULES_PATH / TEMPORAL_RULES_PATH）；读不到时退回
//	           temporalFallbackBound（与 janitor retireGuard 同口径的保守常量）；
//	beacon     max(BEACON_LEARNING_DAYS, BEACON_WINDOW_HOURS)（默认 7d/12h），
//	           仅当 run 口径含 4001+agent（beacon 只读这个组合）；
//	assetmap   7 天回填常量（assetmap.backfill），仅当 run 口径含 4001/5001/5020。
//
// ueba（1007）与 automation（3002）默认归档口径无交集，不进下限；扩大归档类别时须
// 重新评审（ueba 学习天数不能直接当回读窗口用，automation 的 WindowDays 重扫窗口同理）。
// 配置值解析失败直接报错，不静默退默认：宁可拒绝切换，也不在配置不明时放行。
func Guard(ctx context.Context, db *sql.DB, run Run, day time.Time) (GuardReport, error) {
	var now time.Time
	if err := db.QueryRowContext(ctx, `SELECT now()`).Scan(&now); err != nil {
		return GuardReport{}, fmt.Errorf("读数据库当前时间: %w", err)
	}
	now = now.UTC()
	days, err := minAgeDays()
	if err != nil {
		return GuardReport{}, err
	}
	terms, err := guardTerms(run, days)
	if err != nil {
		return GuardReport{}, err
	}
	r := GuardReport{Now: now, MinAgeDays: days, Terms: terms}
	for _, t := range terms {
		if t.Applied && t.Bound > r.Effective {
			r.Effective = t.Bound
		}
	}
	progress, err := ConsumedThrough(ctx, db)
	if err != nil {
		return GuardReport{}, err
	}
	r.Day, r.DayEnd = dayStart(day), dayStart(day).AddDate(0, 0, 1)
	r.Consumers = checkConsumption(run, r.DayEnd, progress)
	r.AgeOK = !r.DayEnd.After(now.Add(-r.Effective)) // 要求 dayEnd ≤ now − 有效下限
	r.Allow = r.AgeOK
	for _, c := range r.Consumers {
		if c.Relevant && !c.OK {
			r.Allow = false
		}
	}
	return r, nil
}

// guardTerms 组装有效下限的各项。beacon/assetmap 项只在回读范围与 run 口径相交时适用：
// 不含 4001 的 run（例如只有 4003 的 DNS）不会被 beacon 的学习期无谓挡住。
func guardTerms(run Run, minAgeDays int) ([]GuardTerm, error) {
	terms := []GuardTerm{{
		Name: "min-age", Bound: time.Duration(minAgeDays) * 24 * time.Hour, Applied: true,
		Source: fmt.Sprintf("%s=%d（默认 %d）", MinAgeEnv, minAgeDays, defaultMinAgeDays),
	}}
	window, source, err := temporalWindowBound()
	if err != nil {
		return nil, err
	}
	terms = append(terms, GuardTerm{
		Name: "temporal", Bound: max(window, 24*time.Hour) + temporal.LateGrace + temporalPruneSlack,
		Applied: true, // 任何类别的事件都可能带基础命中进候选，temporal 边界总是适用
		Source:  source,
	})
	learning, err := envDuration("BEACON_LEARNING_DAYS", 24*time.Hour, beaconLearningDefault)
	if err != nil {
		return nil, err
	}
	beaconWindow, err := envDuration("BEACON_WINDOW_HOURS", time.Hour, beaconWindowDefault)
	if err != nil {
		return nil, err
	}
	terms = append(terms, GuardTerm{
		Name: "beacon", Bound: max(learning, beaconWindow),
		Applied: scopeIntersects(run, []int64{4001}, []string{"agent"}),
		Source:  fmt.Sprintf("max(BEACON_LEARNING_DAYS=%s, BEACON_WINDOW_HOURS=%s)（默认 7d/12h）", learning, beaconWindow),
	})
	terms = append(terms, GuardTerm{
		Name:    "assetmap",
		Bound:   assetmapBackfill,
		Applied: scopeIntersects(run, []int64{4001, 5001, 5020}, nil),
		Source:  "assetmap 无游标回填 7d（assetmap.backfill 常量）",
	})
	return terms, nil
}

// temporalWindowBound 从规则目录读时序规则的最大窗口；读不到（目录缺失、清单不符、
// 规则坏文件）就用保守常量并注明来源。加载失败不作为错误：那是「读不到」，不是「闸门坏了」。
func temporalWindowBound() (time.Duration, string, error) {
	base := os.Getenv("RULES_PATH")
	if base == "" {
		base = "../rules" // 与 main.go 的默认一致
	}
	if snap, err := temporal.LoadSnapshot(base, os.Getenv("TEMPORAL_RULES_PATH")); err == nil {
		w := snap.MaxWindow()
		return w, fmt.Sprintf("规则目录实际最大窗口 %s（RULES_PATH/TEMPORAL_RULES_PATH）+ LateGrace %s + pruneSlack %s",
			w, temporal.LateGrace, temporalPruneSlack), nil
	}
	return temporalFallbackBound, fmt.Sprintf("规则目录读不到，退保守常量 %s（与 janitor retireGuard 同口径：24h + LateGrace %s + 1h 处理余量）",
		temporalFallbackBound, temporal.LateGrace), nil
}

// minAgeDays 读运营下限。设了但不是合法天数直接报错：静默退默认会让「配置写错」
// 表现成「闸门比预期松/紧」，排查时对不上账。
func minAgeDays() (int, error) {
	value := os.Getenv(MinAgeEnv)
	if value == "" {
		return defaultMinAgeDays, nil
	}
	days, err := strconv.Atoi(value)
	if err != nil || days < 0 {
		return 0, fmt.Errorf("%s=%q 不是合法的非负天数", MinAgeEnv, value)
	}
	return days, nil
}

// envDuration 读「数值 + 单位」形式的环境变量，与 main.go 的 getenvInt 同名同默认。
func envDuration(name string, unit, def time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return def, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s=%q 不是合法的非负数", name, value)
	}
	return time.Duration(n) * unit, nil
}

// scopeIntersects 报告 run 的口径与某个消费者的回读范围是否相交：
// 类别有交集，且（消费者不限来源，或来源也有交集）。不相交的消费者不读本次要切的行。
func scopeIntersects(run Run, classes []int64, sources []string) bool {
	hit := false
	for _, c := range run.Classes {
		if slices.Contains(classes, int64(c)) {
			hit = true
			break
		}
	}
	if !hit {
		return false
	}
	if len(sources) == 0 {
		return true
	}
	for _, s := range run.Sources {
		if slices.Contains(sources, s) {
			return true
		}
	}
	return false
}

// ConsumerProgress 是一个消费者的持久进度（只读汇总）。Classes/Sources 描述它回读的
// 事件范围，用来判断它与某个 run 的口径是否相关。Note 在 Known=false 时给出
// 「为什么 unknown」的具体说明（如配置指纹不一致），没有则用默认文案。
type ConsumerProgress struct {
	Name    string
	Classes []int64
	Sources []string // 空 = 任意来源
	Through time.Time
	Known   bool
	Note    string
}

// ConsumedThrough 汇总会回读 events 的各消费者的持久进度（只读）。这是「轻量证明」，
// 不是通用水位平台：每个消费者的持久状态语义不同，下面逐个写明这个值证明什么、
// 不证明什么——它不得被当成「已消费到该时间」以外的任何保证。
//
// beacon — settings[archive.beacon.scan]（引擎每完成一轮有固定上界的扫描后写入，
//
//	见 progress.go 的 RecordBeaconScan；载荷 {"through","at","rev"}）：
//	证明：ts ≤ through 的 4001/agent 事件已全部读过，且该轮全部业务副作用（基线、
//	     告警）成功提交后才发布；空区间/无命中同样推进（扫描完成 ≠ 有数据）。
//	不证明：through 之后的迟到事件——那遵循既有接入契约，扫描上界不是迟到截止水位；
//	     也不约束重启行为：游标回退到 now−窗口/学习期重新回放，重复告警由基线唯一性挡住。
//	闸门方向：标记缺失、载荷损坏，或 rev 与当前配置指纹不一致（窗口扩大/版本切换使
//	     旧证明失效）都按 unknown 拒绝；through 早于待切日结束同样拒绝。
//
// assetmap — settings[assetmap.cursor]（jsonb {"ts":…,"id":…}，旧格式是裸时间）：
//
//	证明：每批的依赖边/清单物化与游标 upsert 在同一事务提交，整批成功才推进
//	     （批内任何一步失败整体回滚，游标不动）；ts ≤ 游标的 4001/5001/5020 事件
//	     已物化。(ts,id) 元组游标保证同一时刻的多条事件不被批次边界或重启跳过
//	     （R3 核对结论，见 assetmap/engine.go 的 batch）。
//	不证明：游标之后的事件；没有 settings 行（unknown）说明从未跑过，或首次启用的
//	     7 天回填还没落第一批。空区间（游标后没有事件）不推进——闸门按未追平保守拒绝。
//	闸门方向：游标早于待切日结束 → 该日事件还没物化，拒绝。
//
// ueba — process_baselines 的 max(first_seen)（引擎重启从它恢复游标，只往前读）：
//
//	证明：1007 事件至少被读到该时间（批次里有新组合才写基线行，真实内存游标只会
//	     更靠后，不会靠前——单写者顺序推进）。
//	不证明：精确游标；批次里没有新组合时该值落后于实际进度，按它拒绝是保守方向。
//	闸门方向：max(first_seen) 早于待切日结束 → 待切日还没消费，拒绝。
//
// automation — ssh_logins 的 max(ts)（收集按游标前进、按事件 id 幂等，窗口外定期删）：
//
//	证明：有 ts ≤ 该时间的登录被收进过 ssh_logins，即该时段的 3002 登录被 collect
//	     扫过（它按 WindowDays 窗口重扫，这里取近似）。
//	不证明：非登录的 3002 事件；窗口外（> WindowDays+1）的行已删，max(ts) 只覆盖
//	     最近窗口。
//	闸门方向：max(ts) 早于待切日结束 → 近窗口里没有任何更早的登录痕迹，拒绝。
//
// 任一消费者 unknown 的默认方向是拒绝：swap 是热表行的不可逆移出，unknown 时放行的
// 失败模式是基线/检测缺口（静默、事后不可补），拒绝的失败模式只是晚切一天，等消费者
// 落下持久进度即可。宁可保守。
func ConsumedThrough(ctx context.Context, db *sql.DB) ([]ConsumerProgress, error) {
	out := make([]ConsumerProgress, 0, 4)
	// beacon：settings[archive.beacon.scan]。R3 起不再读 beacon_baselines 的
	// min(first_seen)——基线是业务数据不是读游标。无标记/载荷损坏/指纹不一致 = unknown。
	var beaconRaw []byte
	err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE id = $1`, BeaconScanKey).Scan(&beaconRaw)
	beacon := ConsumerProgress{Name: "beacon", Classes: []int64{4001}, Sources: []string{"agent"}}
	switch {
	case errors.Is(err, sql.ErrNoRows):
		out = append(out, beacon)
	case err != nil:
		return nil, fmt.Errorf("读 beacon 扫描完成标记: %w", err)
	default:
		rev, rerr := beaconScanRevFromEnv()
		if rerr != nil {
			return nil, rerr
		}
		var m beaconScanMarker
		switch {
		case json.Unmarshal(beaconRaw, &m) != nil || m.Through.IsZero():
			beacon.Note = "扫描完成标记存在但载荷读不懂（through 缺失或格式损坏），按 unknown 拒绝"
			out = append(out, beacon)
		case m.Rev != rev:
			beacon.Note = fmt.Sprintf(
				"扫描完成标记的配置指纹与当前不一致（标记 rev=%q，当前 rev=%q）：学习期/窗口变化使旧证明失效，等引擎用新配置跑完一轮后再切",
				m.Rev, rev)
			out = append(out, beacon)
		default:
			beacon.Through, beacon.Known = m.Through, true
			out = append(out, beacon)
		}
	}
	// assetmap：settings 里的游标（jsonb {"ts":…,"id":…}；旧格式是裸时间，同值读取）。
	var raw []byte
	err = db.QueryRowContext(ctx, `SELECT value FROM settings WHERE id = 'assetmap.cursor'`).Scan(&raw)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		out = append(out, ConsumerProgress{Name: "assetmap", Classes: []int64{4001, 5001, 5020}})
	case err != nil:
		return nil, fmt.Errorf("读 assetmap 游标: %w", err)
	default:
		var at time.Time
		var tuple struct {
			Ts time.Time `json:"ts"`
		}
		if json.Unmarshal(raw, &tuple) == nil && !tuple.Ts.IsZero() {
			out = append(out, ConsumerProgress{Name: "assetmap", Classes: []int64{4001, 5001, 5020},
				Through: tuple.Ts, Known: true})
		} else if json.Unmarshal(raw, &at) != nil {
			out = append(out, ConsumerProgress{Name: "assetmap", Classes: []int64{4001, 5001, 5020}})
		} else {
			out = append(out, ConsumerProgress{Name: "assetmap", Classes: []int64{4001, 5001, 5020},
				Through: at, Known: true})
		}
	}
	// ueba：max(first_seen)（游标恢复点）。
	var ueba sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT max(first_seen) FROM process_baselines`).Scan(&ueba); err != nil {
		return nil, fmt.Errorf("读 ueba 基线进度: %w", err)
	}
	out = append(out, ConsumerProgress{Name: "ueba", Classes: []int64{1007}, Through: ueba.Time, Known: ueba.Valid})
	// automation：ssh_logins 的 max(ts)。
	var auto sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT max(ts) FROM ssh_logins`).Scan(&auto); err != nil {
		return nil, fmt.Errorf("读 automation 登录进度: %w", err)
	}
	out = append(out, ConsumerProgress{Name: "automation", Classes: []int64{3002}, Sources: []string{"agent"},
		Through: auto.Time, Known: auto.Valid})
	return out, nil
}

// checkConsumption 把各消费者的持久进度对照待切日结束逐个判定。R3 起四项进度同向：
// 都是「游标/完成上界已推进到的位置」（max 语义），要越过待切日才算数——beacon 此前
// 「min(first_seen) 反向覆盖」的判定已随代理证明一起废弃（见 ConsumedThrough 的 beacon 注释）。
// 纯函数：只消费 ConsumedThrough 读出的值与 run 口径。
func checkConsumption(run Run, dayEnd time.Time, progress []ConsumerProgress) []ConsumerCheck {
	checks := make([]ConsumerCheck, 0, len(progress))
	for _, p := range progress {
		c := ConsumerCheck{Name: p.Name, Relevant: scopeIntersects(run, p.Classes, p.Sources)}
		switch {
		case !c.Relevant:
			c.OK = true
			c.Reason = fmt.Sprintf("回读范围（类别 %v，来源 %v）与 run 口径（类别 %v，来源 %v）不相交，本次切换不读它",
				p.Classes, p.Sources, run.Classes, run.Sources)
		case !p.Known:
			c.OK = false
			if p.Note != "" {
				c.Reason = p.Note
			} else {
				c.Reason = "没有持久进度可读（unknown）：游标/完成标记为空，无法证明已处理待切日"
			}
		default:
			// 游标/扫描完成上界必须不早于日结束：还落在待切日之前 ⇒ 该日事件尚未消费。
			c.Through = p.Through
			c.OK = !p.Through.Before(dayEnd)
			c.Reason = fmt.Sprintf("%s 持久进度=%s，要求 ≥ 日结束 %s",
				p.Name, p.Through.Format(time.RFC3339), dayEnd.Format(time.RFC3339))
		}
		checks = append(checks, c)
	}
	return checks
}

// refusal 把拒绝原因拼成一条错误：年龄项列出日结束、有效下限数值与贡献最大值的来源；
// 消费项逐个列出名字与原因。放行时返回 nil。
func (r GuardReport) refusal() error {
	if r.Allow {
		return nil
	}
	var problems []string
	if !r.AgeOK {
		top := ""
		for _, t := range r.Terms {
			if t.Applied && t.Bound == r.Effective {
				top = t.Name
				break
			}
		}
		problems = append(problems, fmt.Sprintf("日结束 %s 不够老：有效下限 %s（贡献最大值的来源：%s：%s），要求日结束 ≤ 数据库时间 %s − 下限",
			r.DayEnd.Format(time.RFC3339), r.Effective, top, topTermSource(r.Terms, r.Effective), r.Now.Format(time.RFC3339)))
	}
	for _, c := range r.Consumers {
		if c.Relevant && !c.OK {
			problems = append(problems, fmt.Sprintf("消费者 %s 未追平：%s", c.Name, c.Reason))
		}
	}
	return errors.New("P4 切换闸门拒绝：" + strings.Join(problems, "；"))
}

// topTermSource 返回贡献了 effective 值的第一项的来源说明。
func topTermSource(terms []GuardTerm, effective time.Duration) string {
	for _, t := range terms {
		if t.Applied && t.Bound == effective {
			return t.Source
		}
	}
	return "（未找到，异常）"
}

// ─── 派生状态保护（V09）：swap 的逐表决策表 ──────────────────────────────────────
//
// RewriteDay 的派生清理删除「事件列 ∈ 本日分区 − 暂存表」的行——即只删**随本次切换被移出
// 热表**的事件对应的派生行，保留行（pin/口径外/无冷副本）的派生行一律不动。retire 走同一份
// derived 清单（保留期到了连事件一起删，派生行自然跟着走）；swap 不一样：事件只是移进冷块，
// 还可以 Restore 回来，因此哪些派生行允许顺带删必须逐表查证，不能因为清单里有表名就照删。
//
//	表名                         | swap 是否清 | 依据                                                                 | 读者
//	-----------------------------|------------|----------------------------------------------------------------------|----
//	temporal_matches             | 清（现行为）| 认证序列的已消费命中记录，只由 3002 告警回查写入；**默认口径 4001/4003 不产生行（no-op）**。若口径扩到 3002：事件本身已移出热表，authSequence 的回查读 events 找不到它，清 matches 与事件离开一致；restore 后重放可能重复出告警，属「扩类别时重新评审」项 | ingest/auth_sequence.go 的 NOT EXISTS 回查
//	temporal_candidates          | 清（现行为）| 求值只按 (revision, 实体, ts ≥ now−窗口) 读；Guard 的 temporal 项保证待切日结束 ≤ now−(max(窗口,24h)+LateGrace+pruneSlack)，即 PruneCandidates 当前与其他版本的清理阈值都已覆盖，被删候选不可能再被在线求值读到。Prune 停摆也不阻塞：安全条件是「已失效」，不是「已被物理删除」 | temporal/postgres.go observeScope 的窗口回查
//	temporal_evaluation_gaps     | **不清**    | 诊断记录，有真实读者：GET /api/temporal-gaps 按资产+时间窗列出缺口，只 JOIN assets（event_id 无外键），事件移出热表后 gap 行仍完整可读。swap 顺带删会让分析侧的缺口清单在保留期之前静默缩水。清理链路（R6）：swap 跳过本表后，retire 的「日分区 − 暂存」差集清理与逐行删除触发器（openxdr_events_release，只在热行 DELETE 时触发，搬运被 skipWhenMoving 抑制）都看不到已被移出热表的事件的 gap——这类 gap 由 janitor 按 gap 自身 created_at 的诊断保留期（TEMPORAL_GAP_RETENTION_DAYS，默认 30 天）清理，不 JOIN events；仍留在日分区里的事件的 gap 照旧随 retire 的差集清理 | api/temporal_gaps.go、janitor sweepTemporalGaps
//	temporal_detections          | 清（现行为）| 按锚点删。已出告警的检测锚点在 PinnedIDs 里（WHERE alert_id IS NOT NULL），事件被 pin 保留、检测行不会被删；能被删到的只有被抑制（alert_id NULL）的检测，与 retire 同口径 | api/temporal_rules.go、ingest 告警关联
//	identity_observations        | 清（现行为）| 只由 agent+3002+Windows 登录写入（identity/postgres.go ObserveWindows），**默认口径 4001/4003 不产生行（no-op）**。注意它的读者 JOIN events（api/identity.go 等），事件移出热表后行会从联查结果里消失——扩口径到 3002 前必须重新评审 | api/identity*.go（多数 JOIN events）
//	identity_local_snapshots     | 清（现行为）| 只由 agent+5001+Linux 清单写入（identity/linux_accounts_postgres.go），**默认口径 4001/4003 不产生行（no-op）**；读者同样 JOIN events，扩口径到 5001 前重新评审 | api/local_accounts.go、identity/graph.go
//
// 结论：默认归档口径（4001/4003）下，identity_* 与 temporal_matches 对 swap 是 no-op；
// 真正会被删且需要保护的是 temporal_evaluation_gaps。T17/T18 的测试逐表断言本表。

// swapDerivedSkip 是 swap 注入 eventpart.RewriteHooks.DerivedSkip 的口径：
// 只跳过 temporal_evaluation_gaps（诊断记录，见上表），其余按 derived 清单照旧清理。
// retire 不走这里，但 retire 的差集清理同样只覆盖仍留在日分区里的事件——已被 swap
// 移出热表的事件的 gap 两条路径（retire 差集、逐行删除触发器）都看不到，由 janitor
// 按 created_at 诊断保留期清理（R6）。
func swapDerivedSkip(table string) bool {
	return table == "temporal_evaluation_gaps"
}
