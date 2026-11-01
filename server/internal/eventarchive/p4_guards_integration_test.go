//go:build integration

// P4 集成测试：消费者窗口、追平条件与派生状态（COLD_ARCHIVE_EVOLUTION.SCRATCH.md §P4、
// 5.2 节 T15/T15b/T16/T17/T18，V08–V10 的实现侧）。
//
//   - T15：min-age 有效下限（日结束判定、min-age=0 时 temporal 边界仍生效、day_end vs day_start）；
//   - T15b：消费进度证明（unknown 拒绝、beacon 进度晚于待切日拒绝、越过待切日放行）；
//   - T16：beacon 与 assetmap 的「swap vs 全热对照」——比较基线/依赖边/命中 flow 的集合，
//     不只比数量；每个分支各自开新库（testdb.New 清表），输入完全一致，唯一变量是要不要 swap；
//   - T17：temporal 候选——窗口内候选不被触碰、被移出事件的候选（含旧规则版本）照决策表清理；
//   - T18：temporal_evaluation_gaps 不随 swap 删除（决策表）、identity_*/temporal_matches/
//     temporal_detections 按决策表断言。
//
// 专用测试库 openxdr_p0，与其它集成测试一样串行（-p 1）。复用 p0_*.go 的夹具 helper。
package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/internal/assetmap"
	"openxdr/server/internal/beacon"
	"openxdr/server/internal/eventpart"
)

// ─── 共用夹具 ──────────────────────────────────────────────────────────────────

// p4VerifiedRun 按指定口径跑影子归档并对拍通过（p0VerifiedRun 固定 4001/agent，这里可变）。
func p4VerifiedRun(t *testing.T, ctx context.Context, db *sql.DB, from, to time.Time, classes []int, sources []string) uuid.UUID {
	t.Helper()
	runID, err := Shadow(ctx, db, Options{From: from, To: to, Classes: classes, Sources: sources, Confirm: true})
	if err != nil {
		t.Fatalf("影子归档失败: %v", err)
	}
	if err := Verify(ctx, db, runID); err != nil {
		t.Fatalf("对拍失败: %v", err)
	}
	return runID
}

// p4SeedBeaconScan 播种 beacon 的扫描完成标记：走真实写入器 RecordBeaconScan（引擎每轮
// 收尾写的是同一行）。R3 起 ConsumedThrough 的 beacon 项读 settings[archive.beacon.scan]，
// 不再读 beacon_baselines 的 min(first_seen)——基线是业务数据，不是读游标。
func p4SeedBeaconScan(t *testing.T, ctx context.Context, db *sql.DB, through time.Time) {
	t.Helper()
	if err := RecordBeaconScan(ctx, db, through, time.Now(), beaconLearningDefault, beaconWindowDefault); err != nil {
		t.Fatalf("播种 beacon 扫描完成标记: %v", err)
	}
}

// p4SeedAssetmapCursor 播种 assetmap 的持久游标（settings[assetmap.cursor]，ConsumedThrough 读同一行）。
func p4SeedAssetmapCursor(t *testing.T, ctx context.Context, db *sql.DB, at time.Time) {
	t.Helper()
	value, _ := json.Marshal(at)
	if _, err := db.ExecContext(ctx, `INSERT INTO settings (id, value, updated_at)
 VALUES ('assetmap.cursor', $1::jsonb, now()) ON CONFLICT (id) DO UPDATE SET value = EXCLUDED.value`,
		string(value)); err != nil {
		t.Fatalf("播种 assetmap 游标: %v", err)
	}
}

// p4SeedConsumed 让 4001/agent 口径的 run 通过消费进度闸门：beacon 的扫描完成标记
// 与 assetmap 游标都越过日结束（取 now）。日子的年龄条件由各用例自己控制环境变量。
func p4SeedConsumed(t *testing.T, ctx context.Context, db *sql.DB, day time.Time) {
	t.Helper()
	p4SeedBeaconScan(t, ctx, db, time.Now())
	p4SeedAssetmapCursor(t, ctx, db, time.Now())
}

// p4PollCountAtLeast 轮询直到标量计数达到下限；超时把「卡在哪个值上」写进失败信息。
// 行还不存在（sql.ErrNoRows）按 0 处理继续等。后台引擎（beacon/assetmap）用 goroutine 驱动，
// 稳定判据是可观察的库状态，不用 sleep 猜。
func p4PollCountAtLeast(t *testing.T, ctx context.Context, db *sql.DB, query string, atLeast int64, args ...any) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var n int64
	for {
		err := db.QueryRowContext(ctx, query, args...).Scan(&n)
		if errors.Is(err, sql.ErrNoRows) {
			n = 0
		} else if err != nil {
			t.Fatalf("轮询 %q: %v", query, err)
		}
		if n >= atLeast {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待 %q ≥ %d 超时（当前 %d）", query, atLeast, n)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// p4ColumnSet 把一列字符串查询读成有序切片，用于集合断言（分支对照比较集合而非数量）。
func p4ColumnSet(t *testing.T, ctx context.Context, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		t.Fatalf("查询 %q: %v", query, err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("读取 %q: %v", query, err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍历 %q: %v", query, err)
	}
	slices.Sort(out)
	return out
}

// ─── T15：min-age 闸门 ─────────────────────────────────────────────────────────

// 今天/边界内的日子被拒绝且错误带依据来源；边界外的日子放行；
// EVENT_ARCHIVE_MIN_AGE_DAYS=0 时 temporal 边界仍然生效（且 4003 口径不受 beacon/assetmap 项影响）；
// 年龄判定用日结束，不是日开始。
func TestP4T15MinAgeGate(t *testing.T) {
	t.Run("今天拒绝且错误含依据", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		day := p0Today()
		for i := 1; i <= 3; i++ {
			p0Event(t, ctx, client, day.Add(time.Duration(i)*time.Minute), 4001, "agent",
				fmt.Sprintf(`{"mark":"t15-today-%d","conn":{"dst":"10.0.0.1:443"}}`, i))
		}
		runID := p0VerifiedRun(t, ctx, db, day, day)
		_, err := Swap(ctx, db, runID, day)
		if err == nil {
			t.Fatal("今天不该被切换（P4 闸门应拒绝）")
		}
		msg := err.Error()
		for _, want := range []string{"P4 切换闸门拒绝", "日结束", "有效下限", "EVENT_ARCHIVE_MIN_AGE_DAYS=14"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("拒绝信息应含 %q，实际：%s", want, msg)
			}
		}
	})

	t.Run("min_age_边界内拒绝_边界外放行", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		// 10 天前：默认 min-age 14 天之内 → 拒绝，且贡献最大值的来源是 min-age
		day := p0Day(t, ctx, db, 10)
		for i := 1; i <= 3; i++ {
			p0Event(t, ctx, client, day.Add(time.Duration(i)*time.Minute), 4001, "agent",
				fmt.Sprintf(`{"mark":"t15-in-%d","conn":{"dst":"10.0.0.1:443"}}`, i))
		}
		runID := p0VerifiedRun(t, ctx, db, day, day)
		p4SeedConsumed(t, ctx, db, day) // 消费进度不缺，让拒绝只剩年龄项
		_, err := Swap(ctx, db, runID, day)
		if err == nil || !strings.Contains(err.Error(), "EVENT_ARCHIVE_MIN_AGE_DAYS=14") {
			t.Fatalf("边界内的日子应因 min-age 拒绝，实际：%v", err)
		}
		if err == nil || !strings.Contains(err.Error(), "贡献最大值的来源") {
			t.Fatalf("拒绝信息应列出依据来源，实际：%v", err)
		}
	})

	t.Run("min_age_边界外放行", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		day := p0Day(t, ctx, db, 20) // 默认 min-age 14 天之外
		var ids []uuid.UUID
		for i := 1; i <= 3; i++ {
			ids = append(ids, p0Event(t, ctx, client, day.Add(time.Duration(i)*time.Minute), 4001, "agent",
				fmt.Sprintf(`{"mark":"t15-out-%d","conn":{"dst":"10.0.0.1:443"}}`, i)))
		}
		runID := p0VerifiedRun(t, ctx, db, day, day)
		p4SeedConsumed(t, ctx, db, day)
		p, err := Swap(ctx, db, runID, day)
		if err != nil {
			t.Fatalf("边界外的日子应放行: %v", err)
		}
		if p.Dropped != 3 {
			t.Fatalf("应移出 3 行，实际 %d", p.Dropped)
		}
		for _, id := range ids {
			if p0HotExists(t, ctx, db, id) {
				t.Fatalf("事件 %s 应已移出热表", id)
			}
		}
	})

	t.Run("min_age_0_时_temporal_边界仍生效", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
		// 4003-only 口径：beacon/assetmap 项不适用，有效下限只剩 temporal（回退常量 ≥ 26h10m）
		day := p0Day(t, ctx, db, 1)
		for i := 1; i <= 2; i++ {
			p0Event(t, ctx, client, day.Add(time.Duration(i)*time.Minute), 4003, "sensor",
				fmt.Sprintf(`{"mark":"t15-dns-%d","query":{"name":"a%d.example.com"}}`, i, i))
		}
		runID := p4VerifiedRun(t, ctx, db, day, day, []int{4003}, []string{"sensor"})
		_, err := Swap(ctx, db, runID, day)
		if err == nil || !strings.Contains(err.Error(), "temporal") {
			t.Fatalf("min-age=0 时昨天仍应被 temporal 边界拒绝（日结束距今 < 24h+余量），实际：%v", err)
		}
		// 三天前的 4003：日结束 ≥ 48h，越过 temporal 边界 → 放行
		old := p0Day(t, ctx, db, 3)
		for i := 1; i <= 2; i++ {
			p0Event(t, ctx, client, old.Add(time.Duration(i)*time.Minute), 4003, "sensor",
				fmt.Sprintf(`{"mark":"t15-dns-old-%d","query":{"name":"b%d.example.com"}}`, i, i))
		}
		oldRun := p4VerifiedRun(t, ctx, db, old, old, []int{4003}, []string{"sensor"})
		if _, err := Swap(ctx, db, oldRun, old); err != nil {
			t.Fatalf("三天前的 4003 日应只受 temporal 边界约束并放行: %v", err)
		}
	})

	t.Run("年龄用日结束_不是日开始", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "2")
		// 4003-only 口径：beacon/assetmap 项不适用（它们各是 7 天，会盖住 2 天的运营下限），
		// 有效下限 = max(2 天, temporal 26h10m) = 48h，边界完全可控
		seed := func(daysAgo int) (uuid.UUID, time.Time) {
			t.Helper()
			day := p0Day(t, ctx, db, daysAgo)
			for i := 1; i <= 2; i++ {
				p0Event(t, ctx, client, day.Add(time.Duration(i)*time.Minute), 4003, "sensor",
					fmt.Sprintf(`{"mark":"t15-dayend-%d-%d","query":{"name":"d%d.example.com"}}`, daysAgo, i, i))
			}
			return p4VerifiedRun(t, ctx, db, day, day, []int{4003}, []string{"sensor"}), day
		}
		// 2 天前：日开始已 ≥ 48h（按日开始判会放行），日结束 < 48h（按日结束判必须拒绝）
		runID, day := seed(2)
		_, err := Swap(ctx, db, runID, day)
		if err == nil {
			t.Fatal("日开始够老但日结束不够老的日子必须拒绝（判定值是日结束）")
		}
		if want := day.AddDate(0, 0, 1).Format(time.RFC3339); !strings.Contains(err.Error(), want) {
			t.Fatalf("拒绝信息应带日结束时间 %s，实际：%v", want, err)
		}
		// 对照：3 天前的日结束 ≥ 48h，同样的环境放行
		oldRun, old := seed(3)
		if _, err := Swap(ctx, db, oldRun, old); err != nil {
			t.Fatalf("日结束 ≥ 下限的日子应放行: %v", err)
		}
	})
}

// ─── T15b：消费进度证明 ───────────────────────────────────────────────────────

func TestP4T15bConsumerProgress(t *testing.T) {
	seedDay := func(t *testing.T, ctx context.Context, client *ent.Client, db *sql.DB, daysAgo int) (uuid.UUID, time.Time) {
		t.Helper()
		day := p0Day(t, ctx, db, daysAgo)
		for i := 1; i <= 3; i++ {
			p0Event(t, ctx, client, day.Add(time.Duration(i)*time.Minute), 4001, "agent",
				fmt.Sprintf(`{"mark":"t15b-%d-%d","conn":{"dst":"10.0.0.1:443"}}`, daysAgo, i))
		}
		return p0VerifiedRun(t, ctx, db, day, day), day
	}

	t.Run("unknown_拒绝_错误列出消费者", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
		runID, day := seedDay(t, ctx, client, db, 20)
		// 什么都不播种：settings 无 beacon 扫描标记、无 assetmap 游标 → 双 unknown
		_, err := Swap(ctx, db, runID, day)
		if err == nil {
			t.Fatal("消费者 unknown 时必须拒绝")
		}
		msg := err.Error()
		for _, want := range []string{"beacon", "assetmap", "unknown"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("拒绝信息应列出消费者 %q 与 unknown 原因，实际：%s", want, msg)
			}
		}
	})

	t.Run("beacon_进度晚于待切日_拒绝", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
		runID, day := seedDay(t, ctx, client, db, 20)
		p4SeedAssetmapCursor(t, ctx, db, time.Now())         // assetmap 追平
		p4SeedBeaconScan(t, ctx, db, day.Add(-24*time.Hour)) // 扫描完成上界还停在待切日之前
		_, err := Swap(ctx, db, runID, day)
		if err == nil || !strings.Contains(err.Error(), "beacon") {
			t.Fatalf("beacon 扫描完成上界早于日结束应拒绝并带 beacon 依据，实际：%v", err)
		}
		if err == nil || strings.Contains(err.Error(), "assetmap") {
			t.Fatalf("assetmap 已追平，不应出现在拒绝原因里：%v", err)
		}
	})

	t.Run("assetmap_游标未越过待切日_拒绝", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
		runID, day := seedDay(t, ctx, client, db, 20)
		p4SeedBeaconScan(t, ctx, db, time.Now())
		p4SeedAssetmapCursor(t, ctx, db, day.Add(-5*24*time.Hour)) // 游标还停在待切日之前
		_, err := Swap(ctx, db, runID, day)
		if err == nil || !strings.Contains(err.Error(), "assetmap") {
			t.Fatalf("assetmap 游标早于日结束应拒绝，实际：%v", err)
		}
		if err == nil || strings.Contains(err.Error(), "beacon") {
			t.Fatalf("beacon 已满足，不应出现在拒绝原因里：%v", err)
		}
	})

	t.Run("进度越过待切日_放行", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
		runID, day := seedDay(t, ctx, client, db, 20)
		p4SeedConsumed(t, ctx, db, day)
		p, err := Swap(ctx, db, runID, day)
		if err != nil {
			t.Fatalf("消费者追平后应放行: %v", err)
		}
		if p.Dropped != 3 || p.Guard == nil || !p.Guard.Allow {
			t.Fatalf("应移出 3 行且报告放行：%+v", p)
		}
	})

	t.Run("Plan_不拒绝_只展示", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
		runID, day := seedDay(t, ctx, client, db, 20)
		p, err := Plan(ctx, db, runID, day) // 不播种：闸门必然不放行
		if err != nil {
			t.Fatalf("Plan 不做拒绝，只读展示：%v", err)
		}
		if p.Guard == nil || p.Guard.Allow {
			t.Fatalf("Plan 应携带闸门评估且如实报告不可切：%+v", p.Guard)
		}
		for _, name := range []string{"beacon", "assetmap"} {
			found := false
			for _, c := range p.Guard.Consumers {
				if c.Name == name && c.Relevant && !c.OK {
					found = true
				}
			}
			if !found {
				t.Fatalf("Plan 的闸门报告应列出 %s 未追平：%+v", name, p.Guard.Consumers)
			}
		}
		// 口径不相交的消费者不参与判定：ueba(1007)/automation(3002) 对 4001 run 应标记为不相关
		for _, c := range p.Guard.Consumers {
			if (c.Name == "ueba" || c.Name == "automation") && c.Relevant {
				t.Fatalf("ueba/automation 读的类别不在 4001 口径内，不应相关：%+v", c)
			}
		}
	})
}

// ─── T16：beacon / assetmap 的 swap 对照全热对照 ────────────────────────────────

// p4BeaconBranch 跑一条完整分支：老基线 → 引擎 #1 学进 F1 → （可选）切走 20 天前的
// 一天 → F2 出现 → 引擎 #2 重启回放。返回基线 flow 集合与告警 flow 集合。
// 「学习期内的一天」按闸门口径解释：待切日必须落在所有回读窗口之外（这正是闸门保证的事），
// 因此对照要证明的是——在闸门放行的前提下，swap 前后的 beacon 结果集合与全热对照一致。
func p4BeaconBranch(t *testing.T, swap bool) (baselines, alerts []string) {
	t.Helper()
	ctx, client, db := p0Open(t)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	old := p0Day(t, ctx, db, 20)
	asset := client.Asset.Create().SetHostname("p4-beacon").SetOs("linux").
		SetFirstSeen(time.Now().Add(-40 * 24 * time.Hour)).SaveX(ctx)
	// beacon 闸门：R3 起读引擎自己写的扫描完成标记（archive.beacon.scan），下面引擎 #1
	// 跑完一轮后该标记的 through≈now−30s，自然越过 20 天前的日结束；不再播种 first_seen。
	p4SeedAssetmapCursor(t, ctx, db, time.Now()) // 4001 口径下 assetmap 同样相关

	// 待切日内容：5 条普通出站（非周期，只作为被切走的行）
	for i := 1; i <= 5; i++ {
		p0Event(t, ctx, client, old.Add(time.Duration(i)*time.Minute), 4001, "agent",
			fmt.Sprintf(`{"connection_info":{"direction":"outbound"},"dst_endpoint":{"ip":"198.51.100.7","port":"80"},"mark":"t16-old-%d"}`, i))
	}
	// F1：最近 13 小时每 30 分钟一次的规律外连（回放窗口 12h 内仍留 ≥ 24 次 → Periodic 成立）。
	// beacon 的查询只读 asset_id IS NOT NULL 的行，事件必须带资产。
	flowEvent := func(name, ip, port string, ts time.Time, mark string) {
		t.Helper()
		client.Event.Create().SetTs(ts).SetClassUID(4001).SetSource("agent").SetAssetID(asset.ID).
			SetRaw(json.RawMessage(fmt.Sprintf(
				`{"connection_info":{"direction":"outbound"},"process":{"name":%q},"dst_endpoint":{"ip":%q,"port":%q},"mark":%q}`,
				name, ip, port, mark))).SaveX(ctx)
	}
	for i := 0; i < 25; i++ {
		flowEvent("curl", "93.184.216.34", "443", time.Now().Add(-13*time.Hour+time.Duration(i)*30*time.Minute),
			fmt.Sprintf("t16-f1-%02d", i))
	}
	// stop 等引擎 goroutine 真正退出：既保证后续 Swap/播种与引擎不并发，
	// 也避免测试收尾关连接后引擎还在跑、刷一屏 database is closed。
	runEngine := func() (stop func()) {
		e := &beacon.Engine{DB: client, SQL: db,
			LearningPeriod: 7 * 24 * time.Hour, Window: 12 * time.Hour, Interval: time.Hour}
		ectx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); e.Run(ectx) }()
		return func() { cancel(); <-done }
	}
	stop1 := runEngine()
	p4PollCountAtLeast(t, ctx, db, `SELECT count(*) FROM beacon_baselines WHERE flow='|curl|443'`, 1)
	// 扫描完成标记在基线之后、整轮收尾写入：见到它即证明引擎 #1 完整跑完了一轮
	//（F1 已学进、副作用已提交）。这是 swap 分支过闸门用的真实标记，不是播种值。
	p4PollCountAtLeast(t, ctx, db, `SELECT count(*) FROM settings WHERE id='archive.beacon.scan'`, 1)
	stop1()

	if swap {
		runID := p0VerifiedRun(t, ctx, db, old, old)
		p, err := Swap(ctx, db, runID, old)
		if err != nil {
			t.Fatalf("T16 swap 分支应通过闸门: %v", err)
		}
		if p.Dropped != 5 {
			t.Fatalf("应移出 5 行，实际 %d", p.Dropped)
		}
	}
	// F2：切换之后才出现的规律外连（引擎 #2 重启回放应当场报出来）
	for i := 0; i < 12; i++ {
		flowEvent("wget", "198.51.100.99", "8443", time.Now().Add(-2*time.Hour+time.Duration(i)*6*time.Minute),
			fmt.Sprintf("t16-f2-%02d", i))
	}
	stop2 := runEngine()
	p4PollCountAtLeast(t, ctx, db, `SELECT count(*) FROM alerts a JOIN events e ON e.id=a.event_id
 WHERE a.rule_id='xdr:beacon' AND e.raw->>'mark' LIKE 't16-f2-%'`, 1)
	stop2()

	baselines = p4ColumnSet(t, ctx, db, `SELECT flow FROM beacon_baselines`)
	alerts = p4ColumnSet(t, ctx, db, `SELECT coalesce(e.raw->'container'->>'name','') || '|' ||
 coalesce(e.raw->'process'->>'name','') || '|' || coalesce(e.raw->'dst_endpoint'->>'port','')
 FROM alerts a JOIN events e ON e.id = a.event_id WHERE a.rule_id = 'xdr:beacon'`)
	return baselines, alerts
}

func TestP4T16BeaconSwapMatchesControl(t *testing.T) {
	var ctrlBase, ctrlAlerts, swapBase, swapAlerts []string
	t.Run("全热对照", func(t *testing.T) { ctrlBase, ctrlAlerts = p4BeaconBranch(t, false) })
	t.Run("swap后重启", func(t *testing.T) { swapBase, swapAlerts = p4BeaconBranch(t, true) })
	// 集合一致（不只数量）：少一条基线、多一条告警、flow 换了键都直接暴露
	if !slices.Equal(ctrlBase, swapBase) {
		t.Fatalf("beacon 基线集合不一致：\n全热 %v\nswap %v", ctrlBase, swapBase)
	}
	if !slices.Equal(ctrlAlerts, swapAlerts) {
		t.Fatalf("beacon 告警 flow 集合不一致：\n全热 %v\nswap %v", ctrlAlerts, swapAlerts)
	}
	// 非空护栏：对照分支必须真的学到了 F1、报出了 F2，否则上面的相等是空集相等
	if !slices.Contains(ctrlBase, "|curl|443") || !slices.Contains(ctrlBase, "|wget|8443") {
		t.Fatalf("对照分支应包含两条被学进的规律外连：%v", ctrlBase)
	}
	if !slices.Contains(ctrlAlerts, "|wget|8443") {
		t.Fatalf("对照分支的重启应报出 F2：%v", ctrlAlerts)
	}
}

// p4AssetmapBranch 跑一条 assetmap 分支：引擎 #1 物化旧+近期依赖边 →（可选）切走
// 20 天前的一天 → 新增连接 → 引擎 #2 从持久游标续扫。返回依赖边集合（业务键+聚合计数）。
func p4AssetmapBranch(t *testing.T, swap bool) []string {
	t.Helper()
	ctx, client, db := p0Open(t)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	old := p0Day(t, ctx, db, 20)
	group := client.Group.Create().SetName("p4-amap").SaveX(ctx)
	web := client.Asset.Create().SetHostname("p4-web").SetIPAddrs([]string{"10.0.0.1"}).SetGroupID(group.ID).SaveX(ctx)
	// 目的端资产只为让 10.0.0.2 是纳管地址（依赖判定区分同宿主机连接），不直接断言它
	dbHost := client.Asset.Create().SetHostname("p4-db").SetIPAddrs([]string{"10.0.0.2"}).SetGroupID(group.ID).SaveX(ctx)
	_ = dbHost
	guid := uuid.Must(uuid.NewV7())
	conn := func(ts time.Time, sport, dport string, mark string) {
		t.Helper()
		client.Event.Create().SetTs(ts).SetClassUID(4001).SetSource("agent").SetAssetID(web.ID).
			SetProcessGUID(guid).SetConnTuple("tcp:10.0.0.1:" + sport + ">10.0.0.2:" + dport).
			SetRaw(json.RawMessage(fmt.Sprintf(`{"src_endpoint":{"ip":"10.0.0.1","port":%s},"dst_endpoint":{"ip":"10.0.0.2","port":%s},"mark":%q}`, sport, dport, mark))).
			SaveX(ctx)
	}
	// 进程名来自同一 GUID 的 1007 事件（不在 4001 归档口径内，切不走）
	client.Event.Create().SetTs(old.Add(time.Minute)).SetClassUID(1007).SetSource("agent").
		SetAssetID(web.ID).SetProcessGUID(guid).SetRaw(json.RawMessage(`{"process":{"name":"nginx"}}`)).SaveX(ctx)
	for i := range 3 {
		conn(old.Add(time.Duration(i)*time.Minute), "40000", "5432", fmt.Sprintf("t16-amap-old-%d", i))
	}
	// 近期事件用「今天零点 + 固定分钟偏移」而不是 time.Now()：两个分支在不同时刻跑，
	// 微秒级的时间差会进 first_seen/last_seen，集合对照就永远对不上。assetmap 的批次
	// 读取没有上界（只按游标前进），零点后几分钟的定值时间对它是普通的历史事件。
	recent := p0Today()
	for i := range 3 {
		conn(recent.Add(time.Duration(i+1)*time.Minute), fmt.Sprintf("4%04d", 10000+i), "5432", fmt.Sprintf("t16-amap-new-%d", i))
	}
	// 游标播种到待切日之前：assetmap 无游标时只回填 7 天，够不到 20 天前；
	// 这一行代表「图谱引擎从 21 天前就在跑」，引擎 #1 因此真的会消费待切日的事件
	//（否则 swap 掉的是它从没读过的行，对照就测不到「已物化的边不因 swap 消失」）。
	p4SeedAssetmapCursor(t, ctx, db, old.AddDate(0, 0, -1))
	// 4001 口径下 beacon 闸门同样相关（本分支不跑 beacon，用引擎同款写入器播种标记）
	p4SeedBeaconScan(t, ctx, db, time.Now())
	// stop 等引擎 goroutine 真正退出（同 beacon 分支：不与 Swap/播种并发，也不在测试收尾后刷错误日志）
	runEngine := func() (stop func()) {
		e := &assetmap.Engine{DB: client, SQL: db, Interval: time.Hour}
		ectx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); e.Run(ectx) }()
		return func() { cancel(); <-done }
	}
	stop1 := runEngine()
	p4PollCountAtLeast(t, ctx, db, `SELECT count FROM asset_links WHERE dst_port=5432`, 6)
	stop1()

	if swap {
		runID := p0VerifiedRun(t, ctx, db, old, old)
		p, err := Swap(ctx, db, runID, old)
		if err != nil {
			t.Fatalf("T16 assetmap swap 分支应通过闸门（引擎自己的游标就是进度证明）: %v", err)
		}
		if p.Dropped != 3 {
			t.Fatalf("应移出 3 行 4001 事件，实际 %d", p.Dropped)
		}
	}
	// 引擎 #1 之后的新连接：重启续扫物化出新边；已有边不重复计数
	for i := range 2 {
		conn(recent.Add(time.Duration(4+i)*time.Minute), fmt.Sprintf("5%04d", 20000+i), "6379", fmt.Sprintf("t16-amap-post-%d", i))
	}
	stop2 := runEngine()
	p4PollCountAtLeast(t, ctx, db, `SELECT count FROM asset_links WHERE dst_port=6379`, 2)
	stop2()
	return p4ColumnSet(t, ctx, db, `SELECT src_ip || '>' || dst_ip || ':' || dst_port || '/' || proto ||
 '@proc=' || process || '#count=' || count || '[' || first_seen || ',' || last_seen || ']'
 FROM asset_links ORDER BY 1`)
}

func TestP4T16AssetmapSwapMatchesControl(t *testing.T) {
	var ctrl, swapped []string
	t.Run("全热对照", func(t *testing.T) { ctrl = p4AssetmapBranch(t, false) })
	t.Run("swap后续扫", func(t *testing.T) { swapped = p4AssetmapBranch(t, true) })
	if !slices.Equal(ctrl, swapped) {
		t.Fatalf("assetmap 依赖边集合不一致（业务键+计数+时间并集）：\n全热 %v\nswap %v", ctrl, swapped)
	}
	if len(ctrl) != 2 { // 5432 边(count=6) 与 6379 边(count=2)
		t.Fatalf("对照分支应物化出 2 条依赖边：%v", ctrl)
	}
}

// ─── T17：temporal 候选 ────────────────────────────────────────────────────────

func TestP4T17TemporalCandidates(t *testing.T) {
	ctx, client, db := p0Open(t)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	old := p0Day(t, ctx, db, 20)
	asset := client.Asset.Create().SetHostname("p4-t17").SetOs("linux").SaveX(ctx)
	groupID := uuid.Must(uuid.NewV7())
	// 两条口径内事件：A 会被切走，B 钉住留热
	idA := p0Event(t, ctx, client, old.Add(time.Minute), 4001, "agent", `{"mark":"t17-a","conn":{"dst":"10.0.0.1:443"}}`)
	idB := p0Event(t, ctx, client, old.Add(2*time.Minute), 4001, "agent", `{"mark":"t17-b","conn":{"dst":"10.0.0.2:443"}}`)
	p0Pin(t, ctx, client, old.Add(2*time.Minute), idB)
	// 一条窗口内的近期事件（today 分区，swap 不该碰它的候选）
	idNow := p0Event(t, ctx, client, time.Now().Add(-30*time.Minute), 4001, "agent", `{"mark":"t17-now","conn":{"dst":"10.0.0.3:443"}}`)

	// 候选需要规则快照行（revision 外键）与资产（asset 外键）
	for _, rev := range []string{"t17-r1", "t17-r2-old"} {
		if _, err := db.ExecContext(ctx, `INSERT INTO temporal_rule_snapshots(revision, document)
 VALUES($1, '{}'::jsonb) ON CONFLICT DO NOTHING`, rev); err != nil {
			t.Fatalf("建规则快照 %s: %v", rev, err)
		}
	}
	cand := func(rev string, event uuid.UUID, ts time.Time) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO temporal_candidates
 (revision, event_id, asset_id, group_id, ts, rules) VALUES ($1,$2,$3,$4,$5,'[]'::jsonb)`,
			rev, event, asset.ID, groupID, ts); err != nil {
			t.Fatalf("播种候选(%s,%s): %v", rev, event, err)
		}
	}
	cand("t17-r1", idNow, time.Now().Add(-30*time.Minute)) // 窗口内、别的分区：不许动
	cand("t17-r1", idA, old.Add(time.Minute))              // 将被切走：当前版本候选
	cand("t17-r2-old", idA, old.Add(time.Minute))          // 将被切走：旧规则版本候选
	cand("t17-r1", idB, old.Add(2*time.Minute))            // 留热事件的候选：不许动

	runID := p0VerifiedRun(t, ctx, db, old, old)
	p4SeedConsumed(t, ctx, db, old)
	p, err := Swap(ctx, db, runID, old)
	if err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if p.Dropped != 1 {
		t.Fatalf("应只移出未钉住的 A，实际 %d", p.Dropped)
	}
	var n int64
	// 窗口内候选原样可读（另一个分区，swap 根本不该触碰）
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM temporal_candidates WHERE event_id = $1`, idNow).Scan(&n); err != nil || n != 1 {
		t.Fatalf("窗口内候选必须保留: n=%d err=%v", n, err)
	}
	// 留热事件（被 pin）的候选保留
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM temporal_candidates WHERE event_id = $1`, idB).Scan(&n); err != nil || n != 1 {
		t.Fatalf("保留事件的候选必须保留: n=%d err=%v", n, err)
	}
	// 被切走事件的候选：当前版本与旧规则版本都按决策表清理
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM temporal_candidates WHERE event_id = $1`, idA).Scan(&n); err != nil || n != 0 {
		t.Fatalf("被移出事件的候选（含旧规则版本）应清理: n=%d err=%v", n, err)
	}
	// 后续求值不受影响：observeScope 的同形查询（revision+实体+窗口）仍能读到窗口内候选
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM temporal_candidates
 WHERE revision=$1 AND group_id=$2 AND asset_id=$3 AND ts >= $4 AND ts <= $5`,
		"t17-r1", groupID, asset.ID,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour)).Scan(&n); err != nil || n != 1 {
		t.Fatalf("在线求值的窗口回查应仍读到窗口内候选: n=%d err=%v", n, err)
	}
}

// ─── T18：gaps 与 identity_* 按决策表 ─────────────────────────────────────────

func TestP4T18GapsAndIdentityPerDecisionTable(t *testing.T) {
	ctx, client, db := p0Open(t)
	t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
	old := p0Day(t, ctx, db, 20)
	asset := client.Asset.Create().SetHostname("p4-t18").SetOs("linux").SaveX(ctx)
	groupID := uuid.Must(uuid.NewV7())
	idA := p0Event(t, ctx, client, old.Add(time.Minute), 4001, "agent", `{"mark":"t18-a","conn":{"dst":"10.0.0.1:443"}}`)
	idB := p0Event(t, ctx, client, old.Add(2*time.Minute), 4001, "agent", `{"mark":"t18-b","conn":{"dst":"10.0.0.2:443"}}`)
	// C 是口径外的 1007 事件：swap 不动它，退役时它未被钉住而随分区消失——
	// 用它证明 gaps 的清理责任确实在 janitor 既有策略（retire）那一边。
	idC := p0Event(t, ctx, client, old.Add(3*time.Minute), 1007, "agent", `{"process":{"name":"c"}}`)
	pin := client.Alert.Create().SetTs(old.Add(2 * time.Minute)).SetRuleID("p4-t18-pin").SetSeverity(3).SetEventID(idB).SaveX(ctx)

	if _, err := db.ExecContext(ctx, `INSERT INTO temporal_rule_snapshots(revision, document)
 VALUES('t18-r1', '{}'::jsonb) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatalf("建规则快照: %v", err)
	}
	// late gap：A（将被切走）、B（钉住留热）与 C（口径外，退役时消失）各一条——决策表：swap 不删 gaps
	gap := func(event uuid.UUID, reason string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO temporal_evaluation_gaps
 (revision, event_id, asset_id, group_id, reason, candidate_count_lower_bound, window_from, window_to)
 VALUES('t18-r1', $1, $2, $3, $4, 0, $5, $6) ON CONFLICT DO NOTHING`,
			event, asset.ID, groupID, reason, old.Add(-time.Hour), old.Add(25*time.Hour)); err != nil {
			t.Fatalf("播种 gap(%s): %v", reason, err)
		}
	}
	gap(idA, "late")
	gap(idB, "candidate_limit")
	gap(idC, "late")
	// temporal_matches：已消费命中记录（决策表：清；默认口径 4001 不产生这些行，合成行只为钉住行为）
	if _, err := db.ExecContext(ctx, `INSERT INTO temporal_matches(rule_id, event_id) VALUES('p4-t18-m', $1)`, idA); err != nil {
		t.Fatalf("播种 temporal_matches: %v", err)
	}
	// temporal_detections：A 的无告警检测（决策表：清，与 retire 同口径）；B 的已出告警检测
	//（锚点被 PinnedIDs 钉住，事件留热，检测行不该被删）
	det := func(anchor uuid.UUID, alertID any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO temporal_detections
 (revision, rule_id, anchor_id, group_id, entity, evidence, alert_id)
 VALUES('t18-r1', 'p4-t18-d', $1, $2, 'a', '[]'::jsonb, $3)`, anchor, groupID, alertID); err != nil {
			t.Fatalf("播种 detection(%s): %v", anchor, err)
		}
	}
	det(idA, nil)
	det(idB, pin.ID)
	// identity_*：默认口径（4001/4003）不产生这些行——合成行只为钉住「若产生则随事件清理」的现行为
	for _, table := range []string{"identity_observations", "identity_local_snapshots"} {
		state := "observed"
		cols, vals := "event_id, asset_id, state", fmt.Sprintf("$1, $2, '%s'", state)
		if table == "identity_local_snapshots" {
			cols, vals = "event_id, asset_id, state, source", fmt.Sprintf("$1, $2, '%s', 'etc-passwd'", state)
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s)`, table, cols, vals), idA, asset.ID); err != nil {
			t.Fatalf("播种 %s: %v", table, err)
		}
	}

	runID := p0VerifiedRun(t, ctx, db, old, old)
	p4SeedConsumed(t, ctx, db, old)
	p, err := Swap(ctx, db, runID, old)
	if err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if p.Dropped != 1 {
		t.Fatalf("应只移出未钉住的 A，实际 %d", p.Dropped)
	}
	count := func(query string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
			t.Fatalf("统计 %q: %v", query, err)
		}
		return n
	}
	// 决策表逐表断言
	if n := count(`SELECT count(*) FROM temporal_evaluation_gaps WHERE event_id = $1`, idA); n != 1 {
		t.Fatalf("temporal_evaluation_gaps（被切走事件的 late gap）按决策表必须保留: %d", n)
	}
	if n := count(`SELECT count(*) FROM temporal_evaluation_gaps WHERE event_id = $1`, idB); n != 1 {
		t.Fatalf("temporal_evaluation_gaps（留热事件）必须保留: %d", n)
	}
	if n := count(`SELECT count(*) FROM temporal_matches`); n != 0 {
		t.Fatalf("temporal_matches（被切走事件）按决策表应清理: %d", n)
	}
	if n := count(`SELECT count(*) FROM temporal_detections WHERE anchor_id = $1`, idA); n != 0 {
		t.Fatalf("无告警的 temporal_detections（被切走锚点）按决策表应清理: %d", n)
	}
	if n := count(`SELECT count(*) FROM temporal_detections WHERE anchor_id = $1`, idB); n != 1 {
		t.Fatalf("已出告警的 temporal_detections（锚点被钉住留热）必须保留: %d", n)
	}
	for _, table := range []string{"identity_observations", "identity_local_snapshots"} {
		if n := count(fmt.Sprintf(`SELECT count(*) FROM %s WHERE event_id = $1`, table), idA); n != 0 {
			t.Fatalf("%s（被切走事件）按决策表应清理: %d", table, n)
		}
	}
	// 清理责任的真实链路（R6 后的契约）：该日退役（retire 不跳过任何表）时，
	// 还在分区里且未被钉住的事件（C）的 gap 随退役差集清理；被钉住的 B 跟着证据保留期走；
	// A 的 gap 因事件已先行被 swap 移出分区，retire 的「分区−暂存」差集与逐行删除触发器
	// 都看不到它——由 janitor 按 gap 自身 created_at 的诊断保留期清理
	//（TEMPORAL_GAP_RETENTION_DAYS，见 r56_coverage_gap_integration_test.go 与
	// guard.go 决策表 temporal_evaluation_gaps 行）。
	//
	// Retire 会把该月钉住的行并进月归档分区（events_aYYYYMM），它跨整月、会挡住
	// 后续在共享测试库里重建该月的日分区：用例结束把它拆掉，别污染后面的用例与重跑。
	month := time.Date(old.Year(), old.Month(), 1, 0, 0, 0, 0, time.UTC)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `ALTER TABLE events DETACH PARTITION `+eventpart.ArchiveName(month))
		_, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+eventpart.ArchiveName(month))
	})
	if _, _, err := eventpart.Retire(ctx, db, old.AddDate(0, 0, 2)); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if n := count(`SELECT count(*) FROM events WHERE id = $1`, idC); n != 0 {
		t.Fatalf("口径外的未钉住事件 C 应随退役消失: %d", n)
	}
	if n := count(`SELECT count(*) FROM temporal_evaluation_gaps WHERE event_id = $1`, idC); n != 1 {
		t.Fatalf("retire 后未钉住事件 C 的 gap 必须保留（R6 补全：按诊断期独立清理）: %d", n)
	}
	if n := count(`SELECT count(*) FROM temporal_evaluation_gaps WHERE event_id = $1`, idB); n != 1 {
		t.Fatalf("被钉住的 B 的 gap 跟证据保留期走，retire 不清: %d", n)
	}
	if n := count(`SELECT count(*) FROM temporal_evaluation_gaps WHERE event_id = $1`, idA); n != 1 {
		t.Fatalf("已被 swap 移出分区的事件 A 的 gap 不在退役可见范围（决策表已知局限）: %d", n)
	}
}
