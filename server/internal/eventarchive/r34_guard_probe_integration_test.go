//go:build integration

// R3/R4 集成测试（COLD_ARCHIVE_EVOLUTION.SCRATCH.md §P4「R3 最小修复」与 §P2「R4 最小修复」；
// 5.2 节 T15b 的真实消费者部分、T09b 的完成标记部分。V08 实现侧 / V04 读取成本侧）。
//
// R3（消费完成证明）：
//   - beacon 完成标记由真实引擎写入（不播种）：引擎跑完一轮 → settings 出现
//     archive.beacon.scan，Guard 的 beacon 项 Known；Swap 经真实标记放行；
//   - 空区间/无周期性连接也推进标记（R3 的核心反例：干净系统不再永久 unknown）；
//   - 批次副作用失败不推进标记（告警写入被触发器拒绝），游标回滚、批次不被跳过：
//     修复后重试补完告警，标记才发布；
//   - 配置指纹（rev）变化 → 旧标记失效 → 按 unknown 拒绝。
//   - T16 既有对照（beacon 基线/检测集合一致）在 p4_guards 里继续跑，已迁移为走真实标记。
//
// R4（定位成本）：
//   - 标记 true：未命中直接确定存在性（false），不再反连接全部块——用「手工删 locator 行后
//     仍答确定不存在」证明走的是标记而非反连接（这正是已接受的手工操作风险）；
//   - 标记缺失/false：保持 ErrLocatorIncomplete；
//   - BackfillLocator 发现缺口先撤标记、收尾核验通过才发布 true；
//   - P2 的 T09 既有语义（不依赖热行、幂等、中断重跑）在 p2_locator 里继续跑。
//
// 专用测试库 openxdr_p0，与其它集成测试一样串行（-p 1）。复用 p0_*/p1_*/p4_* 的夹具 helper。
package eventarchive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/beacon"
)

// r34BeaconProgress 从 ConsumedThrough 的汇总里取 beacon 项。
func r34BeaconProgress(t *testing.T, ctx context.Context, db *sql.DB) ConsumerProgress {
	t.Helper()
	progress, err := ConsumedThrough(ctx, db)
	if err != nil {
		t.Fatalf("ConsumedThrough: %v", err)
	}
	for _, p := range progress {
		if p.Name == "beacon" {
			return p
		}
	}
	t.Fatal("ConsumedThrough 应包含 beacon 项")
	return ConsumerProgress{}
}

// ─── R3：beacon 扫描完成标记 ───────────────────────────────────────────────────

func TestR34BeaconScanMarker(t *testing.T) {
	t.Run("真实引擎空转一轮也写标记_空区间推进", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
		started := time.Now()
		// R3 的核心反例：库里一条 4001/agent 事件都没有（没有周期性外联的正常系统）。
		// 旧实现读 min(first_seen) 永远 NULL → beacon 永久 unknown；现在引擎空转一轮
		// 也必须发布扫描完成标记——扫描完成 ≠ 有数据。
		e := &beacon.Engine{DB: client, SQL: db,
			LearningPeriod: beaconLearningDefault, Window: beaconWindowDefault, Interval: time.Hour}
		ectx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); e.Run(ectx) }()
		p4PollCountAtLeast(t, ctx, db,
			`SELECT count(*) FROM settings WHERE id='archive.beacon.scan'`, 1)
		cancel()
		<-done

		var raw []byte
		if err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE id=$1`, BeaconScanKey).Scan(&raw); err != nil {
			t.Fatalf("读扫描完成标记: %v", err)
		}
		var m struct {
			Through time.Time `json:"through"`
			Rev     string    `json:"rev"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("标记载荷: %v", err)
		}
		if want := BeaconScanRev(beaconLearningDefault, beaconWindowDefault); m.Rev != want {
			t.Fatalf("rev 应为默认配置指纹 %q，实际 %q", want, m.Rev)
		}
		// through 是本轮固定上界（发起时刻回退 lateGrace），不是 now：断言它落在
		// 发起时刻前一分钟到当下之间，证明上界回退存在且没有越过当下
		if m.Through.Before(started.Add(-time.Minute)) || m.Through.After(time.Now()) {
			t.Fatalf("through 应在发起时刻附近（回退 30s），实际 %s", m.Through)
		}
		p := r34BeaconProgress(t, ctx, db)
		if !p.Known {
			t.Fatalf("引擎跑完一轮后 beacon 项应 Known：%+v", p)
		}
	})

	t.Run("真实引擎消费后_Swap经真实标记放行", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
		day := p0Day(t, ctx, db, 20)
		asset := client.Asset.Create().SetHostname("r34-real").SetOs("linux").
			SetFirstSeen(time.Now().Add(-40 * 24 * time.Hour)).SaveX(ctx)
		// 待切日的普通出站（非周期，学不进基线）：引擎照样要消费它们，标记照样推进
		for i := 1; i <= 3; i++ {
			client.Event.Create().SetTs(day.Add(time.Duration(i) * time.Minute)).SetClassUID(4001).
				SetSource("agent").SetAssetID(asset.ID).SetRaw(json.RawMessage(
				fmt.Sprintf(`{"connection_info":{"direction":"outbound"},"dst_endpoint":{"ip":"198.51.100.7","port":"80"},"mark":"r34-old-%d"}`, i))).SaveX(ctx)
		}
		p4SeedAssetmapCursor(t, ctx, db, time.Now())
		e := &beacon.Engine{DB: client, SQL: db,
			LearningPeriod: beaconLearningDefault, Window: beaconWindowDefault, Interval: time.Hour}
		ectx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); e.Run(ectx) }()
		p4PollCountAtLeast(t, ctx, db,
			`SELECT count(*) FROM settings WHERE id='archive.beacon.scan'`, 1)
		cancel()
		<-done

		runID := p4VerifiedRun(t, ctx, db, day, day, []int{4001}, []string{"agent"})
		p, err := Swap(ctx, db, runID, day)
		if err != nil {
			t.Fatalf("真实扫描完成标记应放行（不播种 first_seen）: %v", err)
		}
		if p.Dropped != 3 || p.Guard == nil || !p.Guard.Allow {
			t.Fatalf("应移出 3 行且报告放行：%+v", p)
		}
	})

	t.Run("批次副作用失败不推进_修复后重试补完", func(t *testing.T) {
		ctx, client, db := p0Open(t)
		t.Setenv("EVENT_ARCHIVE_MIN_AGE_DAYS", "0")
		now := time.Now()
		// 预置一条别的 flow 的基线：让 start 走「有基线」分支（游标=now−窗口、
		// 非学习期回放），新规律外联直接走告警路径
		other := client.Asset.Create().SetHostname("r34-other").SetOs("linux").
			SetFirstSeen(now.Add(-40 * 24 * time.Hour)).SaveX(ctx)
		if _, err := db.ExecContext(ctx, `INSERT INTO beacon_baselines (id, asset_id, flow, first_seen)
 VALUES ($1, $2, 'r34|existing|1', $3)`, uuid.Must(uuid.NewV7()), other.ID, now.Add(-72*time.Hour)); err != nil {
			t.Fatalf("预置基线: %v", err)
		}
		// 老资产的新规律外联：过去 2 小时每 6 分钟一次（12 次 ≥ MinHits，跨度 ≥ MinSpan）
		asset := client.Asset.Create().SetHostname("r34-fail").SetOs("linux").
			SetFirstSeen(now.Add(-40 * 24 * time.Hour)).SaveX(ctx)
		for i := 0; i < 12; i++ {
			client.Event.Create().SetTs(now.Add(-2*time.Hour + time.Duration(i)*6*time.Minute)).
				SetClassUID(4001).SetSource("agent").SetAssetID(asset.ID).
				SetRaw(json.RawMessage(`{"connection_info":{"direction":"outbound"},"process":{"name":"curl"},"dst_endpoint":{"ip":"93.184.216.34","port":"443"}}`)).
				SaveX(ctx)
		}
		// 注入批次副作用失败：alerts 的 BEFORE INSERT 触发器对 xdr:beacon 报错。
		// 基线插入先成功、告警插入失败——正是「先推进后处理」最容易漏掉的组合。
		if _, err := db.ExecContext(ctx, `CREATE OR REPLACE FUNCTION r34_block_alert() RETURNS trigger AS $f$
BEGIN IF NEW.rule_id='xdr:beacon' THEN RAISE EXCEPTION 'r34 注入：告警写入被拒绝'; END IF; RETURN NEW; END $f$ LANGUAGE plpgsql`); err != nil {
			t.Fatalf("建触发器函数: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS r34_block ON alerts`)
			_, _ = db.ExecContext(context.Background(), `DROP FUNCTION IF EXISTS r34_block_alert()`)
		})
		if _, err := db.ExecContext(ctx, `DROP TRIGGER IF EXISTS r34_block ON alerts`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER r34_block BEFORE INSERT ON alerts
FOR EACH ROW EXECUTE FUNCTION r34_block_alert()`); err != nil {
			t.Fatalf("建触发器: %v", err)
		}

		e := &beacon.Engine{DB: client, SQL: db,
			LearningPeriod: beaconLearningDefault, Window: beaconWindowDefault, Interval: 10 * time.Millisecond}
		ectx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); e.Run(ectx) }()
		defer func() { cancel(); <-done }()
		// 触发器还在：每一轮都在告警插入处失败。基线能落地（批次副作用的一部分），
		// 但标记必须始终缺失——失败的轮次不得发布完成证明
		p4PollCountAtLeast(t, ctx, db, `SELECT count(*) FROM beacon_baselines WHERE flow='|curl|443'`, 1)
		var n int64
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM settings WHERE id=$1`, BeaconScanKey).Scan(&n); err != nil || n != 0 {
			t.Fatalf("失败的轮次不得发布标记，实际 %d 行 err=%v", n, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM alerts`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("失败轮次不应有告警，实际 %d err=%v", n, err)
		}
		if p := r34BeaconProgress(t, ctx, db); p.Known {
			t.Fatalf("标记缺失时 Guard 的 beacon 项应 unknown：%+v", p)
		}

		// 撤掉注入：同一个引擎实例继续按自己的节拍重跑（游标没有推进过，本批事件被
		// 重读；基线撞唯一索引、但那是本实例自己写的）→ 告警补完、标记才发布——
		// 失败批次没有被跳过
		if _, err := db.ExecContext(ctx, `DROP TRIGGER r34_block ON alerts`); err != nil {
			t.Fatal(err)
		}
		p4PollCountAtLeast(t, ctx, db, `SELECT count(*) FROM alerts WHERE rule_id='xdr:beacon'`, 1)
		p4PollCountAtLeast(t, ctx, db, `SELECT count(*) FROM settings WHERE id=$1`, 1, BeaconScanKey)
		// 恰好一条：成功后 known 挡住重复，游标也推进过去了
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM alerts WHERE rule_id='xdr:beacon'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("失败批次的告警必须被补完且只有一条，实际 %d err=%v", n, err)
		}
		if p := r34BeaconProgress(t, ctx, db); !p.Known {
			t.Fatalf("整轮成功后应发布标记：%+v", p)
		}
	})

	t.Run("配置指纹变化_旧标记失效", func(t *testing.T) {
		ctx, _, db := p0Open(t)
		// 引擎按默认 7d/12h 跑过一轮的等价状态（本用例测 Guard 的指纹比对，不重复跑引擎）
		if err := RecordBeaconScan(ctx, db, time.Now(), time.Now(), beaconLearningDefault, beaconWindowDefault); err != nil {
			t.Fatal(err)
		}
		// 当前环境把窗口扩大到 24h：指纹不一致 → 旧证明失效 → 按 unknown 拒绝
		t.Setenv("BEACON_WINDOW_HOURS", "24")
		p := r34BeaconProgress(t, ctx, db)
		if p.Known {
			t.Fatalf("窗口扩大后旧标记应失效（unknown）：%+v", p)
		}
		if !strings.Contains(p.Note, "指纹") {
			t.Fatalf("unknown 说明应指出指纹不一致：%+v", p)
		}
		// 换回默认配置：同一标记重新有效（指纹一致）
		t.Setenv("BEACON_WINDOW_HOURS", "12")
		if p := r34BeaconProgress(t, ctx, db); !p.Known {
			t.Fatalf("指纹一致时标记应重新有效：%+v", p)
		}
	})
}

// ─── R4：locator 覆盖完成标记 ─────────────────────────────────────────────────

// r34SeedTwoChunks 造一天 6 条 4001 事件并按 3 条/块跑出 verified run（两块），
// 返回其中一个块 id。
func r34SeedTwoChunks(t *testing.T) (context.Context, *sql.DB, uuid.UUID) {
	t.Helper()
	ctx, client, db := p0Open(t)
	day := p0Day(t, ctx, db, 8)
	for i := 1; i <= 6; i++ {
		p0Event(t, ctx, client, day.Add(time.Duration(i*10)*time.Minute), 4001, "agent",
			`{"mark":"r34","conn":{"dst":"10.0.0.1:443"}}`)
	}
	p1VerifiedRun(t, ctx, db, day, day, 3, MaxPlainLen)
	var chunkID uuid.UUID
	if err := db.QueryRowContext(ctx, `SELECT chunk_id FROM event_archive_locator LIMIT 1`).Scan(&chunkID); err != nil {
		t.Fatalf("读块 id: %v", err)
	}
	return ctx, db, chunkID
}

func TestR34LocatorCompleteMarker(t *testing.T) {
	t.Run("标记true_未命中确定不存在_不再走反连接", func(t *testing.T) {
		ctx, db, chunkID := r34SeedTwoChunks(t)
		// 回填：收尾核验（覆盖性推导）通过 → 发布完成标记
		if _, err := BackfillLocator(ctx, db); err != nil {
			t.Fatalf("BackfillLocator: %v", err)
		}
		complete, err := LocatorComplete(ctx, db)
		if err != nil || !complete {
			t.Fatalf("回填成功后完成标记应为 true: %v %v", complete, err)
		}
		// 未命中：确定不存在（不再出现 ErrLocatorIncomplete）
		if ok, err := Exists(ctx, db, uuid.New()); err != nil || ok {
			t.Fatalf("标记 true 时未命中应为确定 (false,nil)，实际 (%v,%v)", ok, err)
		}
		// 完成标记的读取是 settings 主键探查；记录执行计划形态（小表上规划器可能
		// 选顺序扫，形态不做硬断言——未命中路径的正确性由下面的行为证明兜住）
		plan := explainAll(t, ctx, db,
			`EXPLAIN (FORMAT TEXT) SELECT value FROM settings WHERE id = 'archive.locator.complete'`)
		t.Logf("EXPLAIN 完成标记读取：%s", plan)

		// 行为证明未命中路径没有咨询反连接：手工删掉一块的全部 locator 行（不经过回填）。
		// 反连接此时会报 ErrLocatorIncomplete；标记路径仍答确定不存在——这正是 R4
		// 已接受的已知风险（规程：动过 locator 必须重跑 backfill-locator 校正标记）。
		if _, err := db.ExecContext(ctx, `DELETE FROM event_archive_locator WHERE chunk_id = $1`, chunkID); err != nil {
			t.Fatal(err)
		}
		if ok, err := Exists(ctx, db, uuid.New()); err != nil || ok {
			t.Fatalf("标记不随手工删除失效（已接受风险）：应仍答确定 (false,nil)，实际 (%v,%v)", ok, err)
		}
		// 诊断入口不受标记影响：反连接推导仍如实报缺口
		if missing, _, err := locatorIncompleteCount(ctx, db, 0); err != nil || missing != 1 {
			t.Fatalf("反连接诊断应仍报 1 块缺口: %d %v", missing, err)
		}
	})

	t.Run("标记缺失或false_保持ErrLocatorIncomplete", func(t *testing.T) {
		ctx, db, chunkID := r34SeedTwoChunks(t)
		// 从未回填：标记缺失。删一块的 locator 行 → 反连接报缺口 → ErrLocatorIncomplete
		if _, err := db.ExecContext(ctx, `DELETE FROM event_archive_locator WHERE chunk_id = $1`, chunkID); err != nil {
			t.Fatal(err)
		}
		if ok, err := Exists(ctx, db, uuid.New()); err == nil || ok || !errors.Is(err, ErrLocatorIncomplete) {
			t.Fatalf("标记缺失且有缺口时应报 ErrLocatorIncomplete，实际 (%v,%v)", ok, err)
		}
		// 显式 false 同样：撤掉标记后未命中回到反连接判定
		if _, err := db.ExecContext(ctx, `INSERT INTO settings (id, value, updated_at)
 VALUES ('archive.locator.complete', 'false'::jsonb, now())
 ON CONFLICT (id) DO UPDATE SET value = EXCLUDED.value`); err != nil {
			t.Fatal(err)
		}
		if ok, err := Exists(ctx, db, uuid.New()); err == nil || ok || !errors.Is(err, ErrLocatorIncomplete) {
			t.Fatalf("标记 false 时应保持 ErrLocatorIncomplete，实际 (%v,%v)", ok, err)
		}
		// 回填修复缺口并重新发布 true → 恢复确定语义
		if _, err := BackfillLocator(ctx, db); err != nil {
			t.Fatalf("BackfillLocator: %v", err)
		}
		if complete, err := LocatorComplete(ctx, db); err != nil || !complete {
			t.Fatalf("修复后标记应为 true: %v %v", complete, err)
		}
		if ok, err := Exists(ctx, db, uuid.New()); err != nil || ok {
			t.Fatalf("修复后未命中应为确定 (false,nil)，实际 (%v,%v)", ok, err)
		}
	})

	t.Run("回填发现缺口先撤标记_失败后未命中回保守", func(t *testing.T) {
		ctx, db, _ := r34SeedTwoChunks(t)
		// 第一轮回填成功：标记 true
		if _, err := BackfillLocator(ctx, db); err != nil {
			t.Fatalf("第一轮回填: %v", err)
		}
		// 再造缺口并改坏按 c.id 排序最后一块的 payload（BackfillLocator 按 c.id 顺序处理，
		// 第一块回填成功、到坏块失败）：回填开头必须先撤标记，失败后未命中回保守判定
		if _, err := db.ExecContext(ctx, `DELETE FROM event_archive_locator`); err != nil {
			t.Fatal(err)
		}
		var bad uuid.UUID
		if err := db.QueryRowContext(ctx, `SELECT id FROM event_archive_chunks ORDER BY id DESC LIMIT 1`).Scan(&bad); err != nil {
			t.Fatal(err)
		}
		var payload []byte
		if err := db.QueryRowContext(ctx, `SELECT payload FROM event_archive_chunks WHERE id=$1`, bad).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		payload[len(payload)-1] ^= 0xff
		if _, err := db.ExecContext(ctx, `UPDATE event_archive_chunks SET payload=$2 WHERE id=$1`, bad, payload); err != nil {
			t.Fatal(err)
		}
		if _, err := BackfillLocator(ctx, db); err == nil || !strings.Contains(err.Error(), bad.String()) {
			t.Fatalf("坏块必须让回填报错并带块 id，实际 %v", err)
		}
		if complete, err := LocatorComplete(ctx, db); err != nil || complete {
			t.Fatalf("回填失败后标记必须已撤为 false: %v %v", complete, err)
		}
		if ok, err := Exists(ctx, db, uuid.New()); err == nil || ok || !errors.Is(err, ErrLocatorIncomplete) {
			t.Fatalf("标记 false + 缺口时未命中应回 ErrLocatorIncomplete，实际 (%v,%v)", ok, err)
		}
		// 修复 payload 后重跑：补齐并重新发布 true
		payload[len(payload)-1] ^= 0xff
		if _, err := db.ExecContext(ctx, `UPDATE event_archive_chunks SET payload=$2 WHERE id=$1`, bad, payload); err != nil {
			t.Fatal(err)
		}
		if _, err := BackfillLocator(ctx, db); err != nil {
			t.Fatalf("修复后重跑: %v", err)
		}
		if complete, err := LocatorComplete(ctx, db); err != nil || !complete {
			t.Fatalf("修复后标记应为 true: %v %v", complete, err)
		}
		if ok, err := Exists(ctx, db, uuid.New()); err != nil || ok {
			t.Fatalf("补齐后未命中应为确定 (false,nil)，实际 (%v,%v)", ok, err)
		}
	})
}
