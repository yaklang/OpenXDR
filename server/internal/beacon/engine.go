package beacon

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

const batchLimit = 5000

// lateGrace 是每轮扫描固定上界的回退量：drain 只读到 now−lateGrace，晚到的事件留给
// 下一轮，免得游标越过还在写入的事件。扫描完成标记（archive.beacon.scan）的 through
// 用同一个上界——标记承诺的是「ts ≤ through 已消费」，不能越过还没读的尾巴。
const lateGrace = 30 * time.Second

// scanMarkKey / scanMark / scanMarkRev 与 eventarchive 包读侧（progress.go 的
// RecordBeaconScan/BeaconScanRev）是同一 settings 行的两端。这里不 import eventarchive
// （该包被接入路径反向使用，保持采集消费者零依赖）；两边按同口径维护，集成测试
// r34_guard_probe 断言「真实引擎写的标记能被 Guard 读到、指纹一致」，漂移会被抓住——
// 与 guard.go 里 temporalPruneSlack / assetmapBackfill 等常量的同步约定相同。
const scanMarkKey = "archive.beacon.scan"

// scanMark 是 settings[archive.beacon.scan] 的载荷：through=扫描完成上界，
// at=写入时刻，rev=影响读范围的配置指纹（学习期/窗口变化使旧证明失效）。
type scanMark struct {
	Through time.Time `json:"through"`
	At      time.Time `json:"at"`
	Rev     string    `json:"rev"`
}

// scanMarkRev 由影响读范围的配置算指纹。
func scanMarkRev(learning, window time.Duration) string {
	return fmt.Sprintf("learning=%s,window=%s", learning, window)
}

// recordScanDone 发布/更新扫描完成标记。只有整轮成功（全部事件读完、全部业务副作用
// 提交）才调用；写入失败只让冷归档切换闸门更保守（标记缺失=unknown 拒绝），不是数据错误。
func (e *Engine) recordScanDone(ctx context.Context, through, at time.Time) error {
	payload, err := json.Marshal(scanMark{
		Through: through.UTC(),
		At:      at.UTC(),
		Rev:     scanMarkRev(e.LearningPeriod, e.Window),
	})
	if err != nil {
		return err
	}
	_, err = e.SQL.ExecContext(ctx, `INSERT INTO settings (id, value, updated_at)
 VALUES ($1, $2::jsonb, now())
 ON CONFLICT (id) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		scanMarkKey, string(payload))
	return err
}

// Engine 增量读出站连接，内存里给每条外联留最近 Window 的连接时刻；单活运行（cluster.RunLeader）
type Engine struct {
	DB             *ent.Client
	SQL            *sql.DB
	Suppress       *suppress.Store
	LearningPeriod time.Duration
	Window         time.Duration
	Interval       time.Duration

	cursorTs time.Time
	cursorID uuid.UUID
	// quietUntil 之前的事件只学不报：首次上线回放历史时用
	quietUntil time.Time
	flows      map[flowKey]*flowState
	known      map[flowKey]bool
	// mine 记录本实例写入过基线的 flow，用于区分唯一索引撞行的两种来源：
	// 别的实例写的（或重启前的自己写的）按既有语义不再报；自己这轮尝试写过、
	// 后续步骤（告警）失败的，重试时仍要把告警补完——否则失败批次会被「跳过」。
	mine map[flowKey]bool
	// 资产接入时间：接入未满学习期的只学不报。不能按基线最早一条算——平时没有规律外联的干净主机
	// 进不了基线，它冒出的第一条心跳恰恰最可疑
	joined map[uuid.UUID]time.Time
}

type flowKey struct {
	asset uuid.UUID
	flow  string
}

type flowState struct {
	conn  Conn
	times []time.Time
	event uuid.UUID
}

func (e *Engine) Run(ctx context.Context) {
	if err := e.start(ctx, time.Now()); err != nil {
		slog.Error("外联心跳检测启动失败", "err", err)
		return
	}
	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()
	for {
		if err := e.round(ctx, time.Now()); err != nil {
			slog.Error("外联心跳检测失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// round 跑一轮扫描并发布完成标记（R3）。上界固定为 now−lateGrace：drain 读到它为止，
// 空区间/无命中同样算扫完（扫描完成 ≠ 有数据）。整轮成功（含全部业务副作用提交）才写
// settings[archive.beacon.scan]；drain 失败直接返回、不发布——标记保守落后，冷归档
// 切换闸门按 unknown 拒绝，方向安全。标记写入失败同样整轮报错（由 Run 记日志）。
func (e *Engine) round(ctx context.Context, now time.Time) error {
	if err := e.drain(ctx, now); err != nil {
		return err
	}
	return e.recordScanDone(ctx, now.Add(-lateGrace), time.Now())
}

// start 载入基线。基线为空说明是首次启用：从学习期起点回放库里的历史，只学不报，
// 有历史数据的资产上线即过学习期；否则从一个窗口之前接着看（重复的由基线挡住）
func (e *Engine) start(ctx context.Context, now time.Time) error {
	e.flows, e.known, e.mine, e.joined = map[flowKey]*flowState{}, map[flowKey]bool{}, map[flowKey]bool{}, map[uuid.UUID]time.Time{}
	rows, err := e.DB.BeaconBaseline.Query().All(ctx)
	if err != nil {
		return err
	}
	for _, b := range rows {
		e.known[flowKey{b.AssetID, b.Flow}] = true
	}
	e.cursorTs = now.Add(-e.Window)
	if len(rows) == 0 {
		e.cursorTs, e.quietUntil = now.Add(-e.LearningPeriod), now
	}
	return nil
}

func (e *Engine) joinedAt(ctx context.Context, asset uuid.UUID) (time.Time, error) {
	if t, ok := e.joined[asset]; ok {
		return t, nil
	}
	a, err := e.DB.Asset.Get(ctx, asset)
	if err != nil {
		return time.Time{}, err
	}
	e.joined[asset] = a.FirstSeen
	return a.FirstSeen, nil
}

// drain 读到追上当前时刻为止。晚到 lateGrace 内的事件留给下一轮，免得游标越过还在写入的事件
func (e *Engine) drain(ctx context.Context, now time.Time) error {
	for {
		n, err := e.batch(ctx, now.Add(-lateGrace))
		if err != nil || n < batchLimit {
			return err
		}
	}
}

// batch 读一批事件（(ts,id) > 游标，ts ≤ upTo），把连接时刻累积进内存 flow 状态，
// 对新出现的规律外联执行基线/告警副作用。**整批副作用成功才推进游标**：任何一步失败
// 都回滚本批对 flow 状态的追加、游标停在批前，下一轮从同一起点重读本批——失败批次
// 不会被跳过（R3：完成标记的 through 不越过未成功处理的批次）。不加通用重试框架，
// 重读与重试的幂等性来自既有机制：基线唯一索引（ON CONFLICT DO NOTHING），自己写入
// 过的基线记在 mine，重试只补落下的步骤、不重复已成功的副作用。
func (e *Engine) batch(ctx context.Context, upTo time.Time) (int, error) {
	rows, err := e.SQL.QueryContext(ctx, `SELECT id, asset_id, ts, raw->'dst_endpoint'->>'ip',
 coalesce(raw->'dst_endpoint'->>'port',''), coalesce(raw->'dst_endpoint'->>'hostname',''),
 coalesce(raw->'process'->>'name',''), coalesce(raw->'container'->>'name',''), raw ? 'platform_command'
FROM events WHERE class_uid=4001 AND source='agent' AND asset_id IS NOT NULL
 AND ts >= $1 AND (ts, id) > ($1, $2) AND ts <= $3 AND raw->'connection_info'->>'direction'='outbound'
ORDER BY ts, id LIMIT $4`, e.cursorTs, e.cursorID, upTo, batchLimit)
	if err != nil {
		return 0, err
	}
	// 先整批读进内存，游标与 flow 状态的变更放到副作用成功之后：读和改分开，
	// 失败才有明确的回滚点。
	type scanned struct {
		id, asset uuid.UUID
		ts        time.Time
		conn      Conn
		commanded bool
	}
	var buf []scanned
	for rows.Next() {
		var s scanned
		var ip sql.NullString
		if err := rows.Scan(&s.id, &s.asset, &s.ts, &ip, &s.conn.Port, &s.conn.Host,
			&s.conn.Process, &s.conn.Container, &s.commanded); err != nil {
			rows.Close()
			return 0, err
		}
		s.conn.IP = ip.String
		buf = append(buf, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(buf) == 0 {
		return 0, nil
	}

	// 累积前给每个被触碰的 flow 拍快照：失败时把 times 截回、conn/event 复原。
	// 不回滚的话重读本批会让同一时刻被记两次，Periodic 的间隔统计被零间隔冲垮。
	type flowSnap struct {
		existed bool
		conn    Conn
		event   uuid.UUID
		times   int
	}
	snaps := map[flowKey]flowSnap{}
	touched := map[flowKey]bool{}
	for _, s := range buf {
		// 平台指令拉起的连接不进基线也不报，与 UEBA 一致
		if s.commanded || !Public(s.conn.IP) {
			continue
		}
		k := flowKey{s.asset, s.conn.Flow()}
		if _, ok := snaps[k]; !ok {
			if f := e.flows[k]; f != nil {
				snaps[k] = flowSnap{existed: true, conn: f.conn, event: f.event, times: len(f.times)}
			}
		}
		f := e.flows[k]
		if f == nil {
			f = &flowState{}
			e.flows[k] = f
		}
		f.conn, f.event = s.conn, s.id
		f.times = append(f.times, s.ts)
		touched[k] = true
	}

	e.prune(buf[len(buf)-1].ts.Add(-e.Window))
	var batchErr error
	for k := range touched {
		if f := e.flows[k]; f != nil && !e.known[k] {
			if err := e.observe(ctx, k, f); err != nil && batchErr == nil {
				// 不打断同批其它 flow 的副作用（都已可重入），只记第一个错误
				batchErr = fmt.Errorf("处理外联 %s（资产 %s）: %w", k.flow, k.asset, err)
			}
		}
	}
	if batchErr != nil {
		// 回滚本批对 flow 状态的追加，游标不推进。prune 已淘汰的 flow 不加回：
		// 「没有本批」的世界里它同样会被淘汰（阈值只取决于本批最后一行的时间）。
		for k, s := range snaps {
			f := e.flows[k]
			if f == nil {
				continue
			}
			if !s.existed {
				delete(e.flows, k)
				continue
			}
			f.conn, f.event = s.conn, s.event
			if len(f.times) > s.times {
				f.times = f.times[:s.times]
			}
		}
		return len(buf), batchErr
	}
	e.cursorTs, e.cursorID = buf[len(buf)-1].ts, buf[len(buf)-1].id
	return len(buf), nil
}

// prune 丢掉窗口外的连接时刻，空了的外联整条丢掉，内存随活跃外联数有界
func (e *Engine) prune(before time.Time) {
	for k, f := range e.flows {
		i := 0
		for i < len(f.times) && f.times[i].Before(before) {
			i++
		}
		f.times = f.times[i:]
		if len(f.times) == 0 {
			delete(e.flows, k)
		}
	}
}

// observe 新出现的规律外联：入基线；资产接入已满学习期、且不在首次回放里，才出告警。
// known 只在整条路径走到头（含告警，或明确判定不该报）之后置位——中途失败留下的 flow
// 不算「见过」，下一轮重试。基线写入幂等（唯一索引）；本实例自己写过的基线记在 mine，
// 重试撞唯一索引时仍要把告警补完，别的实例写的才按既有语义跳过。
func (e *Engine) observe(ctx context.Context, k flowKey, f *flowState) error {
	p, ok := Periodic(f.times)
	if !ok {
		return nil
	}
	// 多节点切换时可能有别的实例刚写过，以唯一索引为准：没插进去就不是新的
	var inserted uuid.UUID
	err := e.SQL.QueryRowContext(ctx, `INSERT INTO beacon_baselines(id, asset_id, flow, first_seen) VALUES($1,$2,$3,$4)
ON CONFLICT (asset_id, flow) DO NOTHING RETURNING id`, uuid.Must(uuid.NewV7()), k.asset, k.flow, p.First).Scan(&inserted)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil {
		e.mine[k] = true
	}
	if err == sql.ErrNoRows && !e.mine[k] {
		// 别的实例（或重启前的自己）写的：不是新出现的，不再报
		e.known[k] = true
		return nil
	}
	if p.Last.Before(e.quietUntil) {
		e.known[k] = true
		return nil
	}
	joined, err := e.joinedAt(ctx, k.asset)
	if err != nil {
		return err
	}
	if p.Last.Sub(joined) < e.LearningPeriod {
		// 接入未满学习期：只学不报
		e.known[k] = true
		return nil
	}
	ev, err := e.DB.Event.Get(ctx, f.event)
	if err != nil {
		return err
	}
	var raw map[string]any
	_ = json.Unmarshal(ev.Raw, &raw)
	if e.Suppress != nil && e.Suppress.Suppressed(sigma.RuleBeacon, &k.asset, raw, p.Last) {
		e.known[k] = true
		return nil
	}
	detail := f.conn.Describe(p)
	if err := e.DB.Alert.Create().SetTs(p.Last).SetLastTs(p.Last).SetRuleID(sigma.RuleBeacon).SetSeverity(3).
		SetEventID(f.event).SetAssetID(k.asset).SetCount(p.Hits).SetDetail(detail).Exec(ctx); err != nil {
		return err
	}
	e.known[k] = true
	slog.Info("新出现的外联心跳", "asset", k.asset, "flow", k.flow, "median", p.Median, "hits", p.Hits)
	return nil
}
