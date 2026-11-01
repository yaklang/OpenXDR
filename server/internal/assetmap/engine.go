package assetmap

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/event"
	"openxdr/server/internal/graphqueue"
	"openxdr/server/internal/triage"
)

const (
	batchLimit = 1000
	cursorKey  = "assetmap.cursor"
	// 首次启用往回补一周的连接，图谱上线就有内容
	backfill = 7 * 24 * time.Hour
	// 超过这么久没再出现的依赖边删掉，与原始事件保留期同量级
	linkTTL = 30 * 24 * time.Hour
	// 标注检查周期：重算事实指纹比对，变了才调模型
	checkEvery = 10 * time.Minute
)

// Engine 集群单活：增量扫描网络与设备清单事件，物化资产画像与依赖边，按需触发 AI 标注。
// 读的是已落库的事件，队列模式与单机直连模式一视同仁。
//
// 游标语义（冷归档 R3 核对结论）：每批的依赖边/清单物化与游标 upsert 在同一事务提交，
// 批内任何一步失败整体回滚——游标只在整批成功后推进；空区间（游标后没有事件）不推进，
// 冷归档切换闸门按「未追平」保守拒绝。游标是 (ts,id) 元组：同一时刻的多条事件不会被
// 批次边界或重启跳过（旧实现的 ts > 游标 会漏掉与游标同时刻的剩余事件，物化计数少记）。
type Engine struct {
	DB       *ent.Client
	SQL      *sql.DB
	LLM      *triage.LLM
	Interval time.Duration
	// 定时重新标注的周期，0 表示只在事实变化或人工要求时标注
	Refresh time.Duration

	cursor    time.Time
	cursorID  uuid.UUID
	lastCheck time.Time
	lastPrune time.Time
	// 标注失败的时刻，单活进程内存里记着即可，重启后重试无妨
	failed map[uuid.UUID]time.Time
}

func (e *Engine) Run(ctx context.Context) {
	e.cursor, e.cursorID = e.loadCursor(ctx)
	if mode, err := graphqueue.Mode(ctx, e.SQL); err == nil && mode == graphqueue.Legacy {
		slog.Warn("资产图谱仍处于 legacy 游标模式，慢时钟主机清单可能被跳过；全部节点升级后请按 docs/asset-map.md 切换为持久待办")
	}
	if err := e.dropNonDependencies(ctx); err != nil {
		slog.Error("清理未指定源地址的依赖边失败", "err", err)
	}
	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()
	for {
		for {
			n, err := e.batch(ctx)
			if err != nil {
				slog.Error("资产图谱批次失败", "err", err)
				break
			}
			if n < batchLimit {
				break
			}
		}
		if time.Since(e.lastPrune) > time.Hour {
			e.lastPrune = time.Now()
			if _, err := e.deleteLinks(ctx, `DELETE FROM asset_links WHERE last_seen < $1`, time.Now().Add(-linkTTL)); err != nil {
				slog.Error("清理过期依赖边失败", "err", err)
			}
		}
		if e.LLM != nil && e.LLM.Enabled() {
			e.annotateDue(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// loadCursor 读持久游标 (ts,id)。旧格式（裸时间）按 (ts, 最大 uuid) 读入：查询条件
// 等价于旧实现的 ts > 游标，不会重读已处理的事件——依赖边的计数是累加，重读会重复计数。
// （冷归档 R3 核对结论：游标只在整批成功后推进，空区间不推进，切换闸门按「未追平」保守拒绝。）
func (e *Engine) loadCursor(ctx context.Context) (time.Time, uuid.UUID) {
	var raw []byte
	err := e.SQL.QueryRowContext(ctx, `SELECT value FROM settings WHERE id=$1`, cursorKey).Scan(&raw)
	if err != nil {
		return time.Now().Add(-backfill), uuid.Max
	}
	var tuple struct {
		Ts time.Time `json:"ts"`
		ID uuid.UUID `json:"id"`
	}
	if json.Unmarshal(raw, &tuple) == nil && !tuple.Ts.IsZero() {
		return tuple.Ts, tuple.ID
	}
	var ts time.Time
	if json.Unmarshal(raw, &ts) == nil {
		return ts, uuid.Max
	}
	return time.Now().Add(-backfill), uuid.Max
}

// upsertLink 依赖边累加：同键的计数相加、时间取并集
const upsertLink = `INSERT INTO asset_links
  (id, src_ip, src_asset_id, dst_ip, dst_port, proto, process, count, first_seen, last_seen)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (src_ip, dst_ip, dst_port, proto, process) DO UPDATE SET
  count = asset_links.count + EXCLUDED.count,
  first_seen = LEAST(asset_links.first_seen, EXCLUDED.first_seen),
  last_seen = GREATEST(asset_links.last_seen, EXCLUDED.last_seen),
  src_asset_id = COALESCE(EXCLUDED.src_asset_id, asset_links.src_asset_id)`

type linkKey struct {
	srcIP, dstIP string
	port         int
	proto        string
	process      string
}

type linkAgg struct {
	srcAsset    *uuid.UUID
	count       int64
	first, last time.Time
}

func (e *Engine) batch(ctx context.Context) (int, error) {
	mode, err := graphqueue.Mode(ctx, e.SQL)
	if err != nil {
		return 0, err
	}
	if mode == graphqueue.Requested {
		if e.cursor.IsZero() {
			e.cursor, e.cursorID = e.loadCursor(ctx)
		}
		if err := graphqueue.Activate(ctx, e.SQL, e.cursor); err != nil {
			return 0, err
		}
		mode = graphqueue.Queued
		slog.Info("资产图谱已切换为持久待办消费")
	}
	tx, err := e.SQL.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	locked, err := lockGraphBatch(ctx, tx)
	if err != nil || !locked {
		return 0, err
	}
	var events []*ent.Event
	if mode == graphqueue.Queued {
		events, err = queuedEvents(ctx, tx)
	} else {
		// (ts,id) > 游标：批次边界或重启落在同一时刻的多条事件之间时，
		// 剩余同刻事件不会被跳过（物化的依赖边计数会少记）
		events, err = e.DB.Event.Query().
			Where(
				event.ClassUIDIn(classNetwork, ClassInventory, ClassSoftware),
				event.Or(
					event.TsGT(e.cursor),
					event.And(event.TsEQ(e.cursor), event.IDGT(e.cursorID)),
				),
			).
			Order(ent.Asc(event.FieldTs), ent.Asc(event.FieldID)).
			Limit(batchLimit).All(ctx)
	}
	if err != nil || len(events) == 0 {
		return 0, err
	}
	own, err := e.assetIPs(ctx)
	if err != nil {
		return 0, err
	}
	names, err := e.processNames(ctx, events)
	if err != nil {
		return 0, err
	}
	managed := map[netip.Addr]bool{}
	for _, ips := range own {
		for _, ip := range ips {
			managed[ip] = true
		}
	}

	links := map[linkKey]*linkAgg{}
	type snapshot struct {
		ts        time.Time
		listening []Listener
		cloud     *Cloud
		os        string
	}
	inventories := map[uuid.UUID]snapshot{}
	type softwareSnap struct {
		ts time.Time
		sw *Software
	}
	softwares := map[uuid.UUID]softwareSnap{}
	for _, ev := range events {
		if ev.ClassUID == ClassSoftware {
			if sw, ok := software(ev.Raw); ok && ev.AssetID != nil {
				if previous, ok := softwares[*ev.AssetID]; !ok || ev.Ts.After(previous.ts) {
					softwares[*ev.AssetID] = softwareSnap{ev.Ts, sw}
				}
			}
			continue
		}
		if ev.ClassUID == ClassInventory {
			if ev.AssetID != nil {
				l, c, os := inventory(ev.Raw)
				if previous, ok := inventories[*ev.AssetID]; !ok || ev.Ts.After(previous.ts) {
					inventories[*ev.AssetID] = snapshot{ev.Ts, l, c, os}
				}
			}
			continue
		}
		k, srcAsset, ok := eventLink(ev, own, names, managed)
		if !ok {
			continue
		}
		agg := links[k]
		if agg == nil {
			agg = &linkAgg{srcAsset: srcAsset, first: ev.Ts}
			links[k] = agg
		}
		agg.count++
		if ev.Ts.Before(agg.first) {
			agg.first = ev.Ts
		}
		if ev.Ts.After(agg.last) {
			agg.last = ev.Ts
		}
	}

	last := events[len(events)-1]
	ids := make([]string, len(events))
	for i, ev := range events {
		ids[i] = ev.ID.String()
	}
	for k, a := range links {
		if _, err := tx.ExecContext(ctx, upsertLink,
			uuid.Must(uuid.NewV7()), k.srcIP, a.srcAsset, k.dstIP, k.port, k.proto, k.process, a.count, a.first, a.last); err != nil {
			return 0, err
		}
	}
	for id, s := range softwares {
		sw, _ := json.Marshal(s.sw)
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET software=$2::jsonb, software_at=$3
WHERE id=$1 AND (software_at IS NULL OR software_at < $3)`, id, string(sw), s.ts); err != nil {
			return 0, err
		}
	}
	for id, s := range inventories {
		listening, _ := json.Marshal(s.listening)
		var cloud any
		if s.cloud != nil {
			b, _ := json.Marshal(s.cloud)
			cloud = string(b)
		}
		// 只接受比已物化的更新的快照，乱序到达的旧快照不回滚状态。
		// os_display 只在事件带系统显示名时覆盖：旧 agent 没有该字段，保留导入时声明的值
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET listening=$2::jsonb, cloud=$3::jsonb, inventory_at=$4,
os_display=COALESCE(NULLIF($5::text, ''), os_display)
WHERE id=$1 AND (inventory_at IS NULL OR inventory_at < $4)`, id, string(listening), cloud, s.ts, s.os); err != nil {
			return 0, err
		}
	}
	// 游标与本批全部物化同一事务提交：整批成功才推进（见 Engine 的游标语义注释）
	value, _ := json.Marshal(struct {
		Ts time.Time `json:"ts"`
		ID uuid.UUID `json:"id"`
	}{last.Ts, last.ID})
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings (id, value, updated_at) VALUES ($1, $2::jsonb, now())
ON CONFLICT (id) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, cursorKey, string(value)); err != nil {
		return 0, err
	}
	if err := graphqueue.Ack(ctx, tx, ids); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	e.cursor, e.cursorID = last.Ts, last.ID
	return len(events), nil
}

// assetIPs 资产登记的地址，判断连接是否发自宿主机本身
func (e *Engine) assetIPs(ctx context.Context) (map[uuid.UUID][]netip.Addr, error) {
	assets, err := e.DB.Asset.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID][]netip.Addr, len(assets))
	for _, a := range assets {
		out[a.ID] = parseIPs(a.IPAddrs)
	}
	return out, nil
}

// processNames 只为缺少进程名的出站连接回查进程事件。
func (e *Engine) processNames(ctx context.Context, events []*ent.Event) (map[uuid.UUID]string, error) {
	return processNamesFrom(ctx, e.SQL, events)
}

func processNamesFrom(ctx context.Context, db graphReader, events []*ent.Event) (map[uuid.UUID]string, error) {
	seen := map[uuid.UUID]bool{}
	var ids []string
	for _, ev := range events {
		if ev.ClassUID != classNetwork || ev.ProcessGUID == nil || seen[*ev.ProcessGUID] {
			continue
		}
		c, ok := connOf(ev.Raw, "")
		if !ok || c.inbound || c.process != "" {
			continue
		}
		seen[*ev.ProcessGUID] = true
		ids = append(ids, ev.ProcessGUID.String())
	}
	out := map[uuid.UUID]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT ON (process_guid) process_guid, coalesce(raw->'process'->>'name', '')
FROM events WHERE process_guid = ANY($1::uuid[]) AND class_uid = 1007`, "{"+strings.Join(ids, ",")+"}")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = clean(name, 64)
	}
	return out, rows.Err()
}

// dropNonDependencies 清掉不该是依赖边的旧数据，在写入侧一次清干净，图谱、攻击面、标注与 AI 只读视图这些读方都不必各自记得过滤。幂等。
//
// 一是未指定源地址：早先 UDP 出站的 0.0.0.0 / :: 原样进了 asset_links，在图谱上长出一个「0.0.0.0」节点。
// 这些边不能改记到某台资产上：唯一键里没有资产，多台资产连同一目的（各机的 tailscaled 连同一批 DERP）落在同一行、
// src_asset_id 是最后写入者，计数与归属都混了，改记就是把别人的连接安到这台机器头上。直接删，活跃的连接下一批事件就按资产自己的地址重新长出来。
// 二是连实例元数据服务的边（见 instanceMetadata）：早先没剔，agent 启动识别云环境的那一次连接在图谱和 AI 眼里成了一条来历不明的外联。
func (e *Engine) dropNonDependencies(ctx context.Context) error {
	n, err := e.deleteLinks(ctx, `DELETE FROM asset_links WHERE src_ip IN ('0.0.0.0', '::') OR dst_ip IN ('100.100.100.200', 'fd00:ec2::254')`)
	if err != nil {
		return err
	}
	if n > 0 {
		slog.Info("已清理不属于依赖的边", "rows", n)
	}
	return nil
}
