package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entevent "openxdr/server/ent/event"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/eventarchive"
	"openxdr/server/internal/eventsearch"
)

const maxEventRows = 200

// eventsCoverage 是 /api/events 响应体里的查询覆盖度说明，真源在这里；
// X-Archive-Coverage 响应头只是调试用的摘要，见 mapEvents。
//
// 字段语义：
//   - hot_searched / cold_searched：本次各自数据源是否真的参与了查询。热表恒为 true
//     （该入口必查热表）；cold_searched=false 表示冷层没查——原因看 reason。
//   - scan_complete：本次请求声明的范围（热 + 冷，按时间窗与过滤条件）是否扫完。
//     与 reason 互为表里：reason 非空（任何缺口）时必为 false；预算耗尽（scan_incomplete）、
//     关键词跳过冷层（keyword_not_searched）、热表关键词检索超时（hot_keyword_degraded）都算没扫完。
//   - reason：空串 = 无缺口。非空取值：
//     hot_keyword_degraded（热表关键词检索超出时限，只覆盖了最近的数据，优先于其他原因）；
//     keyword_not_searched（关键词查询不搜冷块，冷块无关键词索引）；
//     no_archive_schema（冷读开着但冷归档表未初始化）；
//     scan_incomplete（扫描预算耗尽，还有候选块没解压）；
//     before_archive（查询窗口整体早于最早的冷块，该窗口不在冷层覆盖内）。
//     块损坏等读取错误不走 reason——那直接 500，不能用「缺口说明」掩盖错误。
type eventsCoverage struct {
	HotSearched  bool   `json:"hot_searched"`
	ColdSearched bool   `json:"cold_searched"`
	ScanComplete bool   `json:"scan_complete"`
	Reason       string `json:"reason"`
}

// eventsResponse 是 /api/events 的响应契约：items 是事件行，truncated 表示返回条数达到
// limit（可能还有更早的，与扫描是否完整无关），coverage 说明冷热两层的覆盖情况。
type eventsResponse struct {
	Items     []eventRow     `json:"items"`
	Truncated bool           `json:"truncated"`
	Coverage  eventsCoverage `json:"coverage"`
}

// coverage 缺口原因，与 eventsCoverage.Reason 的取值一一对应。
const (
	reasonKeyword            = "keyword_not_searched"
	reasonHotKeywordDegraded = "hot_keyword_degraded"
	reasonNoSchema           = "no_archive_schema"
	reasonScanBudget         = "scan_incomplete"
	reasonBeforeCold         = "before_archive"
)

type eventRow struct {
	ID        uuid.UUID       `json:"id"`
	Ts        time.Time       `json:"ts"`
	ClassUID  int             `json:"classUid"`
	Source    string          `json:"source"`
	AssetID   *uuid.UUID      `json:"assetId"`
	Username  *string         `json:"username"`
	ConnTuple *string         `json:"connTuple"`
	Raw       json.RawMessage `json:"raw"`
	// 这条事件的告警来自登记的可信自动化来源
	Automation *automationRef `json:"automation,omitempty"`
}

// mapEvents 原始事件检索：告警只是线索，取证要能沿着线索翻原始遥测。
// 关键词对整个事件体做子串匹配——分析师拿到的往往是一个 IP、一段命令行、
// 一个文件名，不该要求他先知道字段路径。
//
// 热表（events）与冷块（event_archive_chunks）合流：热表先查，冷块按同一组参数补上，
// 结果按 (ts, id) 去重倒序。冷块里没有数据时不会走到冷查询。
//
// 响应是对象契约 {items, truncated, coverage}：truncated 表示返回条数达到 limit，
// coverage 说明冷热两层的覆盖缺口（关键词跳过冷层、冷读关闭、预算耗尽等）。
// X-Archive-Coverage / X-Truncated 响应头保留为调试摘要，真源是响应体。
//
// conn 是冷归档读取用的原始连接（与 ent 共用同一个池）。为 nil 时冷层整体不参与：
// 拿不到冷库连接时既不能假装查过，也不该因此影响热表查询。
func mapEvents(api *http.ServeMux, db *ent.Client, conn *sql.DB) {
	api.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		p := r.URL.Query()
		now := time.Now()

		from := now.Add(-24 * time.Hour)
		if v, err := time.Parse(time.RFC3339, p.Get("from")); err == nil {
			from = v
		}
		to := now
		if v, err := time.Parse(time.RFC3339, p.Get("to")); err == nil {
			to = v
		}

		preds := append([]predicate.Event{entevent.TsGTE(from), entevent.TsLTE(to)}, s.event()...)
		var assetID *uuid.UUID
		if value := p.Get("assetId"); value != "" {
			id, err := uuid.Parse(value)
			if err != nil {
				http.Error(w, "无效的 assetId", http.StatusBadRequest)
				return
			}
			assetID = &id
			preds = append(preds, entevent.AssetIDEQ(id))
		}
		var classUID *int
		if class, err := strconv.Atoi(p.Get("classUid")); err == nil {
			classUID = &class
			preds = append(preds, entevent.ClassUIDEQ(class))
		}
		if source := p.Get("source"); source != "" {
			preds = append(preds, entevent.SourceEQ(source))
		}

		limit := 100
		if n, err := strconv.Atoi(p.Get("limit")); err == nil && n > 0 && n <= maxEventRows {
			limit = n
		}

		query := func() *ent.EventQuery { return db.Event.Query().Where(preds...) }
		var rows []*ent.Event
		complete := true
		var err error
		if kw := p.Get("q"); kw != "" {
			rows, complete, err = eventsearch.Search(r.Context(), query, eventsearch.Keyword(kw), limit)
		} else {
			rows, err = query().Order(ent.Desc(entevent.FieldTs)).Limit(limit).All(r.Context())
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 冷块按同一组参数补数据。块损坏等错误如实返回 500：不能降级成只返回热表，
		// 那会让调用方以为「查到的就是全部」。
		cold, cov, header, err := archiveEvents(r.Context(), conn, s, eventFilter{
			from: from, to: to, assetID: assetID, classUID: classUID,
			source: p.Get("source"), keyword: p.Get("q"), limit: limit, hotComplete: complete,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// 调试头保留一段时间，真源是响应体里的 coverage
		if header != "" {
			w.Header().Set("X-Archive-Coverage", header)
		}

		out := make([]eventRow, len(rows))
		for i, e := range rows {
			out[i] = toEventRow(e)
		}
		out = mergeRows(out, coldRows(cold), limit)
		// 取满上限说明可能还有更早的，提示前端收窄条件；这只说明条数到限，
		// 与 coverage.scan_complete（是否扫完，含关键词检索降级）是两回事，可以同时为真
		truncated := len(out) == limit
		if truncated {
			w.Header().Set("X-Truncated", "1")
		}
		ids := make([]uuid.UUID, len(out))
		for i, e := range out {
			ids[i] = e.ID
		}
		sources, err := eventAutomation(r.Context(), db, ids)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for i := range out {
			out[i].Automation = sources[out[i].ID]
		}
		writeJSON(w, eventsResponse{Items: out, Truncated: truncated, Coverage: cov})
	})
}

// eventFilter 是一次 /api/events 请求里与冷查询相关的参数，与热表查询用的是同一组。
type eventFilter struct {
	from, to time.Time
	assetID  *uuid.UUID
	classUID *int
	source   string
	keyword  string
	limit    int
	// hotComplete 是热表检索是否完整（关键词检索超时降级为不完整时为 false）；
	// 冷层照常跳过（无关键词索引），但覆盖度要如实反映热侧缺口
	hotComplete bool
}

// archiveEvents 查冷块，返回合流用的事件、写进响应体的覆盖度与调试用摘要头。
//
// 覆盖度必须如实：真查了就报 chunks/matched/truncated（头）与 cold_searched=true（体），
// 没查就写清原因。热表关键词检索超时（hot_keyword_degraded）最先判断：结果里缺的是热表本身的数据，
// 比冷层缺口要紧，不能被下面任何一种情形盖掉。
//
// conn 为 nil（冷读开关没开）时与改动前一致，不报缺口：默认部署每次检索都弹「冷层未搜索」只会是噪音。
// 库里已有冷块却没开读属于部署配置错误，由 main 在启动日志里告警（见 archiveConn）。
// 冷读开着时三种「没查」的情形：
//   - skipped=no-schema（no_archive_schema）：冷读开关开了，但库里还没有冷归档表
//     （没跑过 ensure-schema）。这是部署状态，按「没有冷数据」处理，不能让事件页整页 500。
//   - skipped=keyword（keyword_not_searched）：关键词查询，冷块没有索引。
//   - skipped=before_archive（before_archive）：查询窗口整体早于最早一块冷数据。
//
// 归档表在、但一条冷块都没有时不报缺口：此时冷层不可能吞掉任何事件。
// 扫描预算耗尽时 cold_searched=true 但 scan_complete=false（reason=scan_incomplete）——
// 查了，没查完。真正的块损坏仍然是 500，不降级成部分结果。
func archiveEvents(ctx context.Context, conn *sql.DB, s scope, q eventFilter) ([]eventarchive.Event, eventsCoverage, string, error) {
	// 热表这个入口必查；默认无缺口，下面按实际情形收紧
	cov := eventsCoverage{HotSearched: true, ScanComplete: true}
	if q.keyword != "" && !q.hotComplete {
		cov.Reason, cov.ScanComplete = reasonHotKeywordDegraded, false
		return nil, cov, "hot_keyword_degraded", nil
	}
	if conn == nil {
		return nil, cov, "", nil
	}
	ext, err := eventarchive.ArchiveExtent(ctx, conn)
	if err != nil {
		if errors.Is(err, eventarchive.ErrNoSchema) {
			cov.Reason, cov.ScanComplete = reasonNoSchema, false
			return nil, cov, "skipped=no-schema", nil
		}
		return nil, cov, "", err
	}
	if !ext.Schema {
		cov.Reason, cov.ScanComplete = reasonNoSchema, false
		return nil, cov, "skipped=no-schema", nil
	}
	if !ext.Has {
		// 冷层确实没有数据：谈不上缺口
		return nil, cov, "", nil
	}
	// 冷块没有关键词索引，逐块解压全文扫的代价不可控，明确跳过并告诉调用方
	if q.keyword != "" {
		cov.Reason, cov.ScanComplete = reasonKeyword, false
		return nil, cov, "skipped=keyword", nil
	}
	// 窗口整个早于最早一块冷数据：该窗口不在冷层覆盖内
	if q.to.Before(ext.First) {
		cov.Reason, cov.ScanComplete = reasonBeforeCold, false
		return nil, cov, "skipped=before_archive", nil
	}
	f := eventarchive.Filter{
		From:     q.from,
		To:       q.to.Add(time.Nanosecond), // 热表是 ts <= to，冷查询是左闭右开：补 1ns 不漏边界
		AssetIDs: visibleAssets(s, q.assetID),
		Limit:    q.limit,
	}
	if q.classUID != nil {
		f.Classes = []int{*q.classUID}
	}
	if q.source != "" {
		f.Sources = []string{q.source}
	}
	events, ccov, err := eventarchive.Query(ctx, conn, f)
	if err != nil {
		if errors.Is(err, eventarchive.ErrNoSchema) {
			cov.Reason, cov.ScanComplete = reasonNoSchema, false
			return nil, cov, "skipped=no-schema", nil
		}
		return nil, cov, "", err
	}
	cov.ColdSearched = true
	if ccov.ScanIncomplete {
		// 预算耗尽：查了但没扫完候选块，结果只是该范围的最新一段
		cov.Reason, cov.ScanComplete = reasonScanBudget, false
	}
	header := fmt.Sprintf("chunks=%d;matched=%d;truncated=%d", ccov.ScannedChunks, ccov.Matched, boolInt(ccov.Truncated))
	return events, cov, header, nil
}

// visibleAssets 是冷查询能看到的资产集合：nil 表示不限（全局 admin），
// 其余情况一律受限。非 admin 即便一个可见资产都没有，也要传受限的空集合，
// 不能退化成「不限」——否则组外资产与 asset_id 为 NULL 的冷事件都会漏出去。
func visibleAssets(s scope, assetID *uuid.UUID) []uuid.UUID {
	if s.all {
		if assetID == nil {
			return nil
		}
		return []uuid.UUID{*assetID}
	}
	assets := s.assets
	if assets == nil {
		assets = []uuid.UUID{}
	}
	if assetID == nil {
		return assets
	}
	// 与热表的两个条件同时生效一致：资产不在范围内，交集为空
	if !slices.Contains(assets, *assetID) {
		return []uuid.UUID{}
	}
	return []uuid.UUID{*assetID}
}

// coldRows 把冷块事件转成与热表同构的行，JSON 字段一个不少、一个不多。
func coldRows(events []eventarchive.Event) []eventRow {
	if len(events) == 0 {
		return nil
	}
	out := make([]eventRow, len(events))
	for i, e := range events {
		out[i] = eventRow{
			ID: e.ID, Ts: e.Ts, ClassUID: int(e.ClassUID), Source: e.Source,
			AssetID: e.AssetID, Username: e.Username, ConnTuple: e.ConnTuple, Raw: e.Raw,
		}
	}
	return out
}

// rowKey 是合流去重口径：同一个 id 同一个 ts 只留一条。
type rowKey struct {
	ts int64
	id uuid.UUID
}

// mergeRows 把热表行与冷块事件合流：(ts, id) 去重（热表优先，它带着告警与自动化信息）、
// 按 (ts, id) 倒序、截到 limit。
//
// cold 为空时原样返回热表结果：不重排、不截断、不换底层数组。没有冷数据参与时，
// 响应必须与改动前逐字节一致（同样的 JSON、同样的头）。
func mergeRows(hot, cold []eventRow, limit int) []eventRow {
	if len(cold) == 0 {
		return hot
	}
	seen := make(map[rowKey]struct{}, len(hot)+len(cold))
	out := make([]eventRow, 0, len(hot)+len(cold))
	for _, list := range [][]eventRow{hot, cold} {
		for _, row := range list {
			k := rowKey{ts: row.Ts.UnixNano(), id: row.ID}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, row)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Ts.Equal(out[j].Ts) {
			return out[i].Ts.After(out[j].Ts)
		}
		return bytes.Compare(out[i].ID[:], out[j].ID[:]) > 0
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
