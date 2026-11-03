package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/authfields"

	"openxdr/server/internal/cmdorigin"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/temporal"
)

// 时序回测：按 (事件时间, ID) 顺序回放真实事件，先过基础规则，再在内存里做时序求值，不写库。
// 与线上 Observe 同一快照、同一实体口径（资产 / 规范化账号），终点按排序只在它到达时求值一次，
// 等价于全部事件按时到达后的线上结果。差异：归组取资产当前的组（历史归组不可知）；不模拟迟到与候选清理；
// 候选上限按回放到终点时已见的窗口判断。

type candidate struct {
	id       uuid.UUID
	ts       time.Time
	rules    []string
	group    uuid.NullUUID
	asset    uuid.NullUUID
	host     string
	username string
	sourceIP string
}

type temporalStat struct {
	groupBy  string
	hits     int
	entities map[string]int
	samples  [][]uuid.UUID
}

type windowKey struct {
	groupBy string
	scope   temporal.Scope
}

type temporalBacktest struct {
	snapshot   *temporal.Snapshot
	samples    int
	windows    map[windowKey][]temporal.Event
	stats      map[string]*temporalStat
	skipped    map[string]int
	candidates int
	// byRule 每条被引用的基础规则（含信号规则）贡献的候选数；peak 每个维度单个实体窗口里最多同时有多少候选
	byRule map[string]int
	peak   map[string]peakWindow
	last   candidate
}

type peakWindow struct {
	size  int
	label string
	at    time.Time
}

func newTemporalBacktest(snapshot *temporal.Snapshot, rules []*sigma.Rule, samples int) *temporalBacktest {
	b := &temporalBacktest{snapshot: snapshot, samples: samples, windows: map[windowKey][]temporal.Event{},
		stats: map[string]*temporalStat{}, skipped: map[string]int{}, byRule: map[string]int{}, peak: map[string]peakWindow{}}
	for _, r := range rules {
		if r.Kind != "" {
			b.stats[r.ID] = &temporalStat{entities: map[string]int{}}
		}
	}
	return b
}

// candidateOf 只做基础匹配，不改回放状态：分段读取失败重试时不会重复计数。
func (b *temporalBacktest) candidateOf(class int, osName string, doc map[string]any, username string) []string {
	sigma.WithActor(doc, username)
	return b.snapshot.CandidateRules(class, osName, doc, b.snapshot.EvaluateBase(class, osName, doc))
}

// apply 按排序依次喂入候选；顺序倒退说明读取有误，直接报错而不是给出错误的命中数。
func (b *temporalBacktest) apply(c candidate) error {
	if !b.last.ts.IsZero() && (c.ts.Before(b.last.ts) || (c.ts.Equal(b.last.ts) && c.id.String() <= b.last.id.String())) {
		return fmt.Errorf("事件未按 (时间, ID) 递增读取: %s %s 排在 %s %s 之后", c.id, c.ts.Format(time.RFC3339Nano), b.last.id, b.last.ts.Format(time.RFC3339Nano))
	}
	b.last = c
	b.candidates++
	for _, id := range c.rules {
		b.byRule[id]++
	}
	if !c.asset.Valid || !c.group.Valid || c.group.UUID == uuid.Nil {
		b.skipped["unscoped"]++
		return nil
	}
	for _, d := range []struct{ groupBy, entity, label string }{
		{temporal.GroupByAsset, c.asset.UUID.String(), cmp.Or(c.host, c.asset.UUID.String())},
		{temporal.GroupByAccount, temporal.AccountEntity(c.username), temporal.AccountEntity(c.username)},
		{temporal.GroupByAssetSourceIP, temporal.AssetSourceIPEntity(c.asset.UUID, c.sourceIP), c.asset.UUID.String() + "/" + c.sourceIP},
	} {
		if !b.snapshot.Relevant(d.groupBy, c.rules) {
			continue
		}
		if d.entity == "" {
			reason := "no_account"
			if d.groupBy == temporal.GroupByAssetSourceIP {
				reason = "no_source_ip"
			}
			b.skipped[reason]++
			continue
		}
		key := windowKey{d.groupBy, temporal.Scope{Group: c.group.UUID, Entity: d.entity}}
		window := append(b.windows[key], temporal.Event{ID: c.id, Time: c.ts, Scope: key.scope, Asset: c.asset.UUID.String(), Rules: c.rules})
		cutoff := c.ts.Add(-b.snapshot.MaxWindow())
		start := 0
		for start < len(window) && window[start].Time.Before(cutoff) {
			start++
		}
		window = window[start:]
		b.windows[key] = window
		if len(window) > b.peak[d.groupBy].size {
			b.peak[d.groupBy] = peakWindow{len(window), d.label, c.ts}
		}
		if len(window) > 10000 {
			b.skipped["candidate_limit"]++
			continue
		}
		matches, err := b.snapshot.Evaluate(d.groupBy, window)
		if err != nil {
			return err
		}
		for _, m := range matches {
			// 更早的终点在它们到达时已经求值；新事件排在最后，不会改变它们
			if m.Anchor != c.id {
				continue
			}
			s := b.stats[m.RuleID]
			s.groupBy = d.groupBy
			s.hits++
			s.entities[d.label]++
			if len(s.samples) < b.samples {
				s.samples = append(s.samples, m.Evidence)
			}
		}
	}
	return nil
}

// scanTemporal 读一段事件。只读事务：连到主库也写不进去；整段成功才把候选喂给回放状态。
func (b *temporalBacktest) scanTemporal(db *sql.DB, filter string, from, to time.Time) (int, int, error) {
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT e.id, e.ts, e.class_uid, e.raw, coalesce(e.username, ''), e.asset_id, a.group_id,
 coalesce(a.os, ''), coalesce(a.hostname, '')
FROM events e LEFT JOIN assets a ON a.id = e.asset_id
WHERE e.ts >= $1 AND e.ts < $2`+filter+` ORDER BY e.ts, e.id`, from, to)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	var found []candidate
	events, commanded := 0, 0
	for rows.Next() {
		var c candidate
		var class int
		var raw []byte
		var osName string
		if err := rows.Scan(&c.id, &c.ts, &class, &raw, &c.username, &c.asset, &c.group, &osName, &c.host); err != nil {
			return 0, 0, err
		}
		events++
		var doc map[string]any
		if json.Unmarshal(raw, &doc) != nil {
			continue
		}
		if _, ok := cmdorigin.Tag(doc); ok {
			commanded++
			continue
		}
		if c.rules = b.candidateOf(class, osName, doc, c.username); len(c.rules) > 0 {
			c.sourceIP = authfields.SourceIP(raw)
			found = append(found, c)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	// 先提交再喂入：副本冲突也可能在提交时才报（40001），整段重试前不能已经改了回放状态
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	for _, c := range found {
		if err := b.apply(c); err != nil {
			return 0, 0, err
		}
	}
	return events, commanded, nil
}

// temporalMain 严格加载基础 + 时序规则快照并解析时间范围；拿不准的输入直接拒绝。
func temporalMain(baseDir, temporalDir, fromText, toText string, days, samples int) error {
	store := &temporal.Store{}
	if err := store.Reload(baseDir, temporalDir); err != nil {
		return fmt.Errorf("时序规则快照加载失败: %w", err)
	}
	to := time.Now()
	if toText != "" {
		parsed, err := time.Parse(time.RFC3339, toText)
		if err != nil {
			return fmt.Errorf("-to 时间格式无效: %w", err)
		}
		to = parsed
	}
	from := to.Add(-time.Duration(days) * 24 * time.Hour)
	if fromText != "" {
		parsed, err := time.Parse(time.RFC3339, fromText)
		if err != nil {
			return fmt.Errorf("-from 时间格式无效: %w", err)
		}
		from = parsed
	}
	if !from.Before(to) {
		return fmt.Errorf("-from 必须早于 -to")
	}
	return runTemporal(store, from, to, samples)
}

func runTemporal(store *temporal.Store, from, to time.Time, samples int) error {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer db.Close()
	rules := store.Rules()
	referenced := map[string]bool{}
	for _, r := range rules {
		for _, id := range r.References {
			referenced[id] = true
		}
	}
	// 只读时序规则引用的基础规则会看的类别；不限类别（ClassUID 0）要看全部
	classes := map[int]bool{}
	for _, r := range rules {
		if r.Kind == "" && referenced[r.ID] {
			classes[r.ClassUID] = true
		}
	}
	filter := ""
	if !classes[0] {
		ids := make([]string, 0, len(classes))
		for c := range classes {
			ids = append(ids, fmt.Sprint(c))
		}
		slices.Sort(ids)
		filter = " AND e.class_uid IN (" + strings.Join(ids, ",") + ")"
	}
	b := newTemporalBacktest(store.Current(), rules, samples)
	started := time.Now()
	events, commanded := 0, 0
	for segment := from; segment.Before(to); segment = segment.Add(time.Hour) {
		end := segment.Add(time.Hour)
		if end.After(to) {
			end = to
		}
		var n, c int
		for attempt := 0; attempt < 5; attempt++ {
			if n, c, err = b.scanTemporal(db, filter, segment, end); err == nil || !strings.Contains(err.Error(), "40001") {
				break
			}
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
		if err != nil {
			return fmt.Errorf("%s 那一小时: %w", segment.Format(time.DateTime), err)
		}
		events += n
		commanded += c
	}
	b.report(rules, from, to, events, commanded, time.Since(started))
	return nil
}

func (b *temporalBacktest) report(rules []*sigma.Rule, from, to time.Time, events, commanded int, took time.Duration) {
	fmt.Printf("时序回测 %s — %s：%d 条事件（平台指令拉起的 %d 条不计），基础命中候选 %d 条，规则版本 %s，耗时 %s\n\n",
		from.Format(time.RFC3339), to.Format(time.RFC3339), events, commanded, b.candidates, b.snapshot.Revision(), took.Round(time.Second))
	fmt.Println("| 命中 | 级别 | 规则 | 维度 | 分布（前 10） | 样例证据事件 ID |")
	fmt.Println("|---:|---:|---|---|---|---|")
	var list []*sigma.Rule
	for _, r := range rules {
		if r.Kind != "" {
			list = append(list, r)
		}
	}
	slices.SortFunc(list, func(x, y *sigma.Rule) int {
		return cmp.Or(b.stats[y.ID].hits-b.stats[x.ID].hits, strings.Compare(x.ID, y.ID))
	})
	for _, r := range list {
		s := b.stats[r.ID]
		entities := make([]string, 0, len(s.entities))
		for e := range s.entities {
			entities = append(entities, e)
		}
		slices.SortFunc(entities, func(x, y string) int { return cmp.Or(s.entities[y]-s.entities[x], strings.Compare(x, y)) })
		var shown []string
		for i, e := range entities {
			if i == 10 {
				shown = append(shown, fmt.Sprintf("…另 %d 个", len(entities)-10))
				break
			}
			shown = append(shown, fmt.Sprintf("%s(%d)", e, s.entities[e]))
		}
		var samples []string
		for _, evidence := range s.samples {
			ids := make([]string, len(evidence))
			for i, id := range evidence {
				ids[i] = id.String()
			}
			samples = append(samples, strings.Join(ids, " "))
		}
		dimension := map[string]string{temporal.GroupByAsset: "资产", temporal.GroupByAccount: "账号", temporal.GroupByAssetSourceIP: "主机+来源IP"}[s.groupBy]
		fmt.Printf("| %d | %d | %s `%s` | %s | %s | %s |\n", s.hits, r.Severity, strings.ReplaceAll(r.Title, "|", "\\|"), r.ID, cmp.Or(dimension, "—"),
			strings.ReplaceAll(strings.Join(shown, " "), "|", "\\|"), strings.Join(samples, "<br>"))
	}
	reasons := make([]string, 0, len(b.skipped))
	for reason, n := range b.skipped {
		reasons = append(reasons, fmt.Sprintf("%s %d", reason, n))
	}
	slices.Sort(reasons)
	if len(reasons) == 0 {
		reasons = append(reasons, "无")
	}
	fmt.Printf("\n未参与时序求值的候选（覆盖缺口）：%s\n", strings.Join(reasons, "，"))
	b.reportCandidates(rules, to.Sub(from))
}

// reportCandidates 报告候选量：每条被引用的基础规则贡献多少候选（信号规则单独标出），以及单个实体窗口的峰值。
// 线上 Observe 回查 [t − 最大窗口, t + 最大窗口]，最坏是这里峰值（只含 t 之前一个最大窗口）的约两倍，对照 10000 的上限看余量。
func (b *temporalBacktest) reportCandidates(rules []*sigma.Rule, span time.Duration) {
	days := span.Hours() / 24
	fmt.Println("\n| 候选 | 每天 | 类型 | 基础规则 |")
	fmt.Println("|---:|---:|---|---|")
	var ids []string
	for id := range b.byRule {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(x, y string) int { return cmp.Or(b.byRule[y]-b.byRule[x], strings.Compare(x, y)) })
	byID := map[string]*sigma.Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	for _, id := range ids {
		kind, title := "告警", id
		if r := byID[id]; r != nil {
			title = r.Title + " `" + id + "`"
			if r.Signal {
				kind = "信号"
			}
		}
		fmt.Printf("| %d | %.1f | %s | %s |\n", b.byRule[id], float64(b.byRule[id])/days, kind, strings.ReplaceAll(title, "|", "\\|"))
	}
	for _, groupBy := range []string{temporal.GroupByAsset, temporal.GroupByAccount, temporal.GroupByAssetSourceIP} {
		if p, ok := b.peak[groupBy]; ok {
			fmt.Printf("\n%s维度单实体窗口（最大窗口 %s）候选峰值 %d 条：%s，%s\n", map[string]string{temporal.GroupByAsset: "资产", temporal.GroupByAccount: "账号", temporal.GroupByAssetSourceIP: "主机+来源IP"}[groupBy],
				b.snapshot.MaxWindow(), p.size, p.label, p.at.Format(time.RFC3339))
		}
	}
}
