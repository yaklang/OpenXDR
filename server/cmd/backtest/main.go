// backtest 规则回测：用近 N 天的真实事件把一组规则与内置良性链跑一遍，报告每条内置良性链吸收了多少例行噪声，
// 以及剩余每条规则在这个环境里会响多少次、响在哪些主机、典型样本是什么。
//
// 与线上求值同一口径：同一个规则引擎，同样补上信封上的用户名；平台指令拉起的进程（带 platform_command）
// 线上不进事件，这里单独计数；命中内置已知良性链（rules/benign-chains/*.yml）的低危非高危命中按线上口径压掉并单独统计。
//
// 只读：建议连只读副本。按小时分段流式读取，不把事件攒在内存里；副本上的长查询会和 WAL 回放冲突被取消，
// 分段后每段很短，被取消的段重试。
//
// 用法: DATABASE_URL=... go run ./cmd/backtest [-days 3] [-samples 3] <规则目录>
//
// 时序规则：设 TEMPORAL_RULES_PATH 后，<规则目录> 是配套的基础规则目录（同线上 RULES_PATH），与时序规则整批严格加载，
// 按事件时间顺序回放基础匹配与时序求值（纯内存、只读事务），输出每条时序规则的命中数、按资产/账号分布与样例证据事件 ID。
// 时间范围用 -from/-to（RFC3339），缺省为最近 -days 天：
//
//	DATABASE_URL=... TEMPORAL_RULES_PATH=../temporal-rules go run ./cmd/backtest -from 2026-10-01T00:00:00Z -to 2026-10-04T00:00:00Z ../rules
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"openxdr/server/internal/cmdorigin"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
)

type stat struct {
	rule    *sigma.Rule
	hits    int
	hosts   map[string]int
	samples []string
}

type chainStat struct {
	chain   suppress.BuiltinChain
	hits    int
	hosts   map[string]int
	samples []string
}

func main() {
	days := flag.Int("days", 3, "回测最近几天的事件")
	samples := flag.Int("samples", 3, "每条规则列出几个不同的样本")
	fromFlag := flag.String("from", "", "时序回测起点（RFC3339，仅 TEMPORAL_RULES_PATH 模式）")
	toFlag := flag.String("to", "", "时序回测终点（RFC3339，默认现在，仅 TEMPORAL_RULES_PATH 模式）")
	flag.Parse()
	if flag.NArg() != 1 || os.Getenv("DATABASE_URL") == "" {
		fmt.Fprintln(os.Stderr, "用法: DATABASE_URL=... backtest [-days 3] [-samples 3] <规则目录>")
		os.Exit(2)
	}
	if dir := os.Getenv("TEMPORAL_RULES_PATH"); dir != "" {
		if err := temporalMain(flag.Arg(0), dir, *fromFlag, *toFlag, *days, *samples); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *fromFlag != "" || *toFlag != "" {
		fmt.Fprintln(os.Stderr, "-from/-to 只用于时序回测，需同时设置 TEMPORAL_RULES_PATH")
		os.Exit(2)
	}
	rulesDir := flag.Arg(0)
	engine := sigma.LoadDir(rulesDir)
	rules := engine.Rules()
	if len(rules) == 0 {
		fmt.Fprintln(os.Stderr, "规则目录里没有可加载的规则")
		os.Exit(1)
	}
	chains, err := suppress.LoadBuiltinDir(filepath.Join(rulesDir, "benign-chains"), engine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载内置良性链失败: %v\n", err)
		os.Exit(1)
	}
	if err := run(engine, rules, chains, *days, *samples); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(engine *sigma.Engine, rules []*sigma.Rule, chains []suppress.BuiltinChain, days, samples int) error {
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer db.Close()

	// 只读规则会看的事件类别；不限类别的规则（ClassUID 0）要看全部
	classes := map[int]bool{}
	for _, r := range rules {
		classes[r.ClassUID] = true
	}
	filter := ""
	if !classes[0] {
		ids := make([]string, 0, len(classes))
		for c := range classes {
			ids = append(ids, fmt.Sprint(c))
		}
		filter = " AND e.class_uid IN (" + strings.Join(ids, ",") + ")"
	}

	b := &backtest{
		engine:     engine,
		chains:     chains,
		samples:    samples,
		stats:      map[string]*stat{},
		chainStats: map[string]*chainStat{},
	}
	for _, c := range chains {
		b.chainStats[c.ID] = &chainStat{chain: c, hosts: map[string]int{}}
		if suppress.NeedsLineageConditions(c.Conditions) {
			b.needsLineage = true
		}
	}
	for _, r := range rules {
		b.stats[r.ID] = &stat{rule: r, hosts: map[string]int{}}
	}
	started := time.Now()
	end := started.Truncate(time.Hour).Add(time.Hour)
	for from := end.Add(-time.Duration(days) * 24 * time.Hour); from.Before(end); from = from.Add(time.Hour) {
		var err error
		for attempt := 0; attempt < 5; attempt++ {
			if err = b.scan(db, filter, from, from.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "40001") {
				break
			}
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
		if err != nil {
			return fmt.Errorf("%s 那一小时: %w", from.Format(time.DateTime), err)
		}
	}
	report(b.stats, b.chainStats, b.events, b.commanded, b.suppressed, days, time.Since(started))
	return nil
}

type backtest struct {
	engine       *sigma.Engine
	chains       []suppress.BuiltinChain
	needsLineage bool
	samples      int
	stats        map[string]*stat
	chainStats   map[string]*chainStat
	events       int
	commanded    int
	suppressed   int
}

type candidateEvent struct {
	class      int
	ts         time.Time
	assetID    *uuid.UUID
	parentGUID *uuid.UUID
	osName     string
	host       string
	doc        map[string]any
	alertHits  []*sigma.Rule
	signalHits []*sigma.Rule
}

// scan 一小时的事件过一遍规则。整段成功才计入：被取消重试的段不会重复计数
func (b *backtest) scan(db *sql.DB, filter string, from, to time.Time) error {
	ctx := context.Background()
	rows, err := db.QueryContext(ctx, `SELECT e.class_uid, e.ts, e.asset_id, e.parent_process_guid, e.raw, coalesce(e.username, ''), coalesce(a.os, ''), coalesce(a.hostname, '')
FROM events e LEFT JOIN assets a ON a.id = e.asset_id
WHERE e.ts >= $1 AND e.ts < $2`+filter, from, to)
	if err != nil {
		return err
	}
	var candidates []candidateEvent
	events, commanded := 0, 0
	for rows.Next() {
		var class int
		var ts time.Time
		var assetID, parentGUID uuid.NullUUID
		var raw []byte
		var username, osName, host string
		if err := rows.Scan(&class, &ts, &assetID, &parentGUID, &raw, &username, &osName, &host); err != nil {
			rows.Close()
			return err
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
		sigma.WithActor(doc, username)
		alertHits := b.engine.Evaluate(class, osName, doc)
		signalHits := b.engine.EvaluateSignals(class, osName, doc)
		if len(alertHits) == 0 && len(signalHits) == 0 {
			continue
		}
		var aPtr, pPtr *uuid.UUID
		if assetID.Valid {
			u := assetID.UUID
			aPtr = &u
		}
		if parentGUID.Valid {
			u := parentGUID.UUID
			pPtr = &u
		}
		candidates = append(candidates, candidateEvent{
			class: class, ts: ts, assetID: aPtr, parentGUID: pPtr,
			osName: osName, host: host, doc: doc,
			alertHits: alertHits, signalHits: signalHits,
		})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	type hit struct {
		rule, chain string
		host, text  string
	}
	var hits []hit
	suppressedCount := 0
	for _, c := range candidates {
		text := summary(c.doc)
		var lineage []map[string]any
		if len(c.alertHits) > 0 && c.class == 1007 && b.needsLineage {
			lineage = suppress.ResolveLineage(ctx, db, c.assetID, c.parentGUID, c.ts, c.doc)
		}
		for _, r := range c.alertHits {
			if chainID := b.matchBuiltinChain(r.ID, c.doc, lineage); chainID != "" {
				suppressedCount++
				hits = append(hits, hit{chain: chainID, host: c.host, text: text})
				continue
			}
			hits = append(hits, hit{rule: r.ID, host: c.host, text: text})
		}
		// 信号规则线上不出告警，但回测要看它的量：被时序规则引用后就是候选量
		for _, r := range c.signalHits {
			hits = append(hits, hit{rule: r.ID, host: c.host, text: text})
		}
	}

	b.events += events
	b.commanded += commanded
	b.suppressed += suppressedCount
	for _, h := range hits {
		if h.chain != "" {
			cs := b.chainStats[h.chain]
			cs.hits++
			cs.hosts[h.host]++
			if h.text != "" && len(cs.samples) < b.samples && !slices.Contains(cs.samples, h.text) {
				cs.samples = append(cs.samples, h.text)
			}
			continue
		}
		s := b.stats[h.rule]
		s.hits++
		s.hosts[h.host]++
		if h.text != "" && len(s.samples) < b.samples && !slices.Contains(s.samples, h.text) {
			s.samples = append(s.samples, h.text)
		}
	}
	return nil
}

func (b *backtest) matchBuiltinChain(ruleID string, doc map[string]any, lineage []map[string]any) string {
	for _, ch := range b.chains {
		wildcard := slices.Contains(ch.Rules, suppress.WildcardRule)
		explicit := !wildcard && slices.Contains(ch.Rules, ruleID)
		if !wildcard && !explicit {
			continue
		}
		if !suppress.BuiltinAllowedRule(ruleID, b.engine, explicit) {
			continue
		}
		if suppress.MatchesWithLineage(ch.Conditions, doc, lineage) {
			return ch.ID
		}
	}
	return ""
}

// summary 一条事件最能说明发生了什么的字段：命令行、文件路径、查询域名、连接目标
func summary(doc map[string]any) string {
	get := func(path ...string) string {
		var cur any = doc
		for _, p := range path {
			m, ok := cur.(map[string]any)
			if !ok {
				return ""
			}
			cur = m[p]
		}
		if cur == nil {
			return ""
		}
		return fmt.Sprint(cur)
	}
	text := cmp.Or(get("process", "cmd_line"), get("file", "path"), get("query", "hostname"),
		strings.Trim(get("dst_endpoint", "ip")+":"+get("dst_endpoint", "port"), ":"))
	if r := []rune(text); len(r) > 160 {
		text = string(r[:160]) + "…"
	}
	return strings.ReplaceAll(text, "|", "\\|")
}

func report(stats map[string]*stat, chainStats map[string]*chainStat, events, commanded, suppressed, days int, took time.Duration) {
	list := make([]*stat, 0, len(stats))
	for _, s := range stats {
		list = append(list, s)
	}
	slices.SortFunc(list, func(a, b *stat) int {
		return cmp.Or(b.hits-a.hits, strings.Compare(a.rule.Title, b.rule.Title))
	})
	fmt.Printf("回测 %d 天：%d 条事件（平台指令拉起的 %d 条不计，内置良性链吸收 %d 次规则命中），%d 条规则，耗时 %s\n\n",
		days, events, commanded, suppressed, len(list), took.Round(time.Second))

	if len(chainStats) > 0 {
		chains := make([]*chainStat, 0, len(chainStats))
		for _, cs := range chainStats {
			chains = append(chains, cs)
		}
		slices.SortFunc(chains, func(a, b *chainStat) int {
			return cmp.Or(b.hits-a.hits, strings.Compare(a.chain.ID, b.chain.ID))
		})
		fmt.Println("### 内置已知良性链吸收统计")
		fmt.Println("| 每天吸收 | 总吸收 | 主机 | 内置链 | 样本 |")
		fmt.Println("|---:|---:|---|---|---|")
		for _, cs := range chains {
			hosts := formatHostCounts(cs.hosts)
			fmt.Printf("| %.1f | %d | %s | %s `%s` | %s |\n",
				float64(cs.hits)/float64(days), cs.hits, cmp.Or(hosts, "-"),
				cs.chain.Title, cs.chain.ID, cmp.Or(strings.Join(cs.samples, "<br>"), "-"))
		}
		fmt.Println()
	}

	fmt.Println("| 每天命中 | 主机 | 级别 | 规则 | 样本 |")
	fmt.Println("|---:|---|---:|---|---|")
	silent := 0
	for _, s := range list {
		if s.hits == 0 {
			silent++
			continue
		}
		title := s.rule.Title
		if s.rule.Signal {
			title = "[信号，不告警] " + title
		}
		fmt.Printf("| %.1f | %s | %d | %s `%s` | %s |\n", float64(s.hits)/float64(days), formatHostCounts(s.hosts),
			s.rule.Severity, title, s.rule.ID, strings.Join(s.samples, "<br>"))
	}
	fmt.Printf("\n%d 条规则在回测期内没有命中\n", silent)
}

func formatHostCounts(m map[string]int) string {
	hosts := make([]string, 0, len(m))
	for h, n := range m {
		hosts = append(hosts, fmt.Sprintf("%s(%d)", cmp.Or(h, "?"), n))
	}
	slices.Sort(hosts)
	return strings.Join(hosts, " ")
}
