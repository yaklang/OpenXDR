package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/event"
	"openxdr/server/internal/cmdorigin"
	"openxdr/server/internal/sigma"
)

type ruleRow struct {
	Kind          string   `json:"kind,omitempty"`
	WindowSeconds int      `json:"windowSeconds,omitempty"`
	Threshold     int      `json:"threshold,omitempty"`
	References    []string `json:"references,omitempty"`
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Author        string   `json:"author,omitempty"`
	Severity      int16    `json:"severity"`
	ClassUID      int      `json:"classUid"`
	Product       string   `json:"product"`
	// Signal 信号规则：只作时序规则输入，命中不单独告警
	Signal bool `json:"signal,omitempty"`
	// 该类别是否有采集源在供数：false 表示规则加载了但撞不到事件
	Ingested   bool     `json:"ingested"`
	Source     string   `json:"source"`
	Tactics    []string `json:"tactics"`
	Techniques []string `json:"techniques"`
}

type backtestHost struct {
	Hostname string `json:"hostname"`
	AssetID  string `json:"assetId,omitempty"`
	Count    int    `json:"count"`
}

type backtestSample struct {
	ID       uuid.UUID       `json:"id"`
	Ts       time.Time       `json:"ts"`
	ClassUID int             `json:"classUid"`
	Source   string          `json:"source"`
	AssetID  *uuid.UUID      `json:"assetId,omitempty"`
	Hostname string          `json:"hostname,omitempty"`
	Raw      json.RawMessage `json:"raw"`
}

type backtestResult struct {
	RuleID        string           `json:"ruleId"`
	Hours         int              `json:"hours"`
	ScannedEvents int              `json:"scannedEvents"`
	Truncated     bool             `json:"truncated"`
	MatchedCount  int              `json:"matchedCount"`
	Hosts         []backtestHost   `json:"hosts"`
	Samples       []backtestSample `json:"samples"`
}

// mapRules 检测面透明化：运营要能看到跑着哪些规则、哪些只是摆设，并支持在控制台直接回测历史热数据。
func mapRules(api *http.ServeMux, db *ent.Client, rules sigma.Catalog) {
	api.HandleFunc("GET /api/rules", func(w http.ResponseWriter, r *http.Request) {
		all := rules.Rules()
		out := make([]ruleRow, len(all))
		available := map[string]bool{}
		for _, rule := range all {
			_, ok := sigma.IngestedClass(rule.ClassUID)
			available[rule.ID] = ok || rule.ClassUID == 0
		}
		for i, rule := range all {
			source, ingested := sigma.IngestedClass(rule.ClassUID)
			// 不限 class 的规则对所有事件求值，永远有数据
			if rule.ClassUID == 0 {
				ingested, source = true, "全部类别"
			}
			if rule.Kind != "" {
				source, ingested = "跨事件（依赖基础规则）", true
				for _, id := range rule.References {
					ingested = ingested && available[id]
				}
			}
			out[i] = ruleRow{
				Kind: rule.Kind, WindowSeconds: rule.WindowSeconds, Threshold: rule.Threshold, References: rule.References,
				ID: rule.ID, Title: rule.Title, Author: rule.Author, Severity: rule.Severity,
				ClassUID: rule.ClassUID, Product: rule.Product, Signal: rule.Signal,
				Ingested: ingested, Source: source,
				Tactics: rule.Tactics, Techniques: rule.Techniques,
			}
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Severity != out[j].Severity {
				return out[i].Severity > out[j].Severity
			}
			return out[i].Title < out[j].Title
		})
		writeJSON(w, out)
	})

	// POST /api/rules/{id}/backtest 在近期热表事件上回测单条基础规则，评估命中率与主机分布。
	api.HandleFunc("POST /api/rules/{id}/backtest", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		targetID := r.PathValue("id")
		var target *sigma.Rule
		for _, rule := range rules.Rules() {
			if rule.ID == targetID {
				target = rule
				break
			}
		}
		if target == nil {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}
		if target.Kind != "" {
			http.Error(w, "跨事件时序规则不支持单事件快速回测", http.StatusBadRequest)
			return
		}

		hours := 24
		if v, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && v >= 1 && v <= 168 {
			hours = v
		}
		const maxScan = 5000
		q := db.Event.Query().
			Where(s.event()...).
			Where(event.TsGTE(time.Now().Add(-time.Duration(hours) * time.Hour))).
			Order(ent.Desc(event.FieldTs)).
			WithAsset().
			Limit(maxScan + 1)
		if target.ClassUID != 0 {
			q = q.Where(event.ClassUID(target.ClassUID))
		}
		rows, err := q.All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		truncated := len(rows) > maxScan
		if truncated {
			rows = rows[:maxScan]
		}

		hostMap := map[string]*backtestHost{}
		samples := make([]backtestSample, 0, 8)
		scanned := 0
		matched := 0

		for _, e := range rows {
			var doc map[string]any
			if err := json.Unmarshal(e.Raw, &doc); err != nil {
				continue
			}
			// 平台指令拉起的进程树不进常规检测，回测口径保持一致
			if _, tagged := cmdorigin.Tag(doc); tagged {
				continue
			}
			scanned++
			var osName, hostname, assetIDStr string
			if a := e.Edges.Asset; a != nil {
				hostname = a.Hostname
				assetIDStr = a.ID.String()
				if a.Os != nil {
					osName = strings.ToLower(*a.Os)
				}
			}
			if !target.Matches(e.ClassUID, osName, doc) {
				continue
			}
			matched++
			key := hostname
			if key == "" {
				key = "(未归属)"
			}
			entry, exists := hostMap[key]
			if !exists {
				entry = &backtestHost{Hostname: key, AssetID: assetIDStr}
				hostMap[key] = entry
			}
			entry.Count++
			if len(samples) < 8 {
				samples = append(samples, backtestSample{
					ID:       e.ID,
					Ts:       e.Ts,
					ClassUID: e.ClassUID,
					Source:   e.Source,
					AssetID:  e.AssetID,
					Hostname: hostname,
					Raw:      e.Raw,
				})
			}
		}

		hosts := make([]backtestHost, 0, len(hostMap))
		for _, h := range hostMap {
			hosts = append(hosts, *h)
		}
		sort.Slice(hosts, func(i, j int) bool {
			if hosts[i].Count != hosts[j].Count {
				return hosts[i].Count > hosts[j].Count
			}
			return hosts[i].Hostname < hosts[j].Hostname
		})

		writeJSON(w, backtestResult{
			RuleID:        target.ID,
			Hours:         hours,
			ScannedEvents: scanned,
			Truncated:     truncated,
			MatchedCount:  matched,
			Hosts:         hosts,
			Samples:       samples,
		})
	})
}
