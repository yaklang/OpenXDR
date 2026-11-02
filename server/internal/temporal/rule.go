// Package temporal 对已匹配基础规则的事件执行计数与严格时序检测。
// 它不执行查询、不决定授权、不维护进程内历史；持久状态由事务处理器提供。
package temporal

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	id         string
	title      string
	author     string
	kind       string
	window     time.Duration
	references []string
	threshold  int
	severity   int16
	groupBy    string
	minAssets  int
}

// 聚合实体维度：asset 按资产（默认），account 按同组规范化用户名跨资产累计。
const (
	GroupByAsset         = "asset"
	GroupByAccount       = "account"
	GroupByAssetSourceIP = "asset_source_ip"
)

type definition struct {
	ID        string   `yaml:"id"`
	Title     string   `yaml:"title"`
	Author    string   `yaml:"author"`
	Level     string   `yaml:"level"`
	Kind      string   `yaml:"kind"`
	Within    string   `yaml:"within"`
	Rules     []string `yaml:"rules"`
	Threshold int      `yaml:"threshold"`
	GroupBy   string   `yaml:"group_by"`
	MinAssets *int     `yaml:"min_assets"`
}

// Compile 使用 OpenXDR 的时序规则格式，不解释 Sigma 单事件 condition 中的聚合语法。
// references 是当前规则快照的 ID 集合；不存在的基础规则必须拒绝。
func Compile(data []byte, references map[string]bool) (*Rule, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var d definition
	if err := decoder.Decode(&d); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("时序规则必须只有一个 YAML 文档")
	}
	window, err := time.ParseDuration(d.Within)
	if err != nil || window < time.Second || window > 24*time.Hour {
		return nil, fmt.Errorf("within 必须为 1 秒至 24 小时")
	}
	if strings.TrimSpace(d.ID) == "" || references[d.ID] || strings.HasPrefix(d.ID, "xdr:") {
		return nil, fmt.Errorf("时序规则 ID 为空、与基础规则冲突或使用保留的 xdr: 前缀")
	}
	levels := map[string]int16{"": 3, "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
	severity, ok := levels[d.Level]
	if !ok {
		return nil, fmt.Errorf("无效时序规则 level: %q", d.Level)
	}
	switch d.GroupBy {
	case "":
		d.GroupBy = GroupByAsset
	case GroupByAsset, GroupByAccount, GroupByAssetSourceIP:
	default:
		return nil, fmt.Errorf("无效时序规则 group_by: %q", d.GroupBy)
	}
	switch d.Kind {
	case "event_count":
		if len(d.Rules) != 1 || d.Threshold < 2 || d.Threshold > 10000 {
			return nil, fmt.Errorf("event_count 需要一个基础规则及 2 至 10000 的 threshold")
		}
	case "sequence":
		if len(d.Rules) < 2 || len(d.Rules) > 8 || d.Threshold != 0 {
			return nil, fmt.Errorf("sequence 需要 2 至 8 个步骤且不能设置 threshold")
		}
	case "temporal":
		// 不要求顺序的共现：同一规则重复出现没有意义（多次出现用 event_count）
		sorted := slices.Sorted(slices.Values(d.Rules))
		if len(d.Rules) < 2 || len(d.Rules) > 8 || d.Threshold != 0 || len(slices.Compact(sorted)) != len(d.Rules) {
			return nil, fmt.Errorf("temporal 需要 2 至 8 个互不相同的基础规则且不能设置 threshold")
		}
	default:
		return nil, fmt.Errorf("不支持的时序规则类型 %q", d.Kind)
	}
	// min_assets：计数窗口内参与计数的事件须来自至少 N 台不同资产。只有账号维度能跨资产，
	// 资产维度写大于 1 的值永远无法满足，按配置错误拒绝而不是静默不出命中。
	minAssets := 1
	if d.MinAssets != nil {
		minAssets = *d.MinAssets
		switch {
		case d.Kind != "event_count":
			return nil, fmt.Errorf("min_assets 只能用于 event_count")
		case minAssets < 1 || minAssets > 100:
			return nil, fmt.Errorf("min_assets 必须为 1 至 100")
		case minAssets > 1 && d.GroupBy != GroupByAccount:
			return nil, fmt.Errorf("min_assets 大于 1 时 group_by 必须为 account")
		case minAssets > d.Threshold:
			return nil, fmt.Errorf("min_assets 不能大于 threshold")
		}
	}
	for _, id := range d.Rules {
		if !references[id] {
			return nil, fmt.Errorf("未知基础规则 %q", id)
		}
	}
	if strings.TrimSpace(d.Title) == "" {
		d.Title = d.ID
	}
	return &Rule{title: d.Title, author: strings.TrimSpace(d.Author), severity: severity, id: d.ID, kind: d.Kind, window: window, references: append([]string(nil), d.Rules...), threshold: d.Threshold, groupBy: d.GroupBy, minAssets: minAssets}, nil
}
