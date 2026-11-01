package vuln

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"slices"

	"openxdr/server/ent/schema"
	"openxdr/server/internal/assetmap"
)

// Vuln 一条命中的公告
type Vuln struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
	Summary string   `json:"summary,omitempty"`
	Score   float64  `json:"score"`
	Vector  string   `json:"vector,omitempty"`
	// Fixed 修复版本；空表示发行版还没修
	Fixed string `json:"fixed,omitempty"`
}

// Package 一个源码包的命中情况。Exposed：它的某个二进制包正被对外监听的服务进程使用
type Package struct {
	Source   string   `json:"source"`
	Version  string   `json:"version"`
	Binaries []string `json:"binaries"`
	Exposed  bool     `json:"exposed"`
	MaxScore float64  `json:"maxScore"`
	// FixedIn 升到这个版本就能修掉全部可修的漏洞
	FixedIn string `json:"fixedIn,omitempty"`
	Vulns   []Vuln `json:"vulns"`
}

// Report 一台资产的漏洞情况：可升级修复与暂无修复分开，前者是能马上做的事
type Report struct {
	Ecosystem string    `json:"ecosystem"`
	Packages  int       `json:"packages"`
	Fixable   []Package `json:"fixable"`
	Unfixed   []Package `json:"unfixed"`
}

// Match 软件清单对漏洞库。listening 里带包名的监听服务用来标暴露面（只算非回环监听）
func Match(ctx context.Context, db *sql.DB, sw *assetmap.Software, listening []assetmap.Listener) (Report, error) {
	rep := Report{Ecosystem: Ecosystem(sw.OS, sw.Version), Packages: len(sw.Packages)}
	if sw.Manager != "dpkg" {
		rep.Ecosystem = ""
	}
	if rep.Ecosystem == "" {
		return rep, nil
	}
	type installed struct {
		version  string
		binaries []string
	}
	bySource := map[string]*installed{}
	sourceOf := map[string]string{}
	for _, p := range sw.Packages {
		name, src, srcVer := p[0], p[2], p[3]
		in := bySource[src]
		if in == nil {
			in = &installed{version: srcVer}
			bySource[src] = in
		}
		in.binaries = append(in.binaries, name)
		sourceOf[name] = src
	}
	exposed := map[string]bool{}
	for _, l := range listening {
		if l.Package != "" && !l.Loopback() {
			exposed[sourceOf[l.Package]] = true
		}
	}
	names := make([]string, 0, len(bySource))
	for s := range bySource {
		names = append(names, s)
	}
	rows, err := db.QueryContext(ctx, `SELECT osv_id, package, ranges, aliases, summary, score, vector
FROM vuln_records WHERE ecosystem=$1 AND package = ANY($2)`, rep.Ecosystem, names)
	if err != nil {
		return rep, err
	}
	defer rows.Close()
	fixable, unfixed := map[string]*Package{}, map[string]*Package{}
	for rows.Next() {
		var v Vuln
		var pkg string
		var rangesJSON, aliasesJSON []byte
		var vector sql.NullString
		if err := rows.Scan(&v.ID, &pkg, &rangesJSON, &aliasesJSON, &v.Summary, &v.Score, &vector); err != nil {
			return rep, err
		}
		v.Vector = vector.String
		var ranges []schema.VulnRange
		if json.Unmarshal(rangesJSON, &ranges) != nil {
			continue
		}
		_ = json.Unmarshal(aliasesJSON, &v.Aliases)
		in := bySource[pkg]
		fixed, hit := affected(in.version, ranges)
		if !hit {
			continue
		}
		v.Fixed = fixed
		target := unfixed
		if fixed != "" {
			target = fixable
		}
		p := target[pkg]
		if p == nil {
			p = &Package{Source: pkg, Version: in.version, Binaries: in.binaries, Exposed: exposed[pkg]}
			target[pkg] = p
		}
		p.Vulns = append(p.Vulns, v)
		p.MaxScore = max(p.MaxScore, v.Score)
		if fixed != "" && (p.FixedIn == "" || CompareDeb(fixed, p.FixedIn) > 0) {
			p.FixedIn = fixed
		}
	}
	if err := rows.Err(); err != nil {
		return rep, err
	}
	rep.Fixable, rep.Unfixed = sorted(fixable), sorted(unfixed)
	return rep, nil
}

// affected 已装版本是否落在某个受影响区间里，落在已修复区间时返回修复版本
func affected(version string, ranges []schema.VulnRange) (string, bool) {
	for _, r := range ranges {
		if r.Introduced != "0" && r.Introduced != "" && CompareDeb(version, r.Introduced) < 0 {
			continue
		}
		if r.Fixed == "" {
			return "", true
		}
		if CompareDeb(version, r.Fixed) < 0 {
			return r.Fixed, true
		}
	}
	return "", false
}

// sorted 暴露的在前，其次按最高分、漏洞数
func sorted(m map[string]*Package) []Package {
	out := make([]Package, 0, len(m))
	for _, p := range m {
		slices.SortFunc(p.Vulns, func(a, b Vuln) int { return cmp.Or(cmp.Compare(b.Score, a.Score), cmp.Compare(a.ID, b.ID)) })
		out = append(out, *p)
	}
	slices.SortFunc(out, func(a, b Package) int {
		ea, eb := 0, 0
		if a.Exposed {
			ea = 1
		}
		if b.Exposed {
			eb = 1
		}
		return cmp.Or(eb-ea, cmp.Compare(b.MaxScore, a.MaxScore), cmp.Compare(len(b.Vulns), len(a.Vulns)), cmp.Compare(a.Source, b.Source))
	})
	return out
}
