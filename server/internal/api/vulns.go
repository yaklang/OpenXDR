package api

import (
	"cmp"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/internal/assetmap"
	"openxdr/server/internal/vuln"
)

type exposedPackage struct {
	Source   string   `json:"source"`
	Binaries []string `json:"binaries"`
	MaxScore float64  `json:"maxScore"`
	Vulns    int      `json:"vulns"`
	FixedIn  string   `json:"fixedIn,omitempty"`
}

type vulnReport struct {
	vuln.Report
	SoftwareAt *time.Time   `json:"softwareAt"`
	Sync       *vuln.Status `json:"sync"`
}

// vulnReportOf 一台资产的漏洞报告；没有软件清单返回 nil；未支持的生态保留包数，Ecosystem 为空
func vulnReportOf(r *http.Request, sqlDB *sql.DB, db *ent.Client, a *ent.Asset) (*vulnReport, error) {
	if len(a.Software) == 0 {
		return nil, nil
	}
	var sw assetmap.Software
	if err := json.Unmarshal(a.Software, &sw); err != nil {
		return nil, nil
	}
	var listening []assetmap.Listener
	_ = json.Unmarshal(a.Listening, &listening)
	rep, err := vuln.Match(r.Context(), sqlDB, &sw, listening)
	if err != nil {
		return nil, err
	}
	out := &vulnReport{Report: rep, SoftwareAt: a.SoftwareAt}
	if st, ok := vuln.LoadStatus(r.Context(), db)[rep.Ecosystem]; ok {
		out.Sync = &st
	}
	return out, nil
}

// Vulns 软件漏洞：单台资产的详细报告，与给攻击面用的按资产汇总；都按资产所在组鉴权
func Vulns(db *ent.Client, sqlDB *sql.DB) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/assets/{id}/vulns", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "无效的资产 id", http.StatusBadRequest)
			return
		}
		if !assetInScope(w, r, db, id, "viewer") {
			return
		}
		a, err := db.Asset.Get(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		rep, err := vulnReportOf(r, sqlDB, db, a)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rep)
	})
	mux.HandleFunc("GET /api/vulns/summary", func(w http.ResponseWriter, r *http.Request) {
		s, ok := requireScope(w, r, db, "viewer")
		if !ok {
			return
		}
		assets, err := db.Asset.Query().Where(s.asset()...).Where(entasset.SoftwareNotNil()).Limit(500).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type row struct {
			AssetID uuid.UUID `json:"assetId"`
			// 可升级修复的包数、其中最高分 ≥ 7 的、暴露在外的；暂无修复的包数
			Fixable  int     `json:"fixable"`
			High     int     `json:"high"`
			Exposed  int     `json:"exposed"`
			Unfixed  int     `json:"unfixed"`
			MaxScore float64 `json:"maxScore"`
			// 暴露在外的有漏洞的包：二进制包名用来对攻击面上的服务
			ExposedPackages []exposedPackage `json:"exposedPackages"`
		}
		out := []row{}
		for _, a := range assets {
			rep, err := vulnReportOf(r, sqlDB, db, a)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if rep == nil || rep.Ecosystem == "" {
				continue
			}
			x := row{AssetID: a.ID, Fixable: len(rep.Fixable), Unfixed: len(rep.Unfixed)}
			// 同一个源码包可能既有可修复也有暂无修复的漏洞，暴露面按源码包合并成一条
			bySource := map[string]int{}
			for _, p := range append(append([]vuln.Package{}, rep.Fixable...), rep.Unfixed...) {
				x.MaxScore = max(x.MaxScore, p.MaxScore)
				if !p.Exposed {
					continue
				}
				if i, ok := bySource[p.Source]; ok {
					e := &x.ExposedPackages[i]
					e.MaxScore, e.Vulns = max(e.MaxScore, p.MaxScore), e.Vulns+len(p.Vulns)
					e.FixedIn = cmp.Or(e.FixedIn, p.FixedIn)
					continue
				}
				bySource[p.Source] = len(x.ExposedPackages)
				x.ExposedPackages = append(x.ExposedPackages, exposedPackage{p.Source, p.Binaries, p.MaxScore, len(p.Vulns), p.FixedIn})
			}
			x.Exposed = len(x.ExposedPackages)
			for _, p := range rep.Fixable {
				if p.MaxScore >= 7 {
					x.High++
				}
			}
			out = append(out, x)
		}
		writeJSON(w, out)
	})
	return mux
}
