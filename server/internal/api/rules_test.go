package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"openxdr/server/ent"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/sigma"
)

type metadataCatalog struct {
	sigma.Engine
	entries []*sigma.Rule
}

func (c *metadataCatalog) Rules() []*sigma.Rule { return c.entries }
func TestTemporalRuleMetadataAndSourceCoverage(t *testing.T) {
	for _, class := range []int{1007, 999999} {
		catalog := &metadataCatalog{entries: []*sigma.Rule{
			{ID: "base", Title: "Base", ClassUID: class, Severity: 2},
			{ID: "sequence", Title: "Ordered activity", Author: "Maintainer", Severity: 4, Kind: "sequence", WindowSeconds: 60, References: []string{"base"}},
		}}
		mux := http.NewServeMux()
		mapRules(mux, nil, catalog)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest("GET", "/api/rules", nil))
		if response.Code != 200 {
			t.Fatal(response.Code)
		}
		var rows []ruleRow
		if err := json.Unmarshal(response.Body.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatal(len(rows))
		}
		row := rows[0]
		if row.ID != "sequence" || row.Kind != "sequence" || row.WindowSeconds != 60 || len(row.References) != 1 || row.Author != "Maintainer" {
			t.Fatalf("元数据丢失: %+v", row)
		}
		if row.Ingested != (class == 1007) {
			t.Fatalf("不能将缺失来源的时序规则标记为有数据: %+v", row)
		}
	}
}

func TestRuleBacktestValidation(t *testing.T) {
	catalog := &metadataCatalog{entries: []*sigma.Rule{
		{ID: "sequence", Title: "Ordered activity", Severity: 4, Kind: "sequence", WindowSeconds: 60},
	}}
	mux := http.NewServeMux()
	mapRules(mux, nil, catalog)
	admin := &ent.User{Username: "admin", Role: "admin"}

	// 未知规则 → 404
	r404 := httptest.NewRecorder()
	req404 := httptest.NewRequest("POST", "/api/rules/missing/backtest", nil)
	mux.ServeHTTP(r404, req404.WithContext(auth.WithUser(req404.Context(), admin)))
	if r404.Code != 404 {
		t.Fatalf("未知规则应返回 404，实际 %d", r404.Code)
	}

	// 时序规则 → 400
	r400 := httptest.NewRecorder()
	req400 := httptest.NewRequest("POST", "/api/rules/sequence/backtest", nil)
	mux.ServeHTTP(r400, req400.WithContext(auth.WithUser(req400.Context(), admin)))
	if r400.Code != 400 {
		t.Fatalf("时序规则回测应返回 400，实际 %d", r400.Code)
	}
}
