//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"openxdr/server/internal/sigma"
)

// 带 ATT&CK 战术/技术标签的规则。
const attackRuleYaml = `
id: 11111111-2222-3333-4444-555555555555
title: Misuse via attack technique
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    target.process.name: 'evil'
  condition: selection
tags:
  - attack.initial_access
  - attack.t1190
`

// 无标签规则。
const untaggedRuleYaml = `
id: aaaaaaaa-9999-8888-7777-666666666666
title: Untagged noise
logsource:
  category: process_creation
detection:
  selection:
    target.process.name: 'noise'
  condition: selection
`

// mapAttack 聚合：带标签的规则归入对应战术与技术，无标签的计为 untagged，
// 全部战术都会出现在矩阵里（空列也是要看的东西）。
func TestAPIAttackCoverage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "attack.yml"), []byte(attackRuleYaml), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "untagged.yml"), []byte(untaggedRuleYaml), 0o644); err != nil {
		t.Fatal(err)
	}
	rules := sigma.LoadDir(dir)

	mux := http.NewServeMux()
	mapAttack(mux, rules)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/attack")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var cov attackCoverage
	if err := json.NewDecoder(resp.Body).Decode(&cov); err != nil {
		t.Fatal(err)
	}

	if cov.Untagged != 1 {
		t.Errorf("untagged = %d, want 1", cov.Untagged)
	}

	// 找到 initial_access 战术列，确认 t1190 挂上去且规则数正确。
	var found bool
	for _, col := range cov.Tactics {
		if col.Tactic != "initial-access" {
			continue
		}
		found = true
		if col.Rules != 1 {
			t.Errorf("initial_access 战术规则数 = %d, want 1", col.Rules)
		}
		var tech *techniqueCell
		for i := range col.Techniques {
			if col.Techniques[i].ID == "T1190" {
				tech = &col.Techniques[i]
				break
			}
		}
		if tech == nil {
			t.Fatal("t1190 技术应出现在 initial_access 战术下")
		}
		if tech.Rules != 1 {
			t.Errorf("t1190 规则数 = %d, want 1", tech.Rules)
		}
	}
	if !found {
		t.Error("矩阵应包含 initial_access 战术列")
	}
}
