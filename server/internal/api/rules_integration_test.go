//go:build integration

package api

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

const newRuleYaml = `id: 2b7f3c1a-5d68-4e29-8a30-6c9d4e1f7a52
title: Hunt Rule
description: 来自狩猎的规则
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'evil'
  condition: selection
level: high
`

// POST /api/rules：合法规则落盘到规则目录，非法与重复被拒。
func TestAPIRuleCreate(t *testing.T) {
	_, client := testdb.New(t)
	rulesDir := t.TempDir()
	ts := httptest.NewServer(Handler(client, loadRules(t), rulesDir,
		response.NewHub(client, false), suppress.New(client, time.Hour),
		intel.New(client, time.Hour), nil, nil))
	t.Cleanup(ts.Close)

	body, _ := json.Marshal(map[string]string{"yaml": newRuleYaml})
	resp, err := postJSON(ts, "/api/rules", string(body))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, out)
	}

	path := filepath.Join(rulesDir, "hunt_2b7f3c1a-5d68-4e29-8a30-6c9d4e1f7a52.yml")
	saved, err := os.ReadFile(path)
	if err != nil || string(saved) != newRuleYaml {
		t.Fatalf("规则应原样落盘到 %s (err=%v)", path, err)
	}

	// 编译不过的直接拒绝，不留半成品文件
	bad, _ := json.Marshal(map[string]string{"yaml": "title: broken"})
	resp, err = postJSON(ts, "/api/rules", string(bad))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("非法规则应 400，实际 %d", resp.StatusCode)
	}

	// 与已加载规则撞 ID → 409
	dup, _ := json.Marshal(map[string]string{"yaml": oneRuleYaml})
	resp, err = postJSON(ts, "/api/rules", string(dup))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Errorf("重复规则 ID 应 409，实际 %d", resp.StatusCode)
	}
}
