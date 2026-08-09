//go:build integration

package api

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func intelHandler(t *testing.T) (*httptest.Server, *ent.Client) {
	t.Helper()
	_, client := testdb.New(t)
	store := intel.New(client, time.Hour)
	ts := httptest.NewServer(Handler(client, sigma.LoadDir(t.TempDir()), t.TempDir(), response.NewHub(client, false), suppress.New(client, time.Hour), store, nil, nil))
	t.Cleanup(ts.Close)
	return ts, client
}

// 情报批量导入：类型自动识别、重复跳过、空行/注释忽略、默认 source/severity。
func TestAPIIntelImport(t *testing.T) {
	ts, _ := intelHandler(t)

	body := "1.2.3.4\n"
	body += "evil.example.net\n"
	body += "d41d8cd98f00b204e9800998ecf8427e\n"
	body += "evil.example.net\n" // 重复
	body += "\n# comment line\n"
	payload, _ := json.Marshal(map[string]string{"text": body})
	resp, err := postJSON(ts, "/api/intel/import", string(payload))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("import status = %d: %s", resp.StatusCode, out)
	}
	var res map[string]int
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if res["imported"] != 3 {
		t.Errorf("imported = %d, want 3", res["imported"])
	}
	if res["skipped"] != 1 {
		t.Errorf("skipped = %d, want 1", res["skipped"])
	}

	_, body2 := get(t, ts, "/api/intel")
	var rows []map[string]any
	if err := json.Unmarshal(body2, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("应导入 3 条情报，实际 %d", len(rows))
	}
	kindBy := map[string]string{}
	for _, r := range rows {
		kindBy[r["value"].(string)] = r["kind"].(string)
	}
	if kindBy["1.2.3.4"] != "ip" || kindBy["evil.example.net"] != "domain" || kindBy["d41d8cd98f00b204e9800998ecf8427e"] != "hash" {
		t.Errorf("类型自动识别错误: %v", kindBy)
	}
}

// 单条情报创建：非法 kind 拒绝、重复值返回冲突。
func TestAPIIntelCreate(t *testing.T) {
	ts, _ := intelHandler(t)

	r, _ := postJSON(ts, "/api/intel", `{"kind":"ip","value":"5.6.7.8","source":"manual","severity":5}`)
	created, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 201 {
		t.Fatalf("创建 status = %d: %s", r.StatusCode, created)
	}

	r2, _ := postJSON(ts, "/api/intel", `{"kind":"ip","value":"5.6.7.8"}`)
	r2.Body.Close()
	if r2.StatusCode != 409 {
		t.Errorf("重复情报应 409，得到 %d", r2.StatusCode)
	}

	r3, _ := postJSON(ts, "/api/intel", `{"kind":"url","value":"x"}`)
	r3.Body.Close()
	if r3.StatusCode != 400 {
		t.Errorf("非法 kind 应 400，得到 %d", r3.StatusCode)
	}
}
