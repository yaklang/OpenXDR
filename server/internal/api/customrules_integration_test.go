//go:build integration

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/customrule"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
)

const testCustomRule = `title: Custom Marker
id: 7c1d2e3f-0000-4000-8000-00000000c0de
level: high
logsource:
  category: process_creation
  product: linux
detection:
  sel:
    CommandLine|contains: 'custom-marker'
  condition: sel
`

// 新建即生效、改关闭即失效、删掉即消失；写坏、重名、改 id 都拒绝；草稿能直接回测
func TestCustomRulesLifecycle(t *testing.T) {
	ctx, client := testdb.New(t)
	base, err := sigma.CompileSources(map[string]string{"base-1": strings.NewReplacer(
		"7c1d2e3f-0000-4000-8000-00000000c0de", "base-1", "Custom Marker", "Base").Replace(testCustomRule)})
	if err != nil {
		t.Fatal(err)
	}
	overlay := &sigma.Overlay{Base: base}
	loader := &customrule.Loader{DB: client, Rules: overlay}
	ts := httptest.NewServer(asAdmin(CustomRules(client, overlay, loader)))
	t.Cleanup(ts.Close)

	asset := client.Asset.Create().SetHostname("web").SetOs("linux").SaveX(ctx)
	client.Event.Create().SetTs(time.Now()).SetClassUID(1007).SetSource("agent").SetAssetID(asset.ID).
		SetRaw(json.RawMessage(`{"process":{"cmd_line":"sh -c custom-marker"}}`)).ExecX(ctx)

	body, _ := json.Marshal(customRuleBody{Content: testCustomRule, Enabled: true})
	resp, out := doJSON(t, ts, "POST", "/api/custom-rules/check?hours=1", string(body))
	var bt backtestResult
	if resp.StatusCode != http.StatusOK || json.Unmarshal(out, &bt) != nil || bt.MatchedCount != 1 {
		t.Fatalf("草稿回测应命中 1 条: %d %s", resp.StatusCode, out)
	}
	if overlay.TitleOf("7c1d2e3f-0000-4000-8000-00000000c0de") != "" {
		t.Fatal("回测不应让草稿生效")
	}

	if code := send(t, ts, "POST", "/api/custom-rules", string(body)); code != http.StatusOK {
		t.Fatalf("新建: %d", code)
	}
	raw := map[string]any{"process": map[string]any{"cmd_line": "custom-marker"}}
	if hits := overlay.Evaluate(1007, "linux", raw); len(hits) != 2 {
		t.Fatalf("保存后本节点立即生效: %d", len(hits))
	}
	if code := send(t, ts, "POST", "/api/custom-rules", string(body)); code != http.StatusConflict {
		t.Errorf("同 id 再建应 409: %d", code)
	}
	bad, _ := json.Marshal(customRuleBody{Content: strings.Replace(testCustomRule, "7c1d2e3f-0000-4000-8000-00000000c0de", "base-1", 1)})
	if code := send(t, ts, "POST", "/api/custom-rules", string(bad)); code != http.StatusBadRequest {
		t.Errorf("与内置规则重名应 400: %d", code)
	}
	if code := send(t, ts, "PUT", "/api/custom-rules/7c1d2e3f-0000-4000-8000-00000000c0de", string(bad)); code != http.StatusBadRequest {
		t.Errorf("不能改 id: %d", code)
	}

	off, _ := json.Marshal(customRuleBody{Content: testCustomRule, Enabled: false})
	if code := send(t, ts, "PUT", "/api/custom-rules/7c1d2e3f-0000-4000-8000-00000000c0de", string(off)); code != http.StatusOK {
		t.Fatalf("停用: %d", code)
	}
	if hits := overlay.Evaluate(1007, "linux", raw); len(hits) != 1 {
		t.Fatalf("停用后不再命中: %d", len(hits))
	}
	_, out = get(t, ts, "/api/custom-rules")
	var list []customRuleRow
	if json.Unmarshal(out, &list) != nil || len(list) != 1 || list[0].Title != "Custom Marker" || list[0].Enabled || list[0].CreatedBy != "admin" {
		t.Fatalf("列表: %s", out)
	}

	if code := send(t, ts, "DELETE", "/api/custom-rules/7c1d2e3f-0000-4000-8000-00000000c0de", ""); code != http.StatusNoContent {
		t.Fatalf("删除: %d", code)
	}
	if code := send(t, ts, "DELETE", "/api/custom-rules/7c1d2e3f-0000-4000-8000-00000000c0de", ""); code != http.StatusNotFound {
		t.Errorf("再删应 404: %d", code)
	}
}

func doJSON(t *testing.T, ts *httptest.Server, method, path, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf strings.Builder
	_, _ = io.Copy(&buf, resp.Body)
	return resp, []byte(buf.String())
}
