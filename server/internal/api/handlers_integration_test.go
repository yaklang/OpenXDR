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

	"github.com/google/uuid"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

// suppress 规则：GET 空列表；POST 建一条并立即生效；缺规则 ID 拒绝；DELETE 撤下。
func TestAPISuppressionsCRUD(t *testing.T) {
	ts, _ := seed(t)

	// 初始为空
	resp, body := get(t, ts, "/api/suppressions")
	if resp.StatusCode != 200 {
		t.Fatalf("GET status = %d", resp.StatusCode)
	}
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("初始应无抑制规则，实际 %d", len(rows))
	}

	// 缺 ruleId → 400
	r1, err := postJSON(ts, "/api/suppressions", `{"reason":"x"}`)
	if err != nil {
		t.Fatal(err)
	}
	r1.Body.Close()
	if r1.StatusCode != 400 {
		t.Errorf("缺 ruleId 应 400，得到 %d", r1.StatusCode)
	}

	// 建一条（带有效期）
	r2, err := postJSON(ts, "/api/suppressions", `{"ruleId":"6e0c8f0e-9a44-4b4d-9b6e-1f2a5d9c8b7a","reason":"噪声","expiresInDays":7}`)
	if err != nil {
		t.Fatal(err)
	}
	created, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != 201 {
		t.Fatalf("POST status = %d: %s", r2.StatusCode, created)
	}
	var row map[string]any
	if err := json.Unmarshal(created, &row); err != nil {
		t.Fatal(err)
	}
	id := row["id"].(string)
	if row["expiresAt"] == nil {
		t.Error("带有效期应返回 expiresAt")
	}

	// 列表能查到，且带标题（标题只在 GET 归一化时回填）
	_, body2 := get(t, ts, "/api/suppressions")
	var rows2 []map[string]any
	if err := json.Unmarshal(body2, &rows2); err != nil {
		t.Fatal(err)
	}
	if len(rows2) != 1 || rows2[0]["ruleTitle"] != "Sample Rule" {
		t.Errorf("列表应含一条带标题的规则: %v", rows2)
	}

	// DELETE 撤下 → 204
	req, _ := http.NewRequest("DELETE", ts.URL+"/api/suppressions/"+id, nil)
	rd, _ := http.DefaultClient.Do(req)
	rd.Body.Close()
	if rd.StatusCode != 204 {
		t.Errorf("DELETE 应 204，得到 %d", rd.StatusCode)
	}
}

// agent 采集配置：默认空；PUT 归一化后 GET 回读；非法 JSON 拒绝。
func TestAPIAgentConfig(t *testing.T) {
	ts, _ := seed(t)
	assetID := mustAssetID(t, ts)

	// 未设置 → 空配置
	resp, body := get(t, ts, "/api/assets/"+assetID+"/config")
	if resp.StatusCode != 200 {
		t.Fatalf("GET config status = %d", resp.StatusCode)
	}
	if strings.TrimSpace(string(body)) == "" || !strings.Contains(string(body), "{}") {
		t.Errorf("默认配置应为空对象，得到 %s", body)
	}

	// 非法 JSON → 400
	r, _ := doReq(t, ts, http.MethodPut, "/api/assets/"+assetID+"/config", `{invalid`)
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Errorf("非法配置应 400，得到 %d", r.StatusCode)
	}

	// 合法配置 → 返回归一化 JSON
	cfg := `{"collectNetwork":false,"fileWatchDirs":["/etc"]}`
	r2, err := doReq(t, ts, http.MethodPut, "/api/assets/"+assetID+"/config", cfg)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Fatalf("PUT config status = %d", r2.StatusCode)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["collectNetwork"] != false {
		t.Errorf("collectNetwork = %v, want false", got["collectNetwork"])
	}

	// 回读
	_, body3 := get(t, ts, "/api/assets/"+assetID+"/config")
	if !strings.Contains(string(body3), `"fileWatchDirs"`) {
		t.Errorf("配置未持久化，得到 %s", body3)
	}
}

// 用户管理：建用户（密码≥8）、短密码拒绝、重名 409、删号。
func TestAPIUsers(t *testing.T) {
	ts, _ := seed(t)

	// 短密码 → 400
	r, _ := postJSON(ts, "/api/users", `{"username":"alice","password":"short","role":"analyst"}`)
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Errorf("短密码应 400，得到 %d", r.StatusCode)
	}

	// 非法角色 → 400
	r2, _ := postJSON(ts, "/api/users", `{"username":"alice","password":"password123","role":"superadmin"}`)
	r2.Body.Close()
	if r2.StatusCode != 400 {
		t.Errorf("非法角色应 400，得到 %d", r2.StatusCode)
	}

	// 合法建号 → 201
	r3, err := postJSON(ts, "/api/users", `{"username":"alice","password":"password123","role":"analyst"}`)
	if err != nil {
		t.Fatal(err)
	}
	r3.Body.Close()
	if r3.StatusCode != 201 {
		t.Fatalf("建用户应 201，得到 %d", r3.StatusCode)
	}

	// 重名 → 409
	r4, _ := postJSON(ts, "/api/users", `{"username":"alice","password":"password123","role":"viewer"}`)
	r4.Body.Close()
	if r4.StatusCode != 409 {
		t.Errorf("重名应 409，得到 %d", r4.StatusCode)
	}

	// 列表含 alice
	_, body := get(t, ts, "/api/users")
	if !strings.Contains(string(body), "alice") {
		t.Errorf("用户列表应含 alice: %s", body)
	}

	// 审计里应有 user_created
	_, ab := get(t, ts, "/api/audit")
	if !strings.Contains(string(ab), "user_created") {
		t.Errorf("审计应记录 user_created: %s", ab)
	}
}

// 指令下发：非法 kind 拒绝、响应未启用时下发失败（但拒绝而非 500）。
func TestAPICommandIssue(t *testing.T) {
	ctx, client := testdb.New(t)
	asset, err := client.Asset.Create().SetHostname("web01").SetAgentID(uuid.New()).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rules := sigma.LoadDir(t.TempDir())
	ts := httptest.NewServer(Handler(client, rules, t.TempDir(), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil, nil))
	t.Cleanup(ts.Close)

	// 非法 kind → 400
	r, _ := postJSON(ts, "/api/commands", `{"kind":"format_disk","assetId":"`+asset.ID.String()+`"}`)
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Errorf("非法 kind 应 400，得到 %d", r.StatusCode)
	}

	// 响应未启用 → 冲突（能力关闭，非 500）
	r2, _ := postJSON(ts, "/api/commands", `{"kind":"kill_process","assetId":"`+asset.ID.String()+`"}`)
	r2.Body.Close()
	if r2.StatusCode != 409 {
		t.Errorf("响应未启用应 409，得到 %d", r2.StatusCode)
	}
}

func doReq(t *testing.T, ts *httptest.Server, method, path, body string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

func mustAssetID(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	_, body := get(t, ts, "/api/assets")
	var assets []map[string]any
	if err := json.Unmarshal(body, &assets); err != nil {
		t.Fatal(err)
	}
	for _, a := range assets {
		if a["hostname"] == "web01" {
			return a["id"].(string)
		}
	}
	t.Fatal("资产 web01 未找到")
	return ""
}
