//go:build integration

package api

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/aiconf"
	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/notify"
	"openxdr/server/internal/testdb"
)

// AI 设置：默认来自环境变量；控制台改过的项覆盖并标明来源；没配钥匙不收密钥，配了钥匙密钥加密落库；
// 恢复默认回到环境变量；测试连接用未保存的值；用量按用途汇总 Pi 会话与平台自己的调用。
func TestAISettings(t *testing.T) {
	ctx, client := testdb.New(t)
	sqlDB, err := sql.Open("pgx", os.Getenv("INTEGRATION_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	def := aiconf.Config{BaseURL: "http://env-llm/v1", Model: "env-model", APIKey: "env-key-12345678", PTR: true, VTAlertMin: 3}
	noVault := &aiconf.Store{DB: client, Default: def}
	settings := &notify.Settings{DB: client}
	serve := func(store *aiconf.Store) func(method, path, body string) (*http.Response, map[string]any) {
		ts := httptest.NewServer(Settings(client, settings, &notify.Webhook{Settings: settings}, store, sqlDB))
		t.Cleanup(ts.Close)
		return func(method, path, body string) (*http.Response, map[string]any) {
			req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			var out map[string]any
			_ = json.Unmarshal(raw, &out)
			return resp, out
		}
	}
	do := serve(noVault)

	_, v := do("GET", "/api/settings/ai", "")
	if v["model"] != "env-model" || v["apiKeySet"] != true || v["apiKeyHint"] != "5678" || v["canSaveSecrets"] != false || v["source"].(map[string]any)["model"] != "env" {
		t.Fatalf("默认应来自环境变量: %v", v)
	}
	if resp, _ := do("PUT", "/api/settings/ai", `{"apiKey":"sk-new-abcdefgh"}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("没配钥匙应拒绝保存密钥，得到 %d", resp.StatusCode)
	}
	if resp, _ := do("PUT", "/api/settings/ai", `{"baseUrl":"ftp://x"}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("非 http(s) 地址应拒绝，得到 %d", resp.StatusCode)
	}
	if resp, v := do("PUT", "/api/settings/ai", `{"model":"glm-5","piModel":"glm-5-pi","baseUrl":"http://llm/v1/","vtAlertMin":5}`); resp.StatusCode != 200 ||
		v["model"] != "glm-5" || v["baseUrl"] != "http://llm/v1" || v["source"].(map[string]any)["model"] != "console" {
		t.Fatalf("保存后应覆盖并标明来源: %d %v", resp.StatusCode, v)
	}
	if c := noVault.Get(ctx); c.Model != "glm-5" || c.PiModel != "glm-5-pi" || c.VTAlertMin != 5 || c.APIKey != "env-key-12345678" {
		t.Fatalf("生效配置不对: %+v", c)
	}

	// 配了钥匙：密钥加密落库，库里看不到明文
	vault, err := hostimport.NewVault(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	withVault := &aiconf.Store{DB: client, Vault: vault, Default: def}
	do = serve(withVault)
	if resp, v := do("PUT", "/api/settings/ai", `{"apiKey":"sk-console-abcdefgh","vtKey":"vt-console-12345678","abuseCHKey":"abuse-console-87654321"}`); resp.StatusCode != 200 || v["apiKeyHint"] != "efgh" || v["vtKeySet"] != true || v["abuseCHKeySet"] != true || v["abuseCHKeyHint"] != "4321" {
		t.Fatalf("保存密钥失败: %d %v", resp.StatusCode, v)
	}
	row, _ := client.Setting.Get(ctx, "ai")
	if strings.Contains(string(row.Value), "sk-console") || strings.Contains(string(row.Value), "vt-console") || strings.Contains(string(row.Value), "abuse-console") {
		t.Fatal("密钥不应明文入库")
	}
	if c := withVault.Get(ctx); c.APIKey != "sk-console-abcdefgh" || c.VTKey != "vt-console-12345678" || c.AbuseCHKey != "abuse-console-87654321" {
		t.Fatalf("密钥解密不对: %+v", c)
	}
	if resp, v := do("PUT", "/api/settings/ai", `{"reset":["apiKey","model"]}`); resp.StatusCode != 200 || v["model"] != "env-model" || v["apiKeyHint"] != "5678" {
		t.Fatalf("恢复默认应回到环境变量: %d %v", resp.StatusCode, v)
	}

	// 测试连接：用表单里还没保存的地址与模型
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Model string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/v1/chat/completions" || body.Model != "try-model" || r.Header.Get("Authorization") != "Bearer env-key-12345678" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`))
	}))
	defer llm.Close()
	if resp, v := do("POST", "/api/settings/ai/test", `{"target":"model","baseUrl":"`+llm.URL+`/v1","model":"try-model"}`); resp.StatusCode != 200 || v["reply"] != "OK" {
		t.Fatalf("测试连接应用未保存的值: %d %v", resp.StatusCode, v)
	}
	if resp, _ := do("POST", "/api/settings/ai/test", `{"target":"model","baseUrl":"`+llm.URL+`/v1","model":"wrong"}`); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("调用失败应返回 502，得到 %d", resp.StatusCode)
	}

	// 用量：Pi 会话按会话类型，平台调用按用途
	group, _ := client.Group.Create().SetName("g1").Save(ctx)
	session, _ := client.AgentSession.Create().SetKind("chat").SetGroupID(group.ID).SetInitiator("admin").SetModel("glm-5-pi").SetTitle("排查").SetStatus("idle").Save(ctx)
	for i, usage := range []string{`{"input":100,"output":20,"cacheRead":50}`, `{"input":300,"output":40,"cacheRead":0}`} {
		if err := client.SessionMessage.Create().SetSessionID(session.ID).SetSeq(i + 1).SetRole("assistant").
			SetContent(json.RawMessage(`{"role":"assistant","model":"glm-5-pi","usage":` + usage + `}`)).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	_ = client.SessionMessage.Create().SetSessionID(session.ID).SetSeq(3).SetRole("user").SetContent(json.RawMessage(`{"role":"user"}`)).Exec(ctx)
	aiconf.Recorder(client, "triage")("glm-5", 1000, 200)
	aiconf.Recorder(client, "triage")("glm-5", 500, 100)
	resp, err := http.Get(httptest.NewServer(Settings(client, settings, &notify.Webhook{Settings: settings}, withVault, sqlDB)).URL + "/api/settings/ai/usage?days=7&tz=Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	var usage aiconf.Overview
	_ = json.NewDecoder(resp.Body).Decode(&usage)
	resp.Body.Close()
	by := map[string]aiconf.UsageRow{}
	for _, r := range usage.Rows {
		by[r.Feature] = r
	}
	today := time.Now().In(mustLoc(t, "Asia/Shanghai")).Format(time.DateOnly)
	if c := by["chat"]; c.Input != 400 || c.Output != 60 || c.CacheRead != 50 || c.Calls != 2 || c.Day != today || c.Model != "glm-5-pi" {
		t.Fatalf("Pi 用量不对: %+v", c)
	}
	if tr := by["triage"]; tr.Input != 1500 || tr.Output != 300 || tr.Calls != 2 {
		t.Fatalf("研判用量不对: %+v", tr)
	}
	if len(usage.Top) != 1 || usage.Top[0].Tokens != 460 || usage.Top[0].Group != "g1" || usage.Top[0].Title != "排查" {
		t.Fatalf("会话排行不对: %+v", usage.Top)
	}
}

func mustLoc(t *testing.T, name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}
