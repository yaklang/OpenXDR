//go:build integration

package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"openxdr/server/internal/aiconf"
	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/notify"
	"openxdr/server/internal/testdb"
	"strings"
	"testing"
)

func TestProviderModelsUseStoredOwnKey(t *testing.T) {
	ctx, db := testdb.New(t)
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" || r.Header.Get("Authorization") != "Bearer backup-secret" {
			t.Error("候选服务地址或密钥不匹配")
		}
		w.Write([]byte(`{"data":[{"id":"backup-model"}]}`))
	}))
	defer model.Close()
	vault, err := hostimport.NewVault(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))))
	if err != nil {
		t.Fatal(err)
	}
	store := &aiconf.Store{DB: db, Vault: vault, Default: aiconf.Config{APIKey: "primary-secret", BaseURL: "http://unused-primary"}}
	key := "backup-secret"
	providers := []aiconf.ProviderPatch{{ID: "backup", Name: "备用", BaseURL: model.URL + "/v1", APIKey: &key, Model: "backup-model", Enabled: true}}
	if err := store.Save(ctx, aiconf.Patch{Providers: &providers}); err != nil {
		t.Fatal(err)
	}
	settings := &notify.Settings{DB: db}
	server := httptest.NewServer(Settings(db, settings, &notify.Webhook{Settings: settings}, store, nil))
	defer server.Close()
	resp, err := http.Post(server.URL+"/api/settings/ai/models", "application/json", strings.NewReader(`{"providerId":"backup"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result struct {
		Models []string `json:"models"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != 200 || len(result.Models) != 1 || result.Models[0] != "backup-model" {
		t.Fatalf("目录请求失败: %d", resp.StatusCode)
	}
	if store.Get(ctx).BaseURL != "http://unused-primary" {
		t.Fatal("目录请求不应修改主服务配置")
	}
}
