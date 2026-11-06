//go:build integration

package aiconf

import (
	"encoding/json"
	"openxdr/server/internal/testdb"
	"strings"
	"testing"
)

func TestProvidersEncryptedAndOrdered(t *testing.T) {
	ctx, db := testdb.New(t)
	s := &Store{DB: db, Vault: newVault(t), Default: env}
	key := "provider-secret-12345"
	list := []ProviderPatch{{ID: "a", Name: "内网备用", BaseURL: "https://backup-a/v1", APIKey: &key, Enabled: true, Model: "triage-a", PiModel: "chat-a", FallbackModels: "b,c"}, {ID: "b", Name: "备用二", BaseURL: "http://backup-b/v1", Enabled: false, Model: "x"}}
	if err := s.Save(ctx, Patch{Providers: &list}); err != nil {
		t.Fatal(err)
	}
	row := db.Setting.GetX(ctx, settingKey)
	if strings.Contains(string(row.Value), key) {
		t.Fatal("密钥明文落库")
	}
	c := s.Get(ctx)
	routes := c.Routes(true)
	if len(routes) != 3 || routes[0].Model != "chat-a" || routes[0].APIKey != key || routes[2].Model != "c" {
		t.Fatalf("候选配置不正确: 数量=%d", len(routes))
	}
	v, err := s.View(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), key) || !v.Providers[0].APIKeySet {
		t.Fatal("视图泄密或密钥状态错误")
	}
	list[0].APIKey = nil
	list[0].Name = "改名"
	if err := s.Save(ctx, Patch{Providers: &list}); err != nil || s.Get(ctx).Providers[0].APIKey != key {
		t.Fatal("留空不应丢失密钥")
	}
	previewKey := "unsaved-secret"
	list[0].APIKey = &previewKey
	preview, err := s.Preview(ctx, Patch{Providers: &list})
	if err != nil || preview.Providers[0].APIKey != previewKey || s.Get(ctx).Providers[0].APIKey != key {
		t.Fatal("预览应仅修改内存")
	}
	broken := &Store{DB: db, Vault: newVault(t), Default: env}
	if len(broken.Get(ctx).Routes(true)) != 0 {
		t.Fatal("解密失败不应启用备用服务")
	}
	empty := ""
	list[0].APIKey = &empty
	if err := s.Save(ctx, Patch{Providers: &list}); err != nil || s.Get(ctx).Providers[0].APIKey != "" {
		t.Fatal("显式清空失败")
	}
	list = []ProviderPatch{}
	if err := s.Save(ctx, Patch{Providers: &list}); err != nil || len(s.Get(ctx).Routes(true)) != 0 {
		t.Fatal("删除配置失败")
	}
}
