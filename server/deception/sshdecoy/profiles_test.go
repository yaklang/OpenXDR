package sshdecoy

import (
	"regexp"
	"strings"
	"sync"
	"testing"
)

func TestProfilesDenyAuthenticationAndRecordSelection(t *testing.T) {
	for _, profile := range Profiles() {
		t.Run(profile.ID, func(t *testing.T) {
			cfg := config(t)
			cfg.Template = ""
			cfg.Profile = profile.ID
			var mu sync.Mutex
			var events []Event
			cfg.Record = func(event Event) error {
				mu.Lock()
				defer mu.Unlock()
				events = append(events, event)
				return nil
			}
			server, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			listener, cancel, done := start(t, server)
			banner := attempt(t, listener, cfg.Signer, "profile=pause")
			if len(banner) == 0 || len(banner) > MaxProfileBannerBytes {
				t.Fatalf("策略输出长度不合法：%d", len(banner))
			}
			switch profile.ID {
			case "decoy":
				marker := regexp.MustCompile(`verify-[0-9a-f]{32}`).FindString(banner)
				if marker == "" {
					t.Fatal("诱饵策略缺少一次性标记")
				}
				if !strings.Contains(attempt(t, listener, cfg.Signer, marker), "核实请求已记录") {
					t.Fatal("诱饵标记不能被关联")
				}
			case "pause":
				if banner != templates["operator-close-v1"] {
					t.Fatal("暂停策略偏离已验证模板")
				}
			case "padding":
				if len(banner) != 8192 || strings.Contains(banner, "verify-") || strings.Contains(banner, "<MESSAGE") || strings.Contains(banner, "workflow update") {
					t.Fatal("填充策略不能混入标记或注入指令")
				}
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(events) < 2 {
				t.Fatal("缺少 Banner 与认证事件")
			}
			for _, event := range events {
				if event.Profile != profile.ID || event.Template != profile.Template || event.Attribution != "unconfirmed" {
					t.Fatalf("策略事件归属不正确：%+v", event)
				}
				if event.Kind != "banner_prepared" && event.Kind != "authentication_attempt" && event.Kind != "marker_followed" {
					t.Fatalf("不应凭服务事件推断模型行为：%s", event.Kind)
				}
			}
		})
	}
}

func TestProfilesRejectOverridesAndUnknownNames(t *testing.T) {
	for _, name := range []string{"pause,padding", "custom", "../../pause", "PAUSE"} {
		cfg := config(t)
		cfg.Template = ""
		cfg.Profile = name
		if _, err := New(cfg); err == nil {
			t.Fatalf("接受未知策略：%s", name)
		}
	}
	cfg := config(t)
	cfg.Profile = "padding"
	cfg.Template = "novel-32k-v1"
	if _, err := New(cfg); err == nil {
		t.Fatal("实验模板绕过运行策略输出限制")
	}
}

func TestProfileCatalogCannotBeMutatedByCaller(t *testing.T) {
	catalog := Profiles()
	catalog[0].Template = "novel-32k-v1"
	cfg := config(t)
	cfg.Template = ""
	cfg.Profile = "decoy"
	server, err := New(cfg)
	if err != nil || server.cfg.Template != "identify-v1" {
		t.Fatal("调用方改写了运行策略目录")
	}
}
