package aiconf

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/hostimport"
)

func ptr[T any](v T) *T { return &v }

// newVault 随机生成一把 HOST_CREDENTIAL_KEY
func newVault(t *testing.T) *hostimport.Vault {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	v, err := hostimport.NewVault(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func seal(t *testing.T, v *hostimport.Vault, plain, field string) *secret {
	t.Helper()
	sealed, err := v.Seal(hostimport.Secret{Password: plain}, "setting:ai:"+field)
	if err != nil {
		t.Fatal(err)
	}
	return &secret{Sealed: sealed, Hint: tail(plain)}
}

var env = Config{
	BaseURL: "http://env-llm:8000/v1", APIKey: "env-api-key-0001", Model: "env-model", PiModel: "env-pi",
	PTR: true, VTKey: "env-vt-key-0002", VTAlertMin: 5,
}

// 控制台没保存过任何项时，原样使用环境变量
func TestMergeEmptyUsesEnv(t *testing.T) {
	s := &Store{Default: env}
	if got := s.merge(stored{}); got != env {
		t.Fatalf("未保存时应等于环境变量: %+v", got)
	}
}

// 控制台保存过的项一律覆盖环境变量，包括零值：PTR 关掉、阈值 0、模型清空都要生效
func TestMergeConsoleOverridesEnvIncludingZero(t *testing.T) {
	v := newVault(t)
	s := &Store{Default: env, Vault: v}
	got := s.merge(stored{
		BaseURL: ptr("https://console/v1"), Model: ptr(""), PiModel: ptr("pi-2"),
		PTR: ptr(false), VTAlertMin: ptr(0),
		APIKey: seal(t, v, "console-api-key", "apiKey"), VTKey: seal(t, v, "console-vt-key", "vtKey"),
	})
	want := Config{BaseURL: "https://console/v1", Model: "", PiModel: "pi-2", PTR: false, VTAlertMin: 0,
		APIKey: "console-api-key", VTKey: "console-vt-key"}
	if got != want {
		t.Fatalf("控制台值应覆盖环境变量\n got  %+v\n want %+v", got, want)
	}
}

// 只改了部分项时，其余项仍取环境变量
func TestMergePartial(t *testing.T) {
	s := &Store{Default: env}
	got := s.merge(stored{Model: ptr("console-model")})
	want := env
	want.Model = "console-model"
	if got != want {
		t.Fatalf("部分覆盖: %+v", got)
	}
}

// 控制台清空了密钥（Sealed 为空）：即使环境变量有值也视为没有密钥，不偷偷退回环境变量
func TestMergeClearedSecretIsEmpty(t *testing.T) {
	s := &Store{Default: env}
	got := s.merge(stored{APIKey: &secret{}, VTKey: &secret{}})
	if got.APIKey != "" || got.VTKey != "" {
		t.Fatalf("清空的密钥应为空: api=%q vt=%q", got.APIKey, got.VTKey)
	}
}

// 解不开的密文一律退回环境变量，绝不把乱码当密钥用：换了钥匙、没配钥匙、密文被篡改、字段互换
func TestOpenRejectsUndecryptable(t *testing.T) {
	v := newVault(t)
	good := seal(t, v, "console-api-key", "apiKey")
	tampered := &secret{Sealed: append([]byte(nil), good.Sealed...)}
	tampered.Sealed[len(tampered.Sealed)-1] ^= 0x01
	truncated := &secret{Sealed: good.Sealed[:5]}

	cases := []struct {
		name  string
		vault *hostimport.Vault
		sec   *secret
		field string
	}{
		{"换了钥匙", newVault(t), good, "apiKey"},
		{"没配钥匙", nil, good, "apiKey"},
		{"密文被篡改", v, tampered, "apiKey"},
		{"密文被截短", v, truncated, "apiKey"},
		// 密文与字段名绑定：apiKey 的密文挪到 vtKey 上解不开
		{"字段互换", v, good, "vtKey"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Store{Vault: c.vault}
			if got := s.open(c.sec, c.field, "fallback"); got != "fallback" {
				t.Fatalf("应退回环境变量值，实际 %q", got)
			}
		})
	}
	// 对照：同一把钥匙、同一字段能解开
	if got := (&Store{Vault: v}).open(good, "apiKey", "fallback"); got != "console-api-key" {
		t.Fatalf("正常密文应解开，实际 %q", got)
	}
}

// 同一明文两次加密结果不同（随机 nonce），密文里不含明文
func TestSealIsRandomizedAndOpaque(t *testing.T) {
	v := newVault(t)
	a, b := seal(t, v, "sk-plaintext-key", "apiKey"), seal(t, v, "sk-plaintext-key", "apiKey")
	if string(a.Sealed) == string(b.Sealed) {
		t.Fatal("两次加密密文相同，nonce 未随机")
	}
	if strings.Contains(string(a.Sealed), "sk-plaintext-key") {
		t.Fatal("密文中出现明文")
	}
	if a.Hint != "-key" {
		t.Fatalf("hint 应为末四位: %q", a.Hint)
	}
}

// 不足 8 位的密钥不给提示，免得末四位泄露大半
func TestTailAndHint(t *testing.T) {
	for in, want := range map[string]string{"": "", "1234567": "", "12345678": "5678", "sk-abcdefgh": "efgh"} {
		if got := tail(in); got != want {
			t.Errorf("tail(%q)=%q want %q", in, got, want)
		}
	}
	// 控制台保存过就用保存时记下的 hint，否则从环境变量现算
	if got := hintOf(&secret{Hint: "zzzz"}, "env-api-key-0001"); got != "zzzz" {
		t.Errorf("控制台 hint: %q", got)
	}
	if got := hintOf(nil, "env-api-key-0001"); got != "0001" {
		t.Errorf("环境变量 hint: %q", got)
	}
}

func TestPatchCheck(t *testing.T) {
	ok := []Patch{
		{},
		{BaseURL: ptr("http://10.0.0.1:8000/v1")},
		{BaseURL: ptr("https://api.example.com")},
		{Model: ptr(""), PiModel: ptr(strings.Repeat("m", 128))},
		{APIKey: ptr(""), VTKey: ptr(strings.Repeat("k", 512))},
		{VTAlertMin: ptr(0)}, {VTAlertMin: ptr(100)},
		{Reset: []string{"baseUrl", "model", "piModel", "ptr", "vtAlertMin", "apiKey", "vtKey"}},
	}
	for i, p := range ok {
		if err := p.Check(); err != nil {
			t.Errorf("ok[%d] 应通过: %v", i, err)
		}
	}
	bad := map[string]Patch{
		"非 http 协议": {BaseURL: ptr("ftp://host/v1")},
		"无协议":       {BaseURL: ptr("llm.local:8000")},
		"无主机":       {BaseURL: ptr("http:///v1")},
		"空地址":       {BaseURL: ptr("")},
		"模型名带空格":    {Model: ptr("gpt 4")},
		"Pi 模型名超长":  {PiModel: ptr(strings.Repeat("m", 129))},
		"密钥带换行":     {APIKey: ptr("sk-abc\n")},
		"VT 密钥超长":   {VTKey: ptr(strings.Repeat("k", 513))},
		"阈值为负":      {VTAlertMin: ptr(-1)},
		"阈值超 100":   {VTAlertMin: ptr(101)},
		"重置未知项":     {Reset: []string{"password"}},
		"重置项夹带未知项":  {Reset: []string{"model", "Model"}},
	}
	for name, p := range bad {
		if err := p.Check(); err == nil {
			t.Errorf("%s 应被拒绝", name)
		}
	}
}

// 缓存未过期时 Get 直接返回缓存，不碰数据库（DB 为 nil 也不会 panic）
func TestGetServesCache(t *testing.T) {
	s := &Store{Default: env}
	s.cached, s.at = Config{Model: "cached"}, time.Now()
	if got := s.Get(context.Background()); got.Model != "cached" {
		t.Fatalf("应返回缓存: %+v", got)
	}
}

// Preview 在生效配置上叠加未保存的修改：重置回环境变量、修改项覆盖、地址去尾斜杠，不合法的修改直接拒绝
func TestPreview(t *testing.T) {
	s := &Store{Default: env}
	s.cached = Config{BaseURL: "https://console/v1", APIKey: "console-key", Model: "console-model", PiModel: "console-pi", VTKey: "console-vt"}
	s.at = time.Now()
	ctx := context.Background()

	got, err := s.Preview(ctx, Patch{
		Reset:   []string{"model", "apiKey"},
		BaseURL: ptr("https://new-endpoint/v1///"),
		PiModel: ptr("new-pi"),
		VTKey:   ptr(""),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Config{BaseURL: "https://new-endpoint/v1", APIKey: env.APIKey, Model: env.Model, PiModel: "new-pi", VTKey: ""}
	if got != want {
		t.Fatalf("预览结果\n got  %+v\n want %+v", got, want)
	}
	// 预览不落库也不污染缓存
	if s.cached.Model != "console-model" {
		t.Fatalf("预览改动了缓存: %+v", s.cached)
	}
	if _, err := s.Preview(ctx, Patch{BaseURL: ptr("file:///etc/passwd")}); err == nil {
		t.Fatal("非法地址应拒绝预览")
	}
}

func TestThreatBookSecret(t *testing.T) {
	v := newVault(t)
	s := &Store{Vault: v, Default: Config{ThreatBookKey: "env-secret"}}
	if got := s.merge(stored{}).ThreatBookKey; got != "env-secret" {
		t.Fatal("默认密钥未生效")
	}
	if got := s.merge(stored{ThreatBookKey: seal(t, v, "console-secret", "threatBookKey")}).ThreatBookKey; got != "console-secret" {
		t.Fatal("控制台密钥未解密")
	}
	if got := s.merge(stored{ThreatBookKey: &secret{}}).ThreatBookKey; got != "" {
		t.Fatal("显式清空不能回退环境变量")
	}
	if err := (Patch{ThreatBookKey: ptr(strings.Repeat("k", 513))}).Check(); err == nil {
		t.Fatal("超长密钥应拒绝")
	}
	if err := (Patch{Reset: []string{"threatBookKey"}}).Check(); err != nil {
		t.Fatal(err)
	}
}
