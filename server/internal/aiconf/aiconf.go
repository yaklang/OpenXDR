// Package aiconf 控制台可改的 AI 与外部情报查询配置。
// 与通知配置同一套做法：控制台保存过的项为准，没保存过的用环境变量；各节点读库并短暂缓存，改完十几秒内全集群生效。
// 密钥用主机凭据同一把 HOST_CREDENTIAL_KEY 加密落库；没配这把钥匙就不接受在控制台保存密钥，绝不明文入库。
package aiconf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/setting"
	"openxdr/server/internal/hostimport"
)

const (
	settingKey = "ai"
	cacheTTL   = 15 * time.Second
)

// Config 生效中的配置
type Config struct {
	BaseURL string
	APIKey  string
	// 事件研判与资产标注用的模型；空表示不启用
	Model string
	// AI 助手与定时任务（Pi）用的模型；空表示不启用
	PiModel string
	// 公网目的地址反向解析
	PTR        bool
	VTKey      string
	AbuseCHKey string
	// VirusTotal 判恶意的引擎数达到这个值，就把地址加入威胁情报；0 不加
	VTAlertMin int
}

// stored 库里存的：字段为空表示没在控制台改过，用环境变量
type stored struct {
	BaseURL    *string `json:"baseUrl,omitempty"`
	Model      *string `json:"model,omitempty"`
	PiModel    *string `json:"piModel,omitempty"`
	PTR        *bool   `json:"ptr,omitempty"`
	VTAlertMin *int    `json:"vtAlertMin,omitempty"`
	// 密文；Sealed 为空表示在控制台清空了
	APIKey     *secret `json:"apiKey,omitempty"`
	VTKey      *secret `json:"vtKey,omitempty"`
	AbuseCHKey *secret `json:"abuseCHKey,omitempty"`
}

type secret struct {
	Sealed []byte `json:"sealed,omitempty"`
	// 末四位，界面上用来认是哪把 key
	Hint string `json:"hint,omitempty"`
}

// Store 读写配置。Vault 为空时可以读写非密钥项，保存密钥会被拒绝
type Store struct {
	DB      *ent.Client
	Vault   *hostimport.Vault
	Default Config

	mu     sync.Mutex
	cached Config
	at     time.Time
}

// Get 当前生效的配置。读库失败沿用上次结果，从没读成功过就用环境变量
func (s *Store) Get(ctx context.Context) Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.at.IsZero() && time.Since(s.at) < cacheTTL {
		return s.cached
	}
	raw, err := s.load(ctx)
	if err != nil {
		slog.Error("读取 AI 配置失败，沿用上次结果", "err", err)
		if s.at.IsZero() {
			return s.Default
		}
		return s.cached
	}
	s.cached, s.at = s.merge(raw), time.Now()
	return s.cached
}

func (s *Store) load(ctx context.Context) (stored, error) {
	var raw stored
	row, err := s.DB.Setting.Get(ctx, settingKey)
	if ent.IsNotFound(err) {
		return raw, nil
	}
	if err != nil {
		return raw, err
	}
	if err := json.Unmarshal(row.Value, &raw); err != nil {
		slog.Error("AI 配置损坏，按未保存处理", "err", err)
		return stored{}, nil
	}
	return raw, nil
}

func (s *Store) merge(raw stored) Config {
	c := s.Default
	if raw.BaseURL != nil {
		c.BaseURL = *raw.BaseURL
	}
	if raw.Model != nil {
		c.Model = *raw.Model
	}
	if raw.PiModel != nil {
		c.PiModel = *raw.PiModel
	}
	if raw.PTR != nil {
		c.PTR = *raw.PTR
	}
	if raw.VTAlertMin != nil {
		c.VTAlertMin = *raw.VTAlertMin
	}
	c.APIKey = s.open(raw.APIKey, "apiKey", c.APIKey)
	c.VTKey = s.open(raw.VTKey, "vtKey", c.VTKey)
	c.AbuseCHKey = s.open(raw.AbuseCHKey, "abuseCHKey", c.AbuseCHKey)
	return c
}

// open 解不开（钥匙换了或没配）就退回环境变量的值并记日志，不拿错的密钥去调用
func (s *Store) open(sec *secret, field, fallback string) string {
	if sec == nil {
		return fallback
	}
	if len(sec.Sealed) == 0 {
		return ""
	}
	plain, err := s.Vault.Open(sec.Sealed, "setting:ai:"+field)
	if err != nil {
		slog.Error("控制台保存的密钥无法解密，使用环境变量", "field", field)
		return fallback
	}
	return plain.Password
}

// usable 控制台存的密钥解不开时当作没存：实际生效的是环境变量，界面上的来源与末四位也得跟着它
func (s *Store) usable(sec *secret, field string) *secret {
	if sec == nil || len(sec.Sealed) == 0 {
		return sec
	}
	if _, err := s.Vault.Open(sec.Sealed, "setting:ai:"+field); err != nil {
		return nil
	}
	return sec
}

// View 给界面看的：密钥只说有没有、末四位，每项标明来自控制台还是环境变量
type View struct {
	BaseURL        string            `json:"baseUrl"`
	Model          string            `json:"model"`
	PiModel        string            `json:"piModel"`
	PTR            bool              `json:"ptr"`
	VTAlertMin     int               `json:"vtAlertMin"`
	APIKeySet      bool              `json:"apiKeySet"`
	APIKeyHint     string            `json:"apiKeyHint,omitempty"`
	VTKeySet       bool              `json:"vtKeySet"`
	VTKeyHint      string            `json:"vtKeyHint,omitempty"`
	AbuseCHKeySet  bool              `json:"abuseCHKeySet"`
	AbuseCHKeyHint string            `json:"abuseCHKeyHint,omitempty"`
	Source         map[string]string `json:"source"`
	// 没配 HOST_CREDENTIAL_KEY 时不能在控制台保存密钥
	CanSaveSecrets bool `json:"canSaveSecrets"`
}

func (s *Store) View(ctx context.Context) (View, error) {
	raw, err := s.load(ctx)
	if err != nil {
		return View{}, err
	}
	c := s.merge(raw)
	apiKey, vtKey := s.usable(raw.APIKey, "apiKey"), s.usable(raw.VTKey, "vtKey")
	abuseCHKey := s.usable(raw.AbuseCHKey, "abuseCHKey")
	src := map[string]string{}
	mark := func(name string, set bool) {
		src[name] = map[bool]string{true: "console", false: "env"}[set]
	}
	mark("baseUrl", raw.BaseURL != nil)
	mark("model", raw.Model != nil)
	mark("piModel", raw.PiModel != nil)
	mark("ptr", raw.PTR != nil)
	mark("vtAlertMin", raw.VTAlertMin != nil)
	mark("apiKey", apiKey != nil)
	mark("vtKey", vtKey != nil)
	mark("abuseCHKey", abuseCHKey != nil)
	return View{
		BaseURL: c.BaseURL, Model: c.Model, PiModel: c.PiModel, PTR: c.PTR, VTAlertMin: c.VTAlertMin,
		APIKeySet: c.APIKey != "", APIKeyHint: hintOf(apiKey, c.APIKey), VTKeySet: c.VTKey != "", VTKeyHint: hintOf(vtKey, c.VTKey),
		AbuseCHKeySet: c.AbuseCHKey != "", AbuseCHKeyHint: hintOf(abuseCHKey, c.AbuseCHKey),
		Source: src, CanSaveSecrets: s.Vault != nil,
	}, nil
}

func hintOf(sec *secret, plain string) string {
	if sec != nil {
		return sec.Hint
	}
	return tail(plain)
}

func tail(s string) string {
	if len(s) < 8 {
		return ""
	}
	return s[len(s)-4:]
}

// Patch 一次修改：nil 不动；Reset 里列出的项回到环境变量。密钥传空串表示清空
type Patch struct {
	BaseURL    *string  `json:"baseUrl"`
	Model      *string  `json:"model"`
	PiModel    *string  `json:"piModel"`
	PTR        *bool    `json:"ptr"`
	VTAlertMin *int     `json:"vtAlertMin"`
	APIKey     *string  `json:"apiKey"`
	VTKey      *string  `json:"vtKey"`
	AbuseCHKey *string  `json:"abuseCHKey"`
	Reset      []string `json:"reset"`
}

var ErrNoVault = errors.New("未配置 HOST_CREDENTIAL_KEY，不能在控制台保存密钥，请改用环境变量")

// Check 校验修改，不合法直接拒绝
func (p Patch) Check() error {
	if p.BaseURL != nil {
		if u, err := url.Parse(*p.BaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("推理服务地址必须是 http(s) 链接")
		}
	}
	for _, m := range []*string{p.Model, p.PiModel} {
		if m != nil && (len(*m) > 128 || strings.ContainsAny(*m, " \t\r\n")) {
			return errors.New("模型名不超过 128 个字符且不含空白")
		}
	}
	for _, k := range []*string{p.APIKey, p.VTKey, p.AbuseCHKey} {
		if k != nil && (len(*k) > 512 || strings.ContainsAny(*k, " \t\r\n")) {
			return errors.New("密钥不超过 512 个字符且不含空白")
		}
	}
	if p.VTAlertMin != nil && (*p.VTAlertMin < 0 || *p.VTAlertMin > 100) {
		return errors.New("VirusTotal 告警阈值取 0–100")
	}
	for _, r := range p.Reset {
		if !resettable[r] {
			return fmt.Errorf("不能重置 %s", r)
		}
	}
	return nil
}

var resettable = map[string]bool{"baseUrl": true, "model": true, "piModel": true, "ptr": true, "vtAlertMin": true, "apiKey": true, "vtKey": true, "abuseCHKey": true}

func (s *Store) Save(ctx context.Context, p Patch) error {
	if err := p.Check(); err != nil {
		return err
	}
	raw, err := s.load(ctx)
	if err != nil {
		return err
	}
	if p.BaseURL != nil {
		v := strings.TrimRight(*p.BaseURL, "/")
		raw.BaseURL = &v
	}
	if p.Model != nil {
		raw.Model = p.Model
	}
	if p.PiModel != nil {
		raw.PiModel = p.PiModel
	}
	if p.PTR != nil {
		raw.PTR = p.PTR
	}
	if p.VTAlertMin != nil {
		raw.VTAlertMin = p.VTAlertMin
	}
	for _, k := range []struct {
		in    *string
		field string
		out   **secret
	}{{p.APIKey, "apiKey", &raw.APIKey}, {p.VTKey, "vtKey", &raw.VTKey}, {p.AbuseCHKey, "abuseCHKey", &raw.AbuseCHKey}} {
		if k.in == nil {
			continue
		}
		if *k.in == "" {
			*k.out = &secret{}
			continue
		}
		if s.Vault == nil {
			return ErrNoVault
		}
		sealed, err := s.Vault.Seal(hostimport.Secret{Password: *k.in}, "setting:ai:"+k.field)
		if err != nil {
			return err
		}
		*k.out = &secret{Sealed: sealed, Hint: tail(*k.in)}
	}
	for _, r := range p.Reset {
		switch r {
		case "baseUrl":
			raw.BaseURL = nil
		case "model":
			raw.Model = nil
		case "piModel":
			raw.PiModel = nil
		case "ptr":
			raw.PTR = nil
		case "vtAlertMin":
			raw.VTAlertMin = nil
		case "apiKey":
			raw.APIKey = nil
		case "vtKey":
			raw.VTKey = nil
		case "abuseCHKey":
			raw.AbuseCHKey = nil
		}
	}
	value, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	n, err := s.DB.Setting.Update().Where(setting.IDEQ(settingKey)).SetValue(value).Save(ctx)
	if err == nil && n == 0 {
		err = s.DB.Setting.Create().SetID(settingKey).SetValue(value).Exec(ctx)
	}
	if err != nil {
		return err
	}
	// 本节点立即生效；其他节点等缓存过期
	s.mu.Lock()
	s.at = time.Time{}
	s.mu.Unlock()
	return nil
}

// Preview 当前生效配置叠上一份还没保存的修改，供「测试连接」用；不落库
func (s *Store) Preview(ctx context.Context, p Patch) (Config, error) {
	if err := p.Check(); err != nil {
		return Config{}, err
	}
	c := s.Get(ctx)
	for _, r := range p.Reset {
		switch r {
		case "baseUrl":
			c.BaseURL = s.Default.BaseURL
		case "model":
			c.Model = s.Default.Model
		case "piModel":
			c.PiModel = s.Default.PiModel
		case "apiKey":
			c.APIKey = s.Default.APIKey
		case "vtKey":
			c.VTKey = s.Default.VTKey
		case "abuseCHKey":
			c.AbuseCHKey = s.Default.AbuseCHKey
		}
	}
	for _, f := range []struct{ in, out *string }{{p.BaseURL, &c.BaseURL}, {p.Model, &c.Model}, {p.PiModel, &c.PiModel}, {p.APIKey, &c.APIKey}, {p.VTKey, &c.VTKey}, {p.AbuseCHKey, &c.AbuseCHKey}} {
		if f.in != nil {
			*f.out = *f.in
		}
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	return c, nil
}
