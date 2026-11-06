package aiconf

import (
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/modelroute"
)

// Provider 单套备用服务。数组让配置缓存可按值复制，避免共享可变切片。
type Provider struct {
	ID, Name, BaseURL, APIKey, Model, PiModel, FallbackModels string
	Enabled                                                   bool
}
type providerStored struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	BaseURL        string  `json:"baseUrl"`
	Model          string  `json:"model"`
	PiModel        string  `json:"piModel"`
	FallbackModels string  `json:"fallbackModels"`
	Enabled        bool    `json:"enabled"`
	APIKey         *secret `json:"apiKey,omitempty"`
}
type ProviderPatch struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	BaseURL        string  `json:"baseUrl"`
	Model          string  `json:"model"`
	PiModel        string  `json:"piModel"`
	FallbackModels string  `json:"fallbackModels"`
	Enabled        bool    `json:"enabled"`
	APIKey         *string `json:"apiKey"`
}
type ProviderView struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	BaseURL        string `json:"baseUrl"`
	Model          string `json:"model"`
	PiModel        string `json:"piModel"`
	FallbackModels string `json:"fallbackModels"`
	Enabled        bool   `json:"enabled"`
	APIKeySet      bool   `json:"apiKeySet"`
	APIKeyHint     string `json:"apiKeyHint,omitempty"`
}

var providerID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,40}$`)

func checkProviders(in []ProviderPatch) error {
	if len(in) > 4 {
		return errors.New("备用服务最多 4 套")
	}
	seen := map[string]bool{}
	for _, p := range in {
		if !providerID.MatchString(p.ID) || seen[p.ID] {
			return errors.New("备用服务标识无效或重复")
		}
		seen[p.ID] = true
		if strings.TrimSpace(p.Name) == "" || len(p.Name) > 120 {
			return errors.New("备用服务名称不能为空且不超过 120 字节")
		}
		if err := (Patch{BaseURL: &p.BaseURL, Model: &p.Model, PiModel: &p.PiModel, APIKey: p.APIKey, FallbackModels: &p.FallbackModels}).Check(); err != nil {
			return err
		}
		if p.FallbackModels != "" && len(strings.Split(p.FallbackModels, ",")) > 3 {
			return errors.New("每套备用服务最多 3 个备用模型")
		}
		if p.Enabled && p.Model == "" && p.PiModel == "" {
			return errors.New("启用备用服务前至少填写一个用途的主模型")
		}
	}
	return nil
}

func validBaseURL(value string) bool {
	if len(value) > 2048 || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// providerConfig 解密失败则停用该服务，不能拿空密钥去尝试未知的匿名身份。
func (s *Store) providerConfig(raw []providerStored) [4]Provider {
	var out [4]Provider
	for i, p := range raw {
		if i >= len(out) {
			break
		}
		v := Provider{ID: p.ID, Name: p.Name, BaseURL: p.BaseURL, Model: p.Model, PiModel: p.PiModel, FallbackModels: p.FallbackModels, Enabled: p.Enabled}
		if p.APIKey != nil && len(p.APIKey.Sealed) > 0 {
			plain, err := s.Vault.Open(p.APIKey.Sealed, "setting:ai:provider:"+p.ID)
			if err != nil {
				v.Enabled = false
				slog.Warn("备用模型服务密钥无法解密，已停用该服务", "id", p.ID)
			} else {
				v.APIKey = plain.Password
			}
		}
		out[i] = v
	}
	return out
}

func (s *Store) saveProviders(old []providerStored, in []ProviderPatch) ([]providerStored, error) {
	previous := map[string]providerStored{}
	for _, p := range old {
		previous[p.ID] = p
	}
	out := make([]providerStored, 0, len(in))
	for _, p := range in {
		v := providerStored{ID: p.ID, Name: p.Name, BaseURL: strings.TrimRight(p.BaseURL, "/"), Model: p.Model, PiModel: p.PiModel, FallbackModels: p.FallbackModels, Enabled: p.Enabled, APIKey: previous[p.ID].APIKey}
		if p.APIKey != nil {
			v.APIKey = &secret{}
			if *p.APIKey != "" {
				if s.Vault == nil {
					return nil, ErrNoVault
				}
				sealed, err := s.Vault.Seal(hostimport.Secret{Password: *p.APIKey}, "setting:ai:provider:"+p.ID)
				if err != nil {
					return nil, err
				}
				v.APIKey = &secret{Sealed: sealed, Hint: tail(*p.APIKey)}
			}
		}
		out = append(out, v)
	}
	return out, nil
}

func providerViews(c Config) []ProviderView {
	out := []ProviderView{}
	for _, p := range c.Providers {
		if p.ID == "" {
			continue
		}
		out = append(out, ProviderView{ID: p.ID, Name: p.Name, BaseURL: p.BaseURL, Model: p.Model, PiModel: p.PiModel, FallbackModels: p.FallbackModels, Enabled: p.Enabled, APIKeySet: p.APIKey != "", APIKeyHint: tail(p.APIKey)})
	}
	return out
}

// Routes 只交付已启用、配置了当前用途的服务，按管理员保存的顺序排列。
func (c Config) Routes(pi bool) []modelroute.Endpoint {
	out := []modelroute.Endpoint{}
	for _, p := range c.Providers {
		model := p.Model
		if pi {
			model = p.PiModel
		}
		if !p.Enabled || model == "" {
			continue
		}
		models := []string{model}
		if p.FallbackModels != "" {
			models = append(models, strings.Split(p.FallbackModels, ",")...)
		}
		seen := map[string]bool{}
		for _, m := range models {
			if m != "" && !seen[m] {
				seen[m] = true
				out = append(out, modelroute.Endpoint{BaseURL: p.BaseURL, APIKey: p.APIKey, Model: m})
			}
		}
	}
	return out
}
