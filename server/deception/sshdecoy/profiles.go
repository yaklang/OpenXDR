package sshdecoy

import (
	"errors"
	"openxdr/server/deception/contract"
	"strings"
)

// MaxProfileBannerBytes 限制运行策略的单次输出；大尺寸历史模板仅用于显式实验。
const MaxProfileBannerBytes = 8192

// Profile 只描述策略，不向目录调用方返回可执行的注入正文。
type Profile = contract.Profile

func Profiles() []Profile { return contract.SSHProfiles() }

func resolveProfile(cfg Config) (Config, error) {
	if cfg.Profile == "" {
		return cfg, nil
	}
	if cfg.Template != "" {
		return Config{}, errors.New("运行策略与实验模板不能同时选择")
	}
	for _, profile := range Profiles() {
		if profile.ID != cfg.Profile {
			continue
		}
		text, ok := templates[profile.Template]
		if !ok || len(strings.ReplaceAll(text, "{{marker}}", strings.Repeat("0", 32))) > MaxProfileBannerBytes {
			return Config{}, errors.New("运行策略模板不可用或超过输出上限")
		}
		cfg.Template = profile.Template
		return cfg, nil
	}
	return Config{}, errors.New("未知诱饵运行策略")
}
