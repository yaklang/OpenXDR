package containment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"openxdr/server/ent"
	"openxdr/server/ent/setting"
)

const configKey = "containment"

// ErrLocked 字段由环境变量锁定，控制台不能改
var ErrLocked = errors.New("该项由环境变量锁定，需改部署配置")

// Config 控制台可改的开关与范围，存 settings 表，各节点每轮读取，改了不用重启。
type Config struct {
	Enabled bool   `json:"enabled"`
	Scope   string `json:"scope"`
}

// View 生效值与锁定情况
type View struct {
	Config
	EnabledLocked bool `json:"enabledLocked"`
	ScopeLocked   bool `json:"scopeLocked"`
}

// Store 环境变量非空即锁定值，优先于控制台；都没有时默认关闭、只处置实验等级。
type Store struct {
	DB       *ent.Client
	EnvOn    string // CONTAINMENT_ENABLED
	EnvScope string // CONTAINMENT_SCOPE
}

// Validate 启动时校验环境变量，写错了拒绝启动而不是猜
func (s *Store) Validate() error {
	if s.EnvOn != "" && s.EnvOn != "true" && s.EnvOn != "false" {
		return fmt.Errorf("CONTAINMENT_ENABLED 只能是 true 或 false，实际 %q", s.EnvOn)
	}
	if s.EnvScope != "" && s.EnvScope != ScopeLab && s.EnvScope != ScopeAll {
		return fmt.Errorf("CONTAINMENT_SCOPE 只能是 lab 或 all，实际 %q", s.EnvScope)
	}
	return nil
}

// Load 读不到或配置损坏时报错，调用方本轮按关闭处理：拿不准就不动手。
func (s *Store) Load(ctx context.Context) (View, error) {
	v := View{Config: Config{Scope: ScopeLab}}
	row, err := s.DB.Setting.Get(ctx, configKey)
	switch {
	case ent.IsNotFound(err):
	case err != nil:
		return View{}, err
	default:
		if err := json.Unmarshal(row.Value, &v.Config); err != nil || v.Scope != ScopeLab && v.Scope != ScopeAll {
			return View{}, errors.New("自主响应配置损坏")
		}
	}
	if s.EnvOn != "" {
		v.Enabled, v.EnabledLocked = s.EnvOn == "true", true
	}
	if s.EnvScope != "" {
		v.Scope, v.ScopeLocked = s.EnvScope, true
	}
	return v, nil
}

// Save 锁定的字段只能原样提交
func (s *Store) Save(ctx context.Context, c Config) error {
	if c.Scope != ScopeLab && c.Scope != ScopeAll {
		return errors.New("scope 只能是 lab 或 all")
	}
	cur, err := s.Load(ctx)
	if err != nil {
		return err
	}
	if cur.EnabledLocked && c.Enabled != cur.Enabled || cur.ScopeLocked && c.Scope != cur.Scope {
		return ErrLocked
	}
	value, err := json.Marshal(c)
	if err != nil {
		return err
	}
	n, err := s.DB.Setting.Update().Where(setting.IDEQ(configKey)).SetValue(value).Save(ctx)
	if err == nil && n == 0 {
		err = s.DB.Setting.Create().SetID(configKey).SetValue(value).Exec(ctx)
	}
	return err
}
