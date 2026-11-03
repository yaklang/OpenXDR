package notify

import (
	"context"
	"encoding/json"
	"log/slog"

	"openxdr/server/ent"
	"openxdr/server/ent/setting"
)

const settingKey = "notify"

// Target 推送目标。
type Target struct {
	URL string `json:"url"`
	// generic / dingtalk / feishu / wecom
	Format string `json:"format"`
	// 拼进消息的控制台链接前缀，如 https://xdr.example.com
	LinkBase string `json:"linkBase"`
	// 低于该级别的事件不推送，0 表示全推。降噪的最后一道闸
	MinSeverity int16 `json:"minSeverity"`
}

// Settings 推送目标以控制台保存的为准，从没保存过时用环境变量给的 Default。
type Settings struct {
	DB      *ent.Client
	Default Target
}

func (s *Settings) Load(ctx context.Context) Target {
	row, err := s.DB.Setting.Get(ctx, settingKey)
	if err != nil {
		if !ent.IsNotFound(err) {
			slog.Error("读取通知配置失败，使用默认值", "err", err)
		}
		return s.Default
	}
	var t Target
	if err := json.Unmarshal(row.Value, &t); err != nil {
		slog.Error("通知配置损坏，使用默认值", "err", err)
		return s.Default
	}
	return t
}

// Save 换了推送地址或格式时，旧渠道的连续失败不再代表新渠道，清零
func (s *Settings) Save(ctx context.Context, t Target) error {
	value, err := json.Marshal(t)
	if err != nil {
		return err
	}
	old := s.Load(ctx)
	n, err := s.DB.Setting.Update().Where(setting.IDEQ(settingKey)).SetValue(value).Save(ctx)
	if err == nil && n == 0 {
		err = s.DB.Setting.Create().SetID(settingKey).SetValue(value).Exec(ctx)
	}
	if err == nil && (old.URL != t.URL || old.Format != t.Format) {
		st := s.state(ctx)
		st.ConsecutiveFailures, st.LastError = 0, ""
		s.saveState(ctx, st)
	}
	return err
}
