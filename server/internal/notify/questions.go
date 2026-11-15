package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/setting"
	"openxdr/server/internal/questions"
)

// questionsKey 上次推待答问题汇总的时刻，存库：部署频繁，进程内计时每次重启都会清零
const questionsKey = "notify-questions"

// questionsEvery 待答问题每天至多推一条，问题再多也合成一条
const questionsEvery = 24 * time.Hour

// questionDigest 距上次推送满一天、且有待答问题时推一条：问题数、按主题一行摘要、控制台链接。
// 链接不带任何能直接作答的令牌，作答只在控制台；当天没问题就不发
func (n *Notifier) questionDigest(ctx context.Context, now time.Time) error {
	t := n.Settings.Load(ctx)
	if t.URL == "" {
		return nil
	}
	var last time.Time
	if row, err := n.DB.Setting.Get(ctx, questionsKey); err == nil {
		_ = json.Unmarshal(row.Value, &last)
	} else if !ent.IsNotFound(err) {
		return err
	}
	if now.Sub(last) < questionsEvery {
		return nil
	}
	total, lines, err := questions.Digest(ctx, n.DB, 20)
	if err != nil || total == 0 {
		return err
	}
	body := questionsBody(total, lines, t.LinkBase)
	if err := send(ctx, n.Client, t.URL, t.Format, payload(t.Format, Text{Title: "总控待答问题", Body: body}, body)); err != nil {
		n.Settings.Record(ctx, err)
		return err
	}
	n.Settings.Record(ctx, nil)
	value, _ := json.Marshal(now)
	c, err := n.DB.Setting.Update().Where(setting.IDEQ(questionsKey)).SetValue(value).Save(ctx)
	if err == nil && c == 0 {
		err = n.DB.Setting.Create().SetID(questionsKey).SetValue(value).Exec(ctx)
	}
	slog.Info("总控待答问题汇总已推送", "questions", total)
	return err
}

func questionsBody(total int, lines []string, linkBase string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "📋【OpenXDR】总控待答问题：%d 个\n平台查不到答案、需要管理员决定的归属、授权与策略问题，已按主题合并。证据与作答只在控制台。\n", total)
	for _, l := range lines {
		b.WriteString("· " + l + "\n")
	}
	if linkBase != "" {
		fmt.Fprintf(&b, "🔗 去作答：%s/control?tab=questions\n", linkBase)
	}
	return b.String()
}
