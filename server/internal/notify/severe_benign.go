package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/setting"
	"openxdr/server/internal/review"
)

// severeBenignKey 上次推高危良性汇总的时刻，存库：部署频繁，进程内计时每次重启都会清零
const severeBenignKey = "notify-severe-benign"

// severeBenignEvery 高危良性待确认按天汇总：AI 已判良性，不必即时打扰，但要有人确认
const severeBenignEvery = 24 * time.Hour

// severeBenignDigest 距上次汇总满一天、且有待确认的高危良性事件时推一条汇总
func (n *Notifier) severeBenignDigest(ctx context.Context, now time.Time) error {
	t := n.Settings.Load(ctx)
	if t.URL == "" {
		return nil
	}
	var last time.Time
	if row, err := n.DB.Setting.Get(ctx, severeBenignKey); err == nil {
		_ = json.Unmarshal(row.Value, &last)
	} else if !ent.IsNotFound(err) {
		return err
	}
	if now.Sub(last) < severeBenignEvery {
		return nil
	}
	rows, err := n.DB.Incident.Query().Where(review.SevereBenign()).Order(ent.Asc(incident.FieldCreatedAt)).All(ctx)
	if err != nil || len(rows) == 0 {
		return err
	}
	body := severeBenignBody(rows, t.LinkBase)
	if err := send(ctx, n.Client, t.URL, t.Format, payload(t.Format, Text{Title: "高危良性待确认", Body: body}, body)); err != nil {
		n.Settings.Record(ctx, err)
		return err
	}
	n.Settings.Record(ctx, nil)
	value, _ := json.Marshal(now)
	c, err := n.DB.Setting.Update().Where(setting.IDEQ(severeBenignKey)).SetValue(value).Save(ctx)
	if err == nil && c == 0 {
		err = n.DB.Setting.Create().SetID(severeBenignKey).SetValue(value).Exec(ctx)
	}
	slog.Info("高危良性汇总已推送", "incidents", len(rows))
	return err
}

// severeBenignBody 每个事件一行，最多 20 行
func severeBenignBody(rows []*ent.Incident, linkBase string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "📋【OpenXDR】高危良性待确认：%d 个事件\nAI 判为良性，但告警是高危或严重级、主机上没有写明业务的资产角色或授权事实，需要人确认后结案（给主机补上事实，同类事件以后可由审计员自动结案）。\n", len(rows))
	for i, inc := range rows {
		if i == 20 {
			fmt.Fprintf(&b, "…另有 %d 个\n", len(rows)-20)
			break
		}
		title := inc.ID.String()
		if inc.Title != nil {
			title = *inc.Title
		}
		fmt.Fprintf(&b, "· %s", title)
		if linkBase != "" {
			fmt.Fprintf(&b, "｜%s/incidents/%s", linkBase, inc.ID)
		}
		b.WriteString("\n")
	}
	if linkBase != "" {
		fmt.Fprintf(&b, "🔗 待复核列表：%s/incidents?status=review\n", linkBase)
	}
	return b.String()
}
