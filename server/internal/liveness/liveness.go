// Package liveness 主机失联巡视：agent 静默挂掉，安全覆盖就静默消失，必须有人知道。
//
// 心跳由指令通道刷新 last_seen。超过 SilentAfter 没有心跳记一次失联，恢复后记一次恢复，
// 同一次失联只通知一次。巡视器自己启动后先等满 SilentAfter 再判定——server 重启
// 期间 agent 连不上，心跳本来就是旧的，不能把整片主机都报成失联。
package liveness

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
)

// Notify 推送一条通知；path 是控制台内的相对链接。
type Notify func(ctx context.Context, title, body, path string) error

type Watcher struct {
	DB          *ent.Client
	Notify      Notify
	SilentAfter time.Duration
	Interval    time.Duration
	// DropAlert 一轮（一分钟）内丢弃这么多事件就算采集异常，0 不看丢事件
	DropAlert int
}

func (w *Watcher) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(w.SilentAfter):
	}
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		if err := w.sweep(ctx, time.Now()); err != nil {
			slog.Error("失联巡视失败", "err", err)
		}
		if err := w.sweepHealth(ctx, time.Now()); err != nil {
			slog.Error("采集健康巡视失败", "err", err)
		}
		if err := w.sweepSensorHealth(ctx, time.Now()); err != nil {
			slog.Error("探针状态巡视失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Watcher) sweep(ctx context.Context, now time.Time) error {
	deadline := now.Add(-w.SilentAfter)
	silent, err := w.DB.Asset.Query().
		Where(asset.AgentIDNotNil(), asset.RetiredAtIsNil(), asset.ParkedAtIsNil(), asset.SilentSinceIsNil(), asset.LastSeenLT(deadline)).
		Order(ent.Asc(asset.FieldHostname)).All(ctx)
	if err != nil {
		return err
	}
	back, err := w.DB.Asset.Query().
		Where(asset.SilentSinceNotNil(), asset.LastSeenGTE(deadline)).
		Order(ent.Asc(asset.FieldHostname)).All(ctx)
	if err != nil {
		return err
	}

	if len(silent) > 0 {
		lines := make([]string, len(silent))
		for i, a := range silent {
			lines[i] = fmt.Sprintf("%s：最后心跳 %s（%s 前）", a.Hostname,
				a.LastSeen.Local().Format("01-02 15:04"), since(now, a.LastSeen))
		}
		// 先通知后落标记：推送失败下轮重试，不能让失联悄悄过去
		if err := w.Notify(ctx, fmt.Sprintf("%d 台主机失联", len(silent)),
			strings.Join(lines, "\n")+"\n采集与检测已中断，请检查 agent 或网络", "/assets"); err != nil {
			return err
		}
		if err := w.DB.Asset.Update().Where(asset.IDIn(ids(silent)...)).SetSilentSince(now).Exec(ctx); err != nil {
			return err
		}
		slog.Warn("主机失联", "count", len(silent))
	}

	if len(back) > 0 {
		lines := make([]string, len(back))
		for i, a := range back {
			// 判定失联时心跳已停了 SilentAfter，中断时长从那时算起
			lines[i] = fmt.Sprintf("%s：中断约 %s", a.Hostname, since(now, a.SilentSince.Add(-w.SilentAfter)))
		}
		if err := w.Notify(ctx, fmt.Sprintf("%d 台主机恢复", len(back)), strings.Join(lines, "\n"), "/assets"); err != nil {
			return err
		}
		if err := w.DB.Asset.Update().Where(asset.IDIn(ids(back)...)).ClearSilentSince().Exec(ctx); err != nil {
			return err
		}
		slog.Info("主机恢复", "count", len(back))
	}
	return nil
}

func ids(assets []*ent.Asset) []uuid.UUID {
	out := make([]uuid.UUID, len(assets))
	for i, a := range assets {
		out[i] = a.ID
	}
	return out
}

// since 粗粒度时长，通知里给人看的
func since(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%d 天", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%d 小时", int(d.Hours()))
	default:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	}
}
