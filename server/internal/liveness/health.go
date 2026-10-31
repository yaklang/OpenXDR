package liveness

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
)

// 采集健康通知：降级是悄悄发生的——eBPF 挂不上退轮询、安装包换成没编 eBPF 的构建、缓存写满，
// 主机照样在线，资产页上能看见但没人盯着。问题集合变了才通知，恢复了说一声，同一个问题不反复推。
// 已失联的主机交给失联通知；健康快照过期（旧 agent 或快照停了）的不评估，不拿旧状态报警。

// healthStale 快照多久没更新就不再据它判断（agent 每 30 秒左右报一次）
const healthStale = 5 * time.Minute

// dropSticky 丢事件超过阈值后多久才算恢复：丢事件是一阵一阵的，不能每分钟来回报
const dropSticky = time.Hour

// clockSkewThreshold 主机上报时刻与服务端接收时刻相差超过 1 分钟即告警（超过 5 分钟会被 gRPC 拒绝）
const clockSkewThreshold = time.Minute

var capabilityNames = map[string]string{
	"process": "进程采集", "files": "文件监控", "network": "网络采集", "dns": "DNS 采集", "auth": "登录采集",
	"inventory": "资产清单", "local-accounts": "本地账号清单", "persist": "持久化点监控", "kmod": "内核模块监控",
	"powershell": "PowerShell 脚本块", "software": "软件清单",
}

type healthSnapshot struct {
	ReceivedAt     time.Time `json:"receivedAt"`
	ReportedUnixMs int64     `json:"reportedUnixMs"`
	DroppedEvents  int64     `json:"droppedEvents"`
	WriteBlocked   bool      `json:"writeBlocked"`
	Capabilities   map[string]struct {
		Path     string `json:"path"`
		State    string `json:"state"`
		Reason   string `json:"reason"`
		Rebuilds int    `json:"rebuilds"`
	} `json:"capabilities"`
}

// problem 一项采集问题：key 进签名（不含会变的计数），text 给人看
type problem struct{ key, text string }

func healthProblems(h healthSnapshot, dropping bool, dropped int64) []problem {
	var out []problem
	for name, c := range h.Capabilities {
		if c.State != "degraded" && c.State != "unavailable" {
			continue
		}
		label := capabilityNames[name]
		if label == "" {
			label = name
		}
		state := map[string]string{"degraded": "降级", "unavailable": "不可用"}[c.State]
		text := label + state
		if c.Path != "" {
			text += "（" + c.Path + "）"
		}
		key := "cap:" + name + ":" + c.State
		// 活性检测的降级（通道开着却没有数据）与路径自报的降级是两回事，原因进签名，变了要重新通知
		if c.Reason != "" {
			text += "：" + c.Reason
			key += ":" + c.Reason
		}
		// agent 失明后会按退避自动重建采集，次数只进文字不进签名：每重建一次都重新推送就成了刷屏
		if c.Rebuilds > 0 {
			text += fmt.Sprintf("（已自动重建 %d 次仍未恢复）", c.Rebuilds)
		}
		out = append(out, problem{key, text})
	}
	if h.WriteBlocked {
		out = append(out, problem{"blocked", "本地缓存写不进去（磁盘满或缓存已满），断线时事件会丢"})
	}
	if dropping {
		text := "近一小时有事件因上报跟不上被丢弃"
		if dropped > 0 {
			text = fmt.Sprintf("本轮丢弃 %d 条事件（上报跟不上）", dropped)
		}
		out = append(out, problem{"drops", text})
	}
	if h.ReportedUnixMs > 0 && !h.ReceivedAt.IsZero() {
		reported := time.UnixMilli(h.ReportedUnixMs)
		if skew := h.ReceivedAt.Sub(reported); skew >= clockSkewThreshold {
			out = append(out, problem{"clock_skew", fmt.Sprintf("主机时钟比服务端慢约 %d 秒，请检查 NTP 同步", int(skew.Round(time.Second).Seconds()))})
		} else if skew <= -clockSkewThreshold {
			out = append(out, problem{"clock_skew", fmt.Sprintf("主机时钟比服务端快约 %d 秒，请检查 NTP 同步", int((-skew).Round(time.Second).Seconds()))})
		}
	}
	slices.SortFunc(out, func(a, b problem) int { return strings.Compare(a.key, b.key) })
	return out
}

func signature(ps []problem) string {
	keys := make([]string, len(ps))
	for i, p := range ps {
		keys[i] = p.key
	}
	return strings.Join(keys, "|")
}

func (w *Watcher) sweepHealth(ctx context.Context, now time.Time) error {
	assets, err := w.DB.Asset.Query().
		Where(asset.AgentIDNotNil(), asset.SilentSinceIsNil(), asset.CollectorHealthNotNil()).
		Order(ent.Asc(asset.FieldHostname)).All(ctx)
	if err != nil {
		return err
	}
	var bad, good []change
	for _, a := range assets {
		var h healthSnapshot
		if json.Unmarshal(a.CollectorHealth, &h) != nil || now.Sub(h.ReceivedAt) > healthStale {
			continue
		}
		// 丢弃数是 agent 本次运行的累计值，重启会归零：比上轮小就从零起算
		var delta int64
		if a.HealthDropped != nil {
			delta = h.DroppedEvents - *a.HealthDropped
			if delta < 0 {
				delta = h.DroppedEvents
			}
		}
		droppedAt := a.HealthDroppedAt
		if w.DropAlert > 0 && delta >= int64(w.DropAlert) {
			droppedAt = &now
		}
		upd := a.Update().SetHealthDropped(h.DroppedEvents)
		if droppedAt != nil {
			upd.SetHealthDroppedAt(*droppedAt)
		}
		if err := upd.Exec(ctx); err != nil {
			return err
		}
		dropping := droppedAt != nil && now.Sub(*droppedAt) < dropSticky
		ps := healthProblems(h, dropping, max(delta, 0))
		sig, old := signature(ps), ""
		if a.HealthProblem != nil {
			old = *a.HealthProblem
		}
		if sig == old {
			continue
		}
		lines := make([]string, len(ps))
		for i, p := range ps {
			lines[i] = p.text
		}
		if sig == "" {
			good = append(good, change{a, sig, nil})
		} else {
			bad = append(bad, change{a, sig, lines})
		}
	}
	return w.notifyChanges(ctx, bad, good, func(a *ent.Asset, sig string) error {
		if sig == "" {
			return a.Update().ClearHealthProblem().Exec(ctx)
		}
		return a.Update().SetHealthProblem(sig).Exec(ctx)
	})
}

type change struct {
	a     *ent.Asset
	sig   string
	lines []string
}

// notifyChanges 推送问题集合的变化，推送成功后才落标记：推送失败下轮重试。
func (w *Watcher) notifyChanges(ctx context.Context, bad, good []change, mark func(*ent.Asset, string) error) error {
	if len(bad) > 0 {
		lines := make([]string, len(bad))
		for i, c := range bad {
			lines[i] = c.a.Hostname + "：" + strings.Join(c.lines, "；")
		}
		if err := w.Notify(ctx, fmt.Sprintf("%d 台主机采集异常", len(bad)),
			strings.Join(lines, "\n")+"\n这些主机仍在线，但有可见性缺口，检测可能漏报", "/assets"); err != nil {
			return err
		}
		for _, c := range bad {
			if err := mark(c.a, c.sig); err != nil {
				return err
			}
		}
		slog.Warn("主机采集异常", "count", len(bad))
	}
	if len(good) > 0 {
		names := make([]string, len(good))
		for i, c := range good {
			names[i] = c.a.Hostname
		}
		if err := w.Notify(ctx, fmt.Sprintf("%d 台主机采集恢复正常", len(good)), strings.Join(names, "、"), "/assets"); err != nil {
			return err
		}
		for _, c := range good {
			if err := mark(c.a, ""); err != nil {
				return err
			}
		}
		slog.Info("主机采集恢复", "count", len(good))
	}
	return nil
}

// sensorSnapshot 探针抓包状态里通知要用的部分。
type sensorSnapshot struct {
	ReceivedAt   time.Time `json:"receivedAt"`
	Workers      int       `json:"workers"`
	WorkersAlive int       `json:"workersAlive"`
	Capabilities map[string]struct {
		Path  string `json:"path"`
		State string `json:"state"`
	} `json:"capabilities"`
}

// sensorProblems 探针没有指令通道心跳，状态快照停更就是失联；抓包降级（丢包、线程退出）与不可用另记。
// 丢包是否算降级由探针按一小时窗口自己判定，这里不再看计数，免得两头口径不一。
func sensorProblems(raw []byte, now time.Time) []problem {
	var h sensorSnapshot
	if json.Unmarshal(raw, &h) != nil {
		return nil
	}
	if now.Sub(h.ReceivedAt) > healthStale {
		return []problem{{"sensor:silent", "流量探针失联（最后上报 " + h.ReceivedAt.Local().Format("01-02 15:04") + "）"}}
	}
	c := h.Capabilities["capture"]
	where := ""
	if c.Path != "" {
		where = "（" + c.Path + "）"
	}
	switch {
	case c.State == "unavailable":
		return []problem{{"sensor:capture:unavailable", "流量抓包不可用" + where}}
	case c.State == "degraded" && h.WorkersAlive < h.Workers:
		return []problem{{"sensor:capture:degraded", fmt.Sprintf("流量抓包降级%s：%d/%d 个抓包线程在运行", where, h.WorkersAlive, h.Workers)}}
	case c.State == "degraded":
		return []problem{{"sensor:capture:degraded", "流量抓包降级" + where + "：近一小时丢包超过 0.1%，会话会缺失"}}
	}
	return nil
}

// sweepSensorHealth 探针状态与 agent 采集状态走同一条「主机采集异常」通知，签名分开记。
func (w *Watcher) sweepSensorHealth(ctx context.Context, now time.Time) error {
	assets, err := w.DB.Asset.Query().Where(asset.SensorHealthNotNil()).
		Order(ent.Asc(asset.FieldHostname)).All(ctx)
	if err != nil {
		return err
	}
	var bad, good []change
	for _, a := range assets {
		ps := sensorProblems(a.SensorHealth, now)
		sig, old := signature(ps), ""
		if a.SensorProblem != nil {
			old = *a.SensorProblem
		}
		if sig == old {
			continue
		}
		if sig == "" {
			good = append(good, change{a, sig, nil})
			continue
		}
		lines := make([]string, len(ps))
		for i, p := range ps {
			lines[i] = p.text
		}
		bad = append(bad, change{a, sig, lines})
	}
	return w.notifyChanges(ctx, bad, good, func(a *ent.Asset, sig string) error {
		if sig == "" {
			return a.Update().ClearSensorProblem().Exec(ctx)
		}
		return a.Update().SetSensorProblem(sig).Exec(ctx)
	})
}
