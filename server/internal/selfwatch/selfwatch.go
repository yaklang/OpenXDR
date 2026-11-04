// Package selfwatch 盯 OpenXDR 自己：谁拿下了 XDR，谁就拿到了整张地图，平台节点要当最高等级的资产看。
//
//   - Patroni 动态配置（DCS）被改：每轮读本机 Patroni 的 /config 与基线比对。动态配置只能经 REST 写接口或直连 etcd 改，
//     落不到文件上，agent 看不到。改了 pg_hba、*_command、预加载库这类能开门或执行命令的项判 5 级，其余改动 3 级留痕
//   - 核心节点 agent 停止上报：跑着 openxdr-server 的资产超过 silentAfter 没有上报判 4 级，一小时内同一台只报一次
//
// 单活运行；告警直接落表，关联、研判与推送走现有通路。
package selfwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/internal/sigma"
)

// baselineKey settings 表里存 Patroni 动态配置基线的键
const baselineKey = "selfwatch.patroni_config"

// silentAfter 核心节点 agent 多久不上报算掉线；agent 心跳 30 秒一次，留够重启与升级的时间
const silentAfter = 5 * time.Minute

type Watch struct {
	DB *ent.Client
	// Patroni 动态配置接口（只读、免口令），默认 http://127.0.0.1:8008/config
	PatroniURL string
	Interval   time.Duration
	// 测试用
	Now func() time.Time
}

func (w *Watch) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Watch) Run(ctx context.Context) {
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		if err := w.Tick(ctx); err != nil && ctx.Err() == nil {
			slog.Error("自身监控本轮失败", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (w *Watch) Tick(ctx context.Context) error {
	if w.PatroniURL != "" {
		if err := w.patroni(ctx); err != nil {
			slog.Warn("读取 Patroni 动态配置失败", "err", err)
		}
	}
	return w.silentCores(ctx)
}

// patroni 动态配置与基线比对；第一次只记基线
func (w *Watch) patroni(ctx context.Context) error {
	current, err := fetch(ctx, w.PatroniURL)
	if err != nil {
		return err
	}
	row, err := w.DB.Setting.Get(ctx, baselineKey)
	if ent.IsNotFound(err) {
		return w.DB.Setting.Create().SetID(baselineKey).SetValue(current).Exec(ctx)
	}
	if err != nil {
		return err
	}
	changed := diff(row.Value, current)
	if len(changed) == 0 {
		return nil
	}
	severity := int16(3)
	if slices.ContainsFunc(changed, dangerous) {
		severity = 5
	}
	host, err := w.self(ctx)
	if err != nil {
		return err
	}
	detail := "Patroni 动态配置（DCS）被改：" + strings.Join(changed, "、") + "。只有 REST 写接口或直连 etcd 能改它，确认是否是运维操作"
	now := w.now()
	if err := w.DB.Alert.Create().SetTs(now).SetLastTs(now).SetRuleID(sigma.RuleControlPlaneChange).SetSeverity(severity).
		SetNillableAssetID(host).SetDetail(detail).Exec(ctx); err != nil {
		return err
	}
	slog.Warn("Patroni 动态配置被改", "changed", changed, "severity", severity)
	return w.DB.Setting.UpdateOneID(baselineKey).SetValue(current).Exec(ctx)
}

// dangerous 能开门或执行命令的配置项：访问控制、在服务端执行命令、加载库、关加密
func dangerous(path string) bool {
	for _, p := range []string{"postgresql.pg_hba", "postgresql.pg_ident", "_command", "preload_libraries", "postgresql.parameters.ssl", "password_encryption", "listen_addresses"} {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

// silentCores 核心节点上 agent 停止上报。核心按监听清单认（跑着 openxdr-server），与自主响应的核心等级同一口径
func (w *Watch) silentCores(ctx context.Context) error {
	now := w.now()
	assets, err := w.DB.Asset.Query().
		Where(entasset.AgentIDNotNil(), entasset.LastSeenLT(now.Add(-silentAfter))).
		All(ctx)
	if err != nil {
		return err
	}
	for _, a := range assets {
		if !runsServer(a.Listening) {
			continue
		}
		recent, err := w.DB.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleCoreAgentSilent), alert.AssetIDEQ(a.ID),
			alert.TsGTE(now.Add(-time.Hour))).Exist(ctx)
		if err != nil || recent {
			if err != nil {
				return err
			}
			continue
		}
		detail := fmt.Sprintf("平台节点 %s 的 agent 已 %d 分钟没有上报（最后一次 %s）。节点被拿下后先停 agent 是常见动作，确认是否是维护",
			a.Hostname, int(now.Sub(a.LastSeen).Minutes()), a.LastSeen.UTC().Format(time.RFC3339))
		if err := w.DB.Alert.Create().SetTs(now).SetLastTs(now).SetRuleID(sigma.RuleCoreAgentSilent).SetSeverity(4).
			SetAssetID(a.ID).SetDetail(detail).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// self 本节点的资产（server 用宿主机网络，主机名就是节点名）；认不出就不挂资产
func (w *Watch) self(ctx context.Context) (*uuid.UUID, error) {
	name, err := os.Hostname()
	if err != nil {
		return nil, nil
	}
	a, err := w.DB.Asset.Query().Where(entasset.HostnameEQ(name)).Only(ctx)
	if ent.IsNotFound(err) || ent.IsNotSingular(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a.ID, nil
}

func fetch(ctx context.Context, url string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Patroni /config 返回 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("Patroni /config 不是 JSON: %w", err)
	}
	return json.Marshal(v) // 规范化：键排序，基线比对不受字段顺序影响
}

// diff 两份配置不同的路径（点分），按字典序。数组整体比较，pg_hba 这类列表改一行就报整个列表
func diff(old, cur json.RawMessage) []string {
	var a, b any
	_ = json.Unmarshal(old, &a)
	_ = json.Unmarshal(cur, &b)
	var out []string
	walk("", a, b, &out)
	sort.Strings(out)
	return out
}

func walk(path string, a, b any, out *[]string) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		for k := range keys {
			p := k
			if path != "" {
				p = path + "." + k
			}
			walk(p, am[k], bm[k], out)
		}
		return
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		*out = append(*out, path)
	}
}

func runsServer(listening json.RawMessage) bool {
	var ports []struct {
		Process string `json:"process"`
	}
	if json.Unmarshal(listening, &ports) != nil {
		return false
	}
	for _, p := range ports {
		if p.Process == "openxdr-server" {
			return true
		}
	}
	return false
}
