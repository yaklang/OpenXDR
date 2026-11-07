package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/trustedsource"
	"openxdr/server/internal/automation"
	"openxdr/server/internal/findings"
)

const (
	assetWorkDays     = 14
	assetWorkAssets   = 5
	assetWorkFindings = 8
	assetWorkPorts    = 100
)

type listeningPort struct {
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Process string `json:"process"`
	Path    string `json:"path"`
}

// appendAssetWork 涉事主机近期的运维待办、管理员执行决定与设备清单里的监听端口。
// 告警里的变更常常就是待办在落实的管理员决定（收口端口、装守护单元）；没有这段，研判只能把它当来路不明。
// 管理员决定是人工授权，但只在决定写明的主机与范围内有效；待办正文由 AI 写，只是线索。
func (e *Engine) appendAssetWork(ctx context.Context, sb *strings.Builder, alerts []*ent.Alert) {
	var ids []uuid.UUID
	for _, a := range alerts {
		if a.AssetID != nil && !slices.Contains(ids, *a.AssetID) && len(ids) < assetWorkAssets {
			ids = append(ids, *a.AssetID)
		}
	}
	if len(ids) == 0 {
		return
	}
	assets, err := e.DB.Asset.Query().Where(asset.IDIn(ids...)).All(ctx)
	if err != nil || len(assets) == 0 {
		return
	}
	since := time.Now().AddDate(0, 0, -assetWorkDays)
	sb.WriteString(fmt.Sprintf("## 涉事主机近 %d 天的运维待办、管理员执行决定与监听端口（待办正文由 AI 写，仅为线索；管理员决定是人工授权，只在其写明的主机与范围内有效，变更须与决定内容逐项吻合才可作为授权依据）\n", assetWorkDays))
	for _, a := range assets {
		fmt.Fprintf(sb, "### %s (%s)\n", a.Hostname, a.ID)
		e.writeAssetFindings(ctx, sb, a.ID, since)
		writeListening(sb, a)
	}
}

func (e *Engine) writeAssetFindings(ctx context.Context, sb *strings.Builder, id uuid.UUID, since time.Time) {
	rows, err := e.DB.Finding.Query().Where(finding.AssetIDEQ(id), finding.Or(finding.LastSeenGTE(since), finding.ResolvedAtGTE(since))).
		Order(ent.Desc(finding.FieldLastSeen)).Limit(assetWorkFindings).All(ctx)
	if err != nil || len(rows) == 0 {
		sb.WriteString("运维待办：无\n")
		return
	}
	sb.WriteString("运维待办：\n")
	for _, f := range rows {
		fmt.Fprintf(sb, "- [%s] %s（最近 %s）\n", f.Status, truncateRunes(f.Title, 120), f.LastSeen.UTC().Format(time.RFC3339))
		d, err := findings.LoadDecision(ctx, e.DB, f.ID)
		if err != nil || d == nil {
			continue
		}
		state := "有效"
		if d.Revoked {
			state = "已撤销"
		} else if time.Now().After(d.ExpiresAt) {
			state = "执行窗口已过（决定本身仍是人工意见）"
		}
		fmt.Fprintf(sb, "  管理员执行决定（%s 于 %s 签发，%s）：%s\n", d.Author, d.CreatedAt.UTC().Format(time.RFC3339), state, truncateRunes(d.Instruction, 600))
	}
}

// writeListening 设备清单的监听端口：容器连到网桥网关某端口时，靠它认出宿主上是哪个进程在听
func writeListening(sb *strings.Builder, a *ent.Asset) {
	var ports []listeningPort
	if len(a.Listening) == 0 || json.Unmarshal(a.Listening, &ports) != nil || len(ports) == 0 {
		sb.WriteString("监听端口：设备清单未上报\n")
		return
	}
	at := "时间未知"
	if a.InventoryAt != nil {
		at = a.InventoryAt.UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(sb, "监听端口（设备清单 %s，是清单时刻的状态；同一端口多个地址合并列出）：", at)
	// 同一进程在 0.0.0.0 与 :: 上各听一次，按端口/协议/进程合并，地址并列，免得双栈把名额吃掉一半
	var parts []string
	index := map[string]int{}
	for _, p := range ports {
		key := fmt.Sprintf("%s/%d %s(%s)", p.Proto, p.Port, p.Process, p.Path)
		if i, ok := index[key]; ok {
			parts[i] = strings.Replace(parts[i], " @", " @"+p.Addr+",", 1)
			continue
		}
		index[key] = len(parts)
		parts = append(parts, key+" @"+p.Addr)
	}
	shown := parts[:min(len(parts), assetWorkPorts)]
	sb.WriteString(strings.Join(shown, "；"))
	if len(parts) > len(shown) {
		fmt.Fprintf(sb, "；另有 %d 个未列出", len(parts)-len(shown))
	}
	sb.WriteString("\n")
}

func truncateRunes(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}

// registeredAutomation 入库时没打可信来源标记、但登录会话符合当前有效登记的告警：登记晚于告警时，
// 重研判也要看得到这是登记过的运维自动化。只读匹配，不累加命中计数
func (e *Engine) registeredAutomation(ctx context.Context, a *ent.Alert) string {
	if a.AutomationID != nil || a.AssetID == nil || a.Edges.Event == nil || a.Edges.Event.Source != "agent" {
		return ""
	}
	var raw map[string]any
	if json.Unmarshal(a.Edges.Event.Raw, &raw) != nil {
		return ""
	}
	login, ok := automation.Session(raw)
	if !ok {
		return ""
	}
	host, err := e.DB.Asset.Get(ctx, *a.AssetID)
	if err != nil || host.GroupID == nil {
		return ""
	}
	rows, err := e.DB.TrustedSource.Query().Where(trustedsource.GroupIDEQ(*host.GroupID),
		trustedsource.RevokedAtIsNil(), trustedsource.DeletedAtIsNil(), trustedsource.ExpiresAtGT(time.Now())).
		Order(ent.Asc(trustedsource.FieldCreatedAt)).All(ctx)
	if err != nil {
		return ""
	}
	for _, t := range rows {
		if (automation.Source{ID: t.ID, KeyFingerprint: t.KeyFingerprint, SourceCIDR: t.SourceCidr, LoginUser: t.LoginUser}).Matches(login) {
			return t.Name
		}
	}
	return ""
}
