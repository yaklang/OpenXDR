// Package facts 自治总控的权威事实与运维意图：子 Agent 遇到「这是谁的、谁授权的」先从这里找答案。
//
// 事实只来自管理员录入、平台记录或部署流水线，研判把它当前提引用；
// 意图只解释同一登录身份在登记范围内的行为，不放行高危类别、不跨出登记的主机与时间窗。
package facts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/fact"
	"openxdr/server/ent/intent"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/audit"
)

// Kinds 事实类型
var Kinds = []string{"key", "channel", "asset_role", "decision", "change"}

// Categories 意图用途目录：研判只看类别，说明文字不进模型（防提示词注入）
var Categories = []string{"deploy", "troubleshoot", "migrate", "inspect", "test", "maintenance", "backup"}

// CategoryNames 给模型与界面看的类别名
var CategoryNames = map[string]string{
	"deploy": "部署发布", "troubleshoot": "排障", "migrate": "迁移", "inspect": "巡检核查",
	"test": "测试验证", "maintenance": "维护变更", "backup": "备份",
}

const (
	// MaxIntentHosts 一次意图最多覆盖的主机，不许通配
	MaxIntentHosts = 20
	// MaxIntentTTL 意图最长有效期
	MaxIntentTTL = 4 * time.Hour
	// LateWindow 开始后多久内还能补登
	LateWindow = 2 * time.Hour
	maxContent = 1000
	maxNote    = 500
)

// ValidateFact 按类型检查必填项
func ValidateFact(kind, subject string, assetID *uuid.UUID, content string) error {
	if !slices.Contains(Kinds, kind) {
		return errors.New("kind 只能是 " + strings.Join(Kinds, " / "))
	}
	if n := utf8.RuneCountInString(strings.TrimSpace(content)); n == 0 || n > maxContent {
		return fmt.Errorf("content 须为 1–%d 字", maxContent)
	}
	switch kind {
	case "key":
		if !strings.HasPrefix(subject, "SHA256:") || len(subject) < 20 {
			return errors.New("钥匙事实的 subject 须为 SHA256: 开头的公钥指纹")
		}
	case "channel":
		if _, err := Prefix(subject); err != nil {
			return errors.New("通道事实的 subject 须为 IP 地址或 CIDR")
		}
	case "asset_role", "change":
		if assetID == nil {
			return errors.New(kind + " 事实须指定 assetId")
		}
	case "decision":
		if strings.TrimSpace(subject) == "" {
			return errors.New("决定事实须有 subject（主题）")
		}
	}
	return nil
}

// Prefix 地址或 CIDR 统一成网段
func Prefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Covers cidr 是否覆盖 ip
func Covers(cidr, ip string) bool {
	p, err := Prefix(cidr)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(ip)
	return err == nil && p.Contains(a.Unmap())
}

// Live 当前有效：没停用、没过期
func Live(now time.Time) predicate.Fact {
	return fact.And(fact.RetiredAtIsNil(), fact.Or(fact.ExpiresAtIsNil(), fact.ExpiresAtGT(now)))
}

// HostKinds 写明一台主机做什么、授权过什么的事实：高危告警上的良性结论要有它覆盖才交审计结案
var HostKinds = []string{"asset_role", "change"}

// HostRefs 这台主机上有效的资产角色与已授权变更事实编号
func HostRefs(ctx context.Context, db *ent.Client, asset uuid.UUID, now time.Time) ([]string, error) {
	ids, err := db.Fact.Query().Where(fact.AssetIDEQ(asset), fact.KindIn(HostKinds...), Live(now)).IDs(ctx)
	refs := make([]string, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, Ref("F", id))
	}
	return refs, err
}

// IntentRequest 登记意图的入参
type IntentRequest struct {
	KeyFingerprint string
	SourceAddr     string
	Assets         []uuid.UUID
	Category       string
	Note           string
	StartsAt       time.Time
	Duration       time.Duration
}

// ErrNotOwner 登记人不是这个通道或钥匙在事实库里的持有人
var ErrNotOwner = errors.New("只能为事实库里登记在自己名下的通道与钥匙登记意图")

// CheckIntent 校验意图：范围有界、用途在目录里、登录身份在事实库里归登记人所有。
// 只偷到 SSH 钥匙的人没有控制台账号或集成 Token，登记不了；拿到 Token 的人也只能为 Token 名下的通道登记
func CheckIntent(ctx context.Context, db *ent.Client, holder string, req IntentRequest, now time.Time) (late bool, err error) {
	switch {
	case len(req.Assets) == 0 || len(req.Assets) > MaxIntentHosts:
		return false, fmt.Errorf("主机须为 1–%d 台", MaxIntentHosts)
	case !slices.Contains(Categories, req.Category):
		return false, errors.New("category 只能是 " + strings.Join(Categories, " / "))
	case req.Duration <= 0 || req.Duration > MaxIntentTTL:
		return false, fmt.Errorf("时长须在 %d 小时以内", int(MaxIntentTTL.Hours()))
	case utf8.RuneCountInString(req.Note) > maxNote:
		return false, fmt.Errorf("说明最多 %d 字", maxNote)
	case req.StartsAt.After(now.Add(time.Minute)):
		return false, errors.New("不能预登记将来的意图")
	case req.StartsAt.Before(now.Add(-LateWindow)):
		return false, fmt.Errorf("最多补登 %d 小时前开始的操作", int(LateWindow.Hours()))
	}
	if a, err := netip.ParseAddr(req.SourceAddr); err != nil || !a.IsValid() {
		return false, errors.New("sourceAddr 须为单个 IP 地址")
	}
	key, err := db.Fact.Query().Where(Live(now), fact.KindEQ("key"), fact.SubjectEQ(req.KeyFingerprint), fact.HolderEQ(holder)).Exist(ctx)
	if err != nil {
		return false, err
	}
	channels, err := db.Fact.Query().Where(Live(now), fact.KindEQ("channel"), fact.HolderEQ(holder)).All(ctx)
	if err != nil {
		return false, err
	}
	if !key || !slices.ContainsFunc(channels, func(f *ent.Fact) bool { return Covers(f.Subject, req.SourceAddr) }) {
		return false, ErrNotOwner
	}
	return req.StartsAt.Before(now.Add(-time.Minute)), nil
}

// Login 告警事件上的登录身份
type Login struct {
	KeyFP   string
	SrcIP   string
	AssetID uuid.UUID
	At      time.Time
}

// Match 一条意图与它覆盖的登录
type Match struct {
	Intent *ent.Intent
	Login  Login
}

// Brief 一次研判可引用的事实与意图
type Brief struct {
	Facts   []*ent.Fact
	Intents []Match
}

// Lookup 找出与这些资产、登录身份相关的有效事实，以及覆盖这些登录的意图。
// 事实按组裁剪（全局事实对所有组可见）；意图要指纹、来源、主机、时间四项都对上
func Lookup(ctx context.Context, db *ent.Client, groups, assets []uuid.UUID, logins []Login, now time.Time) (*Brief, error) {
	var fps, ips []string
	for _, l := range logins {
		if l.KeyFP != "" && !slices.Contains(fps, l.KeyFP) {
			fps = append(fps, l.KeyFP)
		}
		if l.SrcIP != "" && !slices.Contains(ips, l.SrcIP) {
			ips = append(ips, l.SrcIP)
		}
	}
	scope := fact.Or(fact.GroupIDIsNil(), fact.GroupIDIn(groups...))
	related := []predicate.Fact{
		fact.And(fact.KindIn("asset_role", "change"), fact.AssetIDIn(assets...)),
		fact.And(fact.KindEQ("decision"), fact.Or(fact.AssetIDIsNil(), fact.AssetIDIn(assets...))),
	}
	if len(fps) > 0 {
		related = append(related, fact.And(fact.KindEQ("key"), fact.SubjectIn(fps...)))
	}
	if len(ips) > 0 {
		related = append(related, fact.KindEQ("channel"))
	}
	rows, err := db.Fact.Query().Where(Live(now), scope, fact.Or(related...)).
		Order(ent.Asc(fact.FieldKind), ent.Asc(fact.FieldCreatedAt)).Limit(200).All(ctx)
	if err != nil {
		return nil, err
	}
	b := &Brief{}
	for _, f := range rows {
		if f.Kind == "channel" && !slices.ContainsFunc(ips, func(ip string) bool { return Covers(f.Subject, ip) }) {
			continue
		}
		b.Facts = append(b.Facts, f)
	}
	if len(fps) == 0 {
		return b, nil
	}
	candidates, err := db.Intent.Query().Where(intent.KeyFingerprintIn(fps...)).
		Order(ent.Desc(intent.FieldCreatedAt)).Limit(500).All(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[uuid.UUID]bool{}
	for _, l := range logins {
		for _, in := range candidates {
			if seen[in.ID] || !covering(in, l) {
				continue
			}
			seen[in.ID] = true
			b.Intents = append(b.Intents, Match{Intent: in, Login: l})
		}
	}
	return b, nil
}

// covering 意图是否覆盖这次登录：指纹、来源、主机、时间（提前结束的到结束为止）
func covering(in *ent.Intent, l Login) bool {
	end := in.ExpiresAt
	if in.EndedAt != nil && in.EndedAt.Before(end) {
		end = *in.EndedAt
	}
	return in.KeyFingerprint == l.KeyFP && in.SourceAddr == l.SrcIP && slices.Contains(in.AssetIds, l.AssetID) &&
		!l.At.Before(in.StartsAt) && !l.At.After(end)
}

// Cite 记一次引用
func Cite(ctx context.Context, db *ent.Client, b *Brief, now time.Time) error {
	if b == nil || len(b.Facts) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(b.Facts))
	for i, f := range b.Facts {
		ids[i] = f.ID
	}
	return db.Fact.Update().Where(fact.IDIn(ids...)).AddCitedCount(1).SetLastCitedAt(now).Exec(ctx)
}

// Ref 事实或意图在结论里引用的编号：取 UUID 末 8 位，人能对得上控制台
func Ref(prefix string, id uuid.UUID) string {
	s := id.String()
	return prefix + "-" + s[len(s)-8:]
}

var kindNames = map[string]string{"key": "钥匙", "channel": "通道", "asset_role": "资产角色", "decision": "管理员决定", "change": "已授权变更"}

// Render 写进研判上下文的一节；没有可引用的就不写
func Render(b *Brief, hostnames map[uuid.UUID]string) string {
	if b == nil || len(b.Facts)+len(b.Intents) == 0 {
		return ""
	}
	var sb strings.Builder
	if len(b.Facts) > 0 {
		sb.WriteString("## 权威事实（管理员或平台录入，可作为前提引用，引用时写编号；只在事实写明的范围内成立，不外推到其他主机、身份或行为）\n")
		for _, f := range b.Facts {
			subject := f.Subject
			if f.AssetID != nil {
				subject = hostnames[*f.AssetID]
			}
			holder := ""
			if f.Holder != "" {
				holder = "，持有人 " + f.Holder
			}
			fmt.Fprintf(&sb, "- [%s] %s %s%s：%s\n", Ref("F", f.ID), kindNames[f.Kind], subject, holder, f.Content)
		}
	}
	if len(b.Intents) > 0 {
		sb.WriteString("## 运维意图（登记人事先声明的操作范围；只能解释与登记用途类别一致、在登记主机与时间窗内的行为，可据此把这类告警判为良性候选。" +
			"凭据窃取、清除痕迹、削弱防御、破坏、往 SSH 授权钥匙里加钥匙等高危行为不因意图成立而视为授权，照常判断；标「事后补登」的只作参考，不能单凭它判良性）\n")
		for _, m := range b.Intents {
			in := m.Intent
			late := ""
			if in.Late {
				late = "（事后补登）"
			}
			var hosts []string
			for _, id := range in.AssetIds {
				if h := hostnames[id]; h != "" {
					hosts = append(hosts, h)
				}
			}
			fmt.Fprintf(&sb, "- [%s]%s 登记人 %s，登录身份 %s 自 %s，用途「%s」，覆盖主机 %s，时间 %s 至 %s；本事件 %s 在 %s 的登录落在范围内\n",
				Ref("I", in.ID), late, in.CreatedBy, in.KeyFingerprint, in.SourceAddr, CategoryNames[in.Category],
				strings.Join(hosts, "、"), in.StartsAt.Format(time.RFC3339), in.ExpiresAt.Format(time.RFC3339),
				hostnames[m.Login.AssetID], m.Login.At.Format(time.RFC3339))
		}
	}
	return sb.String()
}

// ErrInvalid 入参不合法（400）
type ErrInvalid struct{ error }

// ErrForbiddenHost 登记人对部分主机没有分析权限
var ErrForbiddenHost = errors.New("对部分主机没有分析权限")

// Register 控制台与集成 Token 共用的登记：canWrite 判断登记人对主机有没有分析权限。
// 登记、审计同一事务；提交后推送通知，被盗用的登记当场就能被看到
func Register(ctx context.Context, db *ent.Client, holder, remote string, req IntentRequest, canWrite func(uuid.UUID) bool,
	notify func(ctx context.Context, title, body, path string) error, now time.Time) (*ent.Intent, error) {
	slices.SortFunc(req.Assets, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	req.Assets = slices.Compact(req.Assets)
	for _, id := range req.Assets {
		if !canWrite(id) {
			return nil, ErrForbiddenHost
		}
	}
	req.KeyFingerprint, req.SourceAddr, req.Note = strings.TrimSpace(req.KeyFingerprint), strings.TrimSpace(req.SourceAddr), strings.TrimSpace(req.Note)
	late, err := CheckIntent(ctx, db, holder, req, now)
	if errors.Is(err, ErrNotOwner) {
		return nil, err
	}
	if err != nil {
		return nil, ErrInvalid{err}
	}
	hosts, err := db.Asset.Query().Where(asset.IDIn(req.Assets...)).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(hosts) != len(req.Assets) {
		return nil, ErrInvalid{errors.New("部分主机不存在")}
	}
	names := make([]string, len(hosts))
	for i, h := range hosts {
		names[i] = h.Hostname
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	in, err := tx.Intent.Create().SetCreatedBy(holder).SetKeyFingerprint(req.KeyFingerprint).SetSourceAddr(req.SourceAddr).
		SetAssetIds(req.Assets).SetCategory(req.Category).SetNote(req.Note).SetStartsAt(req.StartsAt).
		SetExpiresAt(req.StartsAt.Add(req.Duration)).SetLate(late).Save(ctx)
	if err != nil {
		return nil, err
	}
	detail := fmt.Sprintf("%s 用途=%s 主机=%s 身份=%s@%s 至 %s", Ref("I", in.ID), CategoryNames[in.Category], strings.Join(names, ","),
		in.KeyFingerprint, in.SourceAddr, in.ExpiresAt.Format(time.RFC3339))
	if late {
		detail += "（事后补登）"
	}
	if err := audit.Checked(ctx, tx.AuditLog.Create(), holder, remote, "intent_registered", in.ID.String(), detail); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if notify != nil {
		body := fmt.Sprintf("%s 登记运维意图 %s：用途「%s」，主机 %s，至 %s。不是你本人或你认可的操作，请立即在总控结束它并更换凭据。",
			holder, Ref("I", in.ID), CategoryNames[in.Category], strings.Join(names, "、"), in.ExpiresAt.In(time.Local).Format("01-02 15:04"))
		if late {
			body += "（事后补登，研判只作参考）"
		}
		if err := notify(ctx, "运维意图登记", body, "/control?tab=intents"); err != nil {
			slog.Warn("运维意图通知失败", "err", err)
		}
	}
	return in, nil
}

// IntentBody 登记意图的请求体，控制台与集成接口共用
type IntentBody struct {
	KeyFingerprint  string      `json:"keyFingerprint"`
	SourceAddr      string      `json:"sourceAddr"`
	AssetIDs        []uuid.UUID `json:"assetIds"`
	Category        string      `json:"category"`
	Note            string      `json:"note"`
	DurationMinutes int         `json:"durationMinutes"`
	StartedAt       *time.Time  `json:"startedAt"`
}

// Request 换成登记参数；没给开始时间就是现在
func (b IntentBody) Request(now time.Time) IntentRequest {
	starts := now
	if b.StartedAt != nil {
		starts = *b.StartedAt
	}
	return IntentRequest{KeyFingerprint: b.KeyFingerprint, SourceAddr: b.SourceAddr, Assets: b.AssetIDs, Category: b.Category,
		Note: b.Note, StartsAt: starts, Duration: time.Duration(b.DurationMinutes) * time.Minute}
}

// ForGroup 组内（含全局）有效事实，给运维巡检与对话会话作前提；按类型、更新时间排序，最多 100 条
func ForGroup(ctx context.Context, db *ent.Client, group uuid.UUID, hostnames map[uuid.UUID]string, now time.Time) ([]map[string]any, error) {
	rows, err := db.Fact.Query().Where(Live(now), fact.Or(fact.GroupIDIsNil(), fact.GroupIDEQ(group))).
		Order(ent.Asc(fact.FieldKind), ent.Desc(fact.FieldUpdatedAt)).Limit(100).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, f := range rows {
		m := map[string]any{"ref": Ref("F", f.ID), "kind": kindNames[f.Kind], "content": f.Content}
		if f.Subject != "" {
			m["subject"] = f.Subject
		}
		if f.AssetID != nil {
			m["host"] = hostnames[*f.AssetID]
		}
		if f.Holder != "" {
			m["holder"] = f.Holder
		}
		out = append(out, m)
	}
	return out, nil
}
