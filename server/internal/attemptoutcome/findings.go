package attemptoutcome

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/ent/fact"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/trustedsource"
	"openxdr/server/ent/zone"
	"openxdr/server/internal/authfields"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/findings"
)

const (
	hardeningWindow             = 7 * 24 * time.Hour
	defaultMinHardeningFailures = 5
	defaultMinHardeningSources  = 2
)

// HardeningKey 同一目标服务固定使用的运维待办去重键（满足 ^[a-z0-9][a-z0-9._-]{0,63}$）。
func HardeningKey(serviceSlug string) string {
	slug := sanitizeSlug(serviceSlug)
	if slug == "" {
		slug = "auth"
	}
	key := "auth-hardening-" + slug
	if len(key) > 64 {
		key = strings.TrimRight(key[:64], "._-")
	}
	return key
}

type countItem struct {
	name  string
	count int
}

// UpsertHardeningFindings 按（组、资产、目标服务）统计近 7 天外部公网口令猜解规模，生成或原地更新加固建议待办。
// 同一目标服务始终复用同一条记录；已被人工标为 ignored 的绝不重开或改写。
func UpsertHardeningFindings(
	ctx context.Context,
	db *ent.Client,
	sqlDB *sql.DB,
	targets []ServiceTarget,
	now time.Time,
	minFailures, minSources int,
	timeout time.Duration,
) (int, error) {
	if len(targets) == 0 {
		return 0, nil
	}
	if minFailures <= 0 {
		minFailures = defaultMinHardeningFailures
	}
	if minSources <= 0 {
		minSources = defaultMinHardeningSources
	}
	if timeout <= 0 {
		timeout = defaultStatementTimeout
	}
	updated := 0
	for _, tgt := range targets {
		if tgt.GroupID == uuid.Nil || tgt.AssetID == uuid.Nil {
			continue
		}
		ok, err := upsertOneHardeningFinding(ctx, db, sqlDB, tgt, now, minFailures, minSources, timeout)
		if err != nil {
			// 查询超时按保守跳过，不阻塞结案主流程
			if ctx.Err() == nil && isTimeoutError(err) {
				continue
			}
			return updated, err
		}
		if ok {
			updated++
		}
	}
	return updated, nil
}

func upsertOneHardeningFinding(
	ctx context.Context,
	db *ent.Client,
	sqlDB *sql.DB,
	tgt ServiceTarget,
	now time.Time,
	minFailures, minSources int,
	timeout time.Duration,
) (bool, error) {
	key := HardeningKey(tgt.ServiceSlug)
	existing, err := db.Finding.Query().
		Where(
			finding.GroupIDEQ(tgt.GroupID),
			finding.AssetIDEQ(tgt.AssetID),
			finding.KeyEQ(key),
		).
		Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return false, err
	}
	// 人工已忽略：严格遵守平台规矩，不重开、不改写
	if existing != nil && existing.Status == "ignored" {
		return false, nil
	}

	windowFrom := now.Add(-hardeningWindow)
	// 若人工已标记为已处理（resolved），仅统计处理完成之后的新猜解；未再达到阈值则不打扰
	if existing != nil && existing.Status == "resolved" && existing.ResolvedAt != nil && existing.ResolvedAt.After(windowFrom) {
		windowFrom = *existing.ResolvedAt
	}
	queryTo := now.Add(5 * time.Minute)

	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var tx *sql.Tx
	if sqlDB != nil {
		ms, err := statementTimeoutMillis(qctx, timeout)
		if err != nil {
			return false, err
		}
		tx, err = sqlDB.BeginTx(qctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return false, err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(qctx, fmt.Sprintf("SET LOCAL statement_timeout = '%dms'", ms)); err != nil {
			return false, err
		}
	}

	as, err := db.Asset.Get(qctx, tgt.AssetID)
	if err != nil || as.RetiredAt != nil {
		if ent.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	assetOS := ""
	if as.Os != nil {
		assetOS = *as.Os
	}
	hostLabel := cmp.Or(as.Hostname, tgt.Hostname, tgt.AssetID.String())

	rows, _, err := queryAssetAuthEvents(qctx, db, tx, []uuid.UUID{tgt.AssetID}, windowFrom, queryTo, false, maxFailureScanRows)
	if err != nil {
		return false, err
	}

	nonExternalChecker, err := buildNonExternalIPChecker(qctx, db, tgt.GroupID, now)
	if err != nil {
		return false, err
	}

	bySource := map[string]int{}
	byAccount := map[string]int{}
	totalFailures := 0
	var earliestTs, latestTs time.Time

	for _, r := range rows {
		parsed, ok := ParseAuthEvent(r.classUID, r.source, assetOS, r.username, r.raw)
		if !ok || !parsed.Failure || parsed.ServiceSlug != tgt.ServiceSlug || parsed.SrcIP == "" {
			continue
		}
		if nonExternalChecker(parsed.SrcIP) {
			continue
		}
		totalFailures++
		bySource[parsed.SrcIP]++
		if parsed.Account != "" {
			byAccount[parsed.Account]++
		}
		if earliestTs.IsZero() || r.ts.Before(earliestTs) {
			earliestTs = r.ts
		}
		if latestTs.IsZero() || r.ts.After(latestTs) {
			latestTs = r.ts
		}
	}

	if len(bySource) == 0 {
		return false, nil
	}

	// 兼容告警去重合并后单条锚点事件代表多次命中的计数
	alerts, err := db.Alert.Query().
		Where(
			alert.AssetIDEQ(tgt.AssetID),
			alert.RuleIDIn(
				RuleLinuxLoginFailure,
				RuleSSHAuthFailure,
				RuleWinLoginFailure,
				RuleTemporalLinuxAuthBurst,
				RuleTemporalLinuxAccountAuthBurst,
				RuleTemporalSSHDFailBurst,
				RuleTemporalWindowsFailBurst,
			),
			alert.Or(alert.TsGTE(windowFrom), alert.LastTsGTE(windowFrom)),
		).
		WithEvent().
		All(qctx)
	if err == nil {
		dedupSum := 0
		for _, a := range alerts {
			if a.Edges.Event == nil {
				continue
			}
			parsed, ok := ParseAuthEvent(a.Edges.Event.ClassUID, a.Edges.Event.Source, assetOS, "", a.Edges.Event.Raw)
			if !ok || !parsed.Failure || parsed.ServiceSlug != tgt.ServiceSlug || parsed.SrcIP == "" || nonExternalChecker(parsed.SrcIP) {
				continue
			}
			dedupSum += max(a.Count, 1)
			end := a.Ts
			if a.LastTs != nil && a.LastTs.After(end) {
				end = *a.LastTs
			}
			if end.After(latestTs) {
				latestTs = end
			}
		}
		if dedupSum > totalFailures {
			extra := dedupSum - totalFailures
			totalFailures = dedupSum
			if len(byAccount) == 1 {
				for k := range byAccount {
					byAccount[k] += extra
				}
			}
			if len(bySource) == 1 {
				for k := range bySource {
					bySource[k] += extra
				}
			}
		}
	}

	if totalFailures < minFailures && len(bySource) < minSources {
		return false, nil
	}

	topAccounts := topCounts(byAccount, 5)
	topSources := topCounts(bySource, 8)

	topTargetPhrase := ""
	if len(topAccounts) > 0 {
		topTargetPhrase = topAccounts[0].name + " 是主要目标，"
	}
	adviceShort, adviceDetail := hardeningAdvice(tgt.ServiceSlug)
	title := truncateUTF8Bytes(
		fmt.Sprintf("%s 的 %s 公网登录近 7 天被 %d 个地址猜解 %d 次，%s%s",
			hostLabel, tgt.ServiceLabel, len(bySource), totalFailures, topTargetPhrase, adviceShort),
		200,
	)

	var detailBuilder strings.Builder
	fmt.Fprintf(&detailBuilder, "目标主机与服务：%s（%s）\n", hostLabel, tgt.ServiceLabel)
	fmt.Fprintf(&detailBuilder, "统计时间窗：%s 至 %s\n", windowFrom.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	fmt.Fprintf(&detailBuilder, "外部公网猜解规模：共 %d 个外部公网地址发起 %d 次失败认证尝试（最近一次：%s）\n",
		len(bySource), totalFailures, latestTs.UTC().Format(time.RFC3339))
	if len(topAccounts) > 0 {
		parts := make([]string, len(topAccounts))
		for i, item := range topAccounts {
			parts[i] = fmt.Sprintf("%s（%d 次）", item.name, item.count)
		}
		fmt.Fprintf(&detailBuilder, "主要被试账号：%s\n", strings.Join(parts, "、"))
	}
	if len(topSources) > 0 {
		parts := make([]string, len(topSources))
		for i, item := range topSources {
			parts[i] = fmt.Sprintf("%s（%d 次）", item.name, item.count)
		}
		fmt.Fprintf(&detailBuilder, "高频来源地址：%s\n", strings.Join(parts, "、"))
	}
	fmt.Fprintf(&detailBuilder, "加固建议：%s", adviceDetail)
	detail := truncateUTF8Bytes(detailBuilder.String(), 4000)

	severity := "medium"
	if totalFailures >= 200 || len(bySource) >= 20 {
		severity = "high"
	}

	workPayload := findings.EncodeWork(findings.Work{
		Version:         2,
		Stage:           "waiting",
		Blocker:         "manual_business_decision",
		Plan:            adviceDetail,
		WakeOn:          "new_observation_or_next_check",
		OriginalTitle:   title,
		OriginalProblem: detail,
	})

	if existing == nil {
		_, err := db.Finding.Create().
			SetGroupID(tgt.GroupID).
			SetAssetID(tgt.AssetID).
			SetKey(key).
			SetTitle(title).
			SetDetail(detail).
			SetSeverity(severity).
			SetStatus("open").
			SetWorkOwner("human").
			SetFirstSeen(earliestTs).
			SetLastSeen(latestTs).
			SetWork(workPayload).
			Save(ctx)
		if err != nil {
			if !ent.IsConstraintError(err) {
				return false, err
			}
			existing, err = db.Finding.Query().
				Where(finding.GroupIDEQ(tgt.GroupID), finding.AssetIDEQ(tgt.AssetID), finding.KeyEQ(key)).
				Only(ctx)
			if err != nil || existing.Status == "ignored" {
				return false, err
			}
		} else {
			return true, nil
		}
	}

	if existing.Status == "open" &&
		existing.Title == title &&
		existing.Detail == detail &&
		existing.Severity == severity &&
		!latestTs.After(existing.LastSeen) {
		return false, nil
	}

	upd := db.Finding.UpdateOneID(existing.ID).
		Where(finding.StatusNEQ("ignored")).
		SetTitle(title).
		SetDetail(detail).
		SetSeverity(severity).
		SetLastSeen(maxTime(existing.LastSeen, latestTs))

	if existing.Status == "resolved" {
		upd.SetStatus("open").
			ClearResolvedAt().
			ClearResolvedBy().
			ClearNote().
			SetWorkOwner("human").
			SetWork(workPayload)
	}
	if err := upd.Exec(ctx); err != nil && !ent.IsNotFound(err) {
		return false, err
	}
	return true, nil
}

func buildNonExternalIPChecker(ctx context.Context, db *ent.Client, groupID uuid.UUID, now time.Time) (func(string) bool, error) {
	zones, err := db.Zone.Query().Where(zone.GroupIDEQ(groupID)).All(ctx)
	if err != nil {
		return nil, err
	}
	assets, err := db.Asset.Query().Where(entasset.RetiredAtIsNil()).Select(entasset.FieldIPAddrs).All(ctx)
	if err != nil {
		return nil, err
	}
	managedIPs := map[string]bool{}
	for _, a := range assets {
		for _, ip := range a.IPAddrs {
			if c := authfields.CanonicalIP(ip); c != "" {
				managedIPs[c] = true
			}
		}
	}
	channels, err := db.Fact.Query().Where(fact.KindEQ("channel"), facts.Live(now)).All(ctx)
	if err != nil {
		return nil, err
	}
	trusted, err := db.TrustedSource.Query().Where(
		trustedsource.GroupIDEQ(groupID),
		trustedsource.RevokedAtIsNil(),
		trustedsource.DeletedAtIsNil(),
		trustedsource.ExpiresAtGT(now),
		trustedsource.SourceCidrNotNil(),
	).All(ctx)
	if err != nil {
		return nil, err
	}

	return func(ip string) bool {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return true
		}
		addr = addr.Unmap()
		if !isPublicAddr(addr) || managedIPs[ip] {
			return true
		}
		if z := matchZoneCIDR(addr, zones); z != nil && string(z.Kind) != "external" {
			return true
		}
		for _, ch := range channels {
			if facts.Covers(ch.Subject, ip) {
				return true
			}
		}
		for _, ts := range trusted {
			if ts.SourceCidr != nil && facts.Covers(*ts.SourceCidr, ip) {
				return true
			}
		}
		return false
	}, nil
}

func hardeningAdvice(serviceSlug string) (short, detail string) {
	switch serviceSlug {
	case "authentik":
		return "建议加限速或来源限制",
			"在反向代理（如 Caddy）或 Authentik 认证流上配置按源 IP 与目标账号的登录速率限制、接入来源网段限制，并确保管理员账号（如 akadmin）强制启用多因素认证（MFA）。"
	case "ssh":
		return "建议加限速或收敛公网暴露",
			"收敛 SSH 公网暴露面（改走 WireGuard / 跳板机等受控通道）、禁用口令认证（PasswordAuthentication no，仅允许密钥登录），或在主机/边界网关启用源 IP 速率限制与自动封禁。"
	case "windows-rdp", "windows-logon":
		return "建议收敛公网暴露并启用账户锁定",
			"禁止将 RDP / SMB 认证端口直接暴露在公网（改经 VPN 接入），启用网络级身份验证（NLA）、配置组策略账户锁定阈值与源地址限制。"
	default:
		return "建议加限速或来源限制",
			"对该公网认证入口配置按来源 IP 与账号的失败速率限制、收敛访问来源网段，并对特权账号启用多因素认证或强凭据策略。"
	}
}

func topCounts(m map[string]int, limit int) []countItem {
	items := make([]countItem, 0, len(m))
	for k, v := range m {
		items = append(items, countItem{name: k, count: v})
	}
	slices.SortFunc(items, func(a, b countItem) int {
		if a.count != b.count {
			return b.count - a.count
		}
		return strings.Compare(a.name, b.name)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func truncateUTF8Bytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return strings.TrimSpace(s)
}
