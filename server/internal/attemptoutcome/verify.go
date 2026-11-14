package attemptoutcome

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entasset "openxdr/server/ent/asset"
	"openxdr/server/ent/event"
	"openxdr/server/ent/fact"
	"openxdr/server/ent/sshlogin"
	"openxdr/server/ent/trustedsource"
	"openxdr/server/ent/zone"
	"openxdr/server/internal/authfields"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/facts"
)

// Outcome 认证尝试核验的三态细分结论。
type Outcome string

const (
	// OutcomeUnsuccessful 未得手：全部来源为外部公网地址、窗口内无任何成功认证、无其他非本族告警、采集完整
	OutcomeUnsuccessful Outcome = "unsuccessful"
	// OutcomeSucceeded 有成功：窗口内存在同来源成功认证
	OutcomeSucceeded Outcome = "succeeded"
	// OutcomeInternalOrRegistered 内网或已登记通道：无同源成功（若有成功优先归入 OutcomeSucceeded），但来源含内网/纳管资产/已登记通道/可信来源
	OutcomeInternalOrRegistered Outcome = "internal_or_registered"
	// OutcomeOtherAlerts 同来源存在其他非认证失败族命中告警，不自动放行
	OutcomeOtherAlerts Outcome = "other_alerts"
	// OutcomeIncomplete 查不全或不适用（缺来源 IP、含非本族告警、采集中断、分区已退役、查询超时等），拿不准绝不自动结案
	OutcomeIncomplete Outcome = "incomplete"
)

const (
	defaultStatementTimeout = 5 * time.Second
	maxFailureScanRows      = 50000
	maxSuccessScanRows      = 5000
	maxAlertScanRows        = 2000
	agentFreshnessLimit     = 15 * time.Minute
	authentikFreshnessLimit = 15 * time.Minute
	syslogQuietAliveWindow  = time.Hour
	// 与 authentik.PolledAtKey 保持一致（不直接 import authentik 以免测试包环状依赖）
	authentikPolledAtKey = "authentik.events.polled_at"
)

// Options 确定性核验运行参数。
type Options struct {
	Now              time.Time
	QuietWindow      time.Duration
	StatementTimeout time.Duration
}

func (o Options) normalized() Options {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.QuietWindow <= 0 {
		o.QuietWindow = DefaultQuietHours * time.Hour
	}
	if o.StatementTimeout <= 0 {
		o.StatementTimeout = defaultStatementTimeout
	}
	return o
}

// AttemptTuple 单个（来源地址 + 目标资产 + 目标服务 + 被试账号）的失败聚合。
type AttemptTuple struct {
	SrcIP        string    `json:"src_ip"`
	AssetID      uuid.UUID `json:"asset_id"`
	Hostname     string    `json:"hostname"`
	ServiceSlug  string    `json:"service"`
	ServiceLabel string    `json:"service_label"`
	Account      string    `json:"account"`
	Count        int       `json:"count"`
	FirstTs      time.Time `json:"first_ts"`
	LastTs       time.Time `json:"last_ts"`
}

// ServiceTarget 被猜解的目标主机与服务。
type ServiceTarget struct {
	GroupID      uuid.UUID `json:"group_id"`
	AssetID      uuid.UUID `json:"asset_id"`
	Hostname     string    `json:"hostname"`
	ServiceSlug  string    `json:"service"`
	ServiceLabel string    `json:"service_label"`
}

// SuccessHit 窗口内核验到的同来源成功认证记录。
type SuccessHit struct {
	SrcIP        string    `json:"src_ip"`
	AssetID      uuid.UUID `json:"asset_id"`
	Hostname     string    `json:"hostname"`
	ServiceLabel string    `json:"service"`
	Account      string    `json:"account"`
	Ts           time.Time `json:"ts"`
	Via          string    `json:"via"`
}

// SourceAttribution 非外部公网来源（内网、纳管主机、已登记通道或可信自动化网段）的归属说明。
type SourceAttribution struct {
	SrcIP  string `json:"src_ip"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// OtherAlertHit 同来源触发的其他命中告警摘要。
type OtherAlertHit struct {
	AlertID uuid.UUID `json:"alert_id"`
	RuleID  string    `json:"rule_id"`
	SrcIP   string    `json:"src_ip"`
	Ts      time.Time `json:"ts"`
}

// Verification 单个安全事件的认证尝试核验完整结果。
type Verification struct {
	Outcome             Outcome             `json:"outcome"`
	Applicable          bool                `json:"applicable"`
	AllAuthFailureRules bool                `json:"all_auth_failure_rules"`
	IncompleteReasons   []string            `json:"incomplete_reasons,omitempty"`
	FirstFailure        time.Time           `json:"first_failure"`
	LastFailure         time.Time           `json:"last_failure"`
	WindowFrom          time.Time           `json:"window_from"`
	WindowTo            time.Time           `json:"window_to"`
	QuietWindow         time.Duration       `json:"quiet_window"`
	QuietDuration       time.Duration       `json:"quiet_duration"`
	TotalFailures       int                 `json:"total_failures"`
	Tuples              []AttemptTuple      `json:"tuples,omitempty"`
	SourceIPs           []string            `json:"source_ips,omitempty"`
	Targets             []ServiceTarget     `json:"targets,omitempty"`
	Accounts            []string            `json:"accounts,omitempty"`
	Successes           []SuccessHit        `json:"successes,omitempty"`
	InternalSources     []SourceAttribution `json:"internal_sources,omitempty"`
	OtherAlerts         []OtherAlertHit     `json:"other_alerts,omitempty"`
}

// ReadyToClose 是否满足「未得手且已满静默观察期」的全部自动结案硬门槛。
func (v *Verification) ReadyToClose() bool {
	if v == nil {
		return false
	}
	return v.Applicable &&
		v.AllAuthFailureRules &&
		v.Outcome == OutcomeUnsuccessful &&
		len(v.IncompleteReasons) == 0 &&
		len(v.Successes) == 0 &&
		len(v.InternalSources) == 0 &&
		len(v.OtherAlerts) == 0 &&
		len(v.SourceIPs) > 0 &&
		v.QuietWindow > 0 &&
		v.QuietDuration >= v.QuietWindow
}

// FormatResolution 生成可审计的自动结案理由（写入 incident.resolution 与 audit_logs）。
func (v *Verification) FormatResolution() string {
	targets := make([]string, 0, len(v.Targets))
	for _, t := range v.Targets {
		host := cmp.Or(t.Hostname, t.AssetID.String())
		targets = append(targets, host+"/"+t.ServiceLabel)
	}
	srcs := summarizeList(v.SourceIPs, 6)
	accts := summarizeList(v.Accounts, 6)
	if accts == "" {
		accts = "（未记录用户名）"
	}
	return fmt.Sprintf(
		"认证尝试未得手自动结案（%s）：核验时间窗 %s 至 %s，目标 %s，外部公网来源 %s，被试账号 %s，累计失败 %d 次；"+
			"末次失败（%s）后已静默 %s（阈值 %s），期间同来源无任何成功认证、无其他关联告警，确认攻击尝试未得手。",
		ResolutionSource,
		v.WindowFrom.UTC().Format(time.RFC3339),
		v.WindowTo.UTC().Format(time.RFC3339),
		strings.Join(targets, "、"),
		srcs,
		accts,
		v.TotalFailures,
		v.LastFailure.UTC().Format(time.RFC3339),
		v.QuietDuration.Truncate(time.Minute),
		v.QuietWindow.Truncate(time.Minute),
	)
}

// RenderTriageEvidence 为旧 triage 研判上下文渲染确定性核验证据节；不适用时返回空串。
func (v *Verification) RenderTriageEvidence() string {
	if v == nil || !v.Applicable || len(v.SourceIPs) == 0 {
		return ""
	}
	switch v.Outcome {
	case OutcomeSucceeded, OutcomeInternalOrRegistered, OutcomeOtherAlerts:
	default:
		return ""
	}

	var b strings.Builder
	b.WriteString("## 认证尝试确定性核验结果（服务端数据库核验事实）\n")
	fmt.Fprintf(&b, "- 核验时间窗：%s 至 %s（首次失败 %s，末次失败 %s，累计失败 %d 次）\n",
		v.WindowFrom.UTC().Format(time.RFC3339),
		v.WindowTo.UTC().Format(time.RFC3339),
		v.FirstFailure.UTC().Format(time.RFC3339),
		v.LastFailure.UTC().Format(time.RFC3339),
		v.TotalFailures,
	)
	fmt.Fprintf(&b, "- 涉及来源地址：%s；被试账号：%s\n",
		summarizeList(v.SourceIPs, 10),
		cmp.Or(summarizeList(v.Accounts, 10), "（未记录）"),
	)
	if len(v.Successes) > 0 {
		b.WriteString("- 同来源成功认证核验：发现成功认证记录（事件不自动结案，请重点核查是否爆破得手或凭据失陷）：\n")
		for i, s := range v.Successes {
			if i >= 10 {
				fmt.Fprintf(&b, "  - 其余 %d 条成功认证已省略\n", len(v.Successes)-10)
				break
			}
			host := cmp.Or(s.Hostname, s.AssetID.String())
			fmt.Fprintf(&b, "  - %s 来源 %s 在 %s（%s）成功认证账号 %s（数据源：%s）\n",
				s.Ts.UTC().Format(time.RFC3339), s.SrcIP, host, s.ServiceLabel, cmp.Or(s.Account, "-"), s.Via)
		}
	} else {
		b.WriteString("- 同来源成功认证核验：核验时间窗内未见已入库的同来源成功认证记录。\n")
	}
	if len(v.InternalSources) > 0 {
		b.WriteString("- 来源地址归属核验：包含内网、纳管主机或已登记通道（不按外部盲猜自动结案，请结合业务身份与授权核实）：\n")
		for _, attr := range v.InternalSources {
			fmt.Fprintf(&b, "  - %s：%s（%s）\n", attr.SrcIP, attr.Detail, attr.Kind)
		}
	}
	if len(v.OtherAlerts) > 0 {
		b.WriteString("- 同来源其他告警核验：窗口内存在非认证失败族告警命中：\n")
		for i, oa := range v.OtherAlerts {
			if i >= 8 {
				fmt.Fprintf(&b, "  - 其余 %d 条关联告警已省略\n", len(v.OtherAlerts)-8)
				break
			}
			fmt.Fprintf(&b, "  - %s 规则 %s（来源 %s，告警 %s）\n",
				oa.Ts.UTC().Format(time.RFC3339), oa.RuleID, oa.SrcIP, oa.AlertID)
		}
	}
	if len(v.IncompleteReasons) > 0 {
		fmt.Fprintf(&b, "- 采集与覆盖边界提示：%s（未查到不等于未发生）\n", strings.Join(v.IncompleteReasons, "；"))
	}
	return b.String()
}

// SubjectSummary 为 Pi 对话会话（agentchat）提供结构化核验摘要。
func (v *Verification) SubjectSummary() map[string]any {
	if v == nil || !v.Applicable || len(v.SourceIPs) == 0 {
		return nil
	}
	out := map[string]any{
		"outcome":         v.Outcome,
		"window_from":     v.WindowFrom,
		"window_to":       v.WindowTo,
		"first_failure":   v.FirstFailure,
		"last_failure":    v.LastFailure,
		"total_failures":  v.TotalFailures,
		"source_ips":      v.SourceIPs,
		"accounts":        v.Accounts,
		"ready_to_close":  v.ReadyToClose(),
		"quiet_hours_min": v.QuietWindow.Hours(),
	}
	if len(v.Successes) > 0 {
		out["successes"] = v.Successes
	}
	if len(v.InternalSources) > 0 {
		out["internal_or_registered_sources"] = v.InternalSources
	}
	if len(v.OtherAlerts) > 0 {
		out["other_alerts"] = v.OtherAlerts
	}
	if len(v.IncompleteReasons) > 0 {
		out["incomplete_reasons"] = v.IncompleteReasons
	}
	return out
}

type rawEventRow struct {
	id       uuid.UUID
	ts       time.Time
	classUID int
	source   string
	assetID  uuid.UUID
	username string
	raw      []byte
}

// Verify 对给定事件执行确定性核验。当数据库查询触发 statement_timeout 时返回 OutcomeIncomplete 而非放行。
func Verify(ctx context.Context, db *ent.Client, sqlDB *sql.DB, incidentID uuid.UUID, opts Options) (*Verification, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	opts = opts.normalized()

	qctx, cancel := context.WithTimeout(ctx, opts.StatementTimeout)
	defer cancel()

	v, err := verifyInner(qctx, db, sqlDB, incidentID, opts)
	if err != nil {
		// 父 ctx 未取消而子查询超时或触发 PostgreSQL statement_timeout：按「查不全」处理，不阻断研判、绝不自动结案
		if ctx.Err() == nil && isTimeoutError(err) {
			return &Verification{
				Outcome:           OutcomeIncomplete,
				Applicable:        true,
				QuietWindow:       opts.QuietWindow,
				IncompleteReasons: []string{"认证核验数据库查询超时"},
			}, nil
		}
		return nil, err
	}
	return v, nil
}

func verifyInner(ctx context.Context, db *ent.Client, sqlDB *sql.DB, incidentID uuid.UUID, opts Options) (*Verification, error) {
	alerts, err := db.Alert.Query().
		Where(alert.IncidentIDEQ(incidentID)).
		WithAsset().
		WithEvent().
		Order(ent.Asc(alert.FieldTs), ent.Asc(alert.FieldID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if !IncidentHasAuthFailures(alerts) {
		return &Verification{Outcome: OutcomeIncomplete, Applicable: false, QuietWindow: opts.QuietWindow}, nil
	}

	v := &Verification{
		Applicable:          true,
		AllAuthFailureRules: IncidentAllAuthFailures(alerts),
		QuietWindow:         opts.QuietWindow,
	}
	addIncomplete := func(reason string) {
		if reason != "" && !slices.Contains(v.IncompleteReasons, reason) {
			v.IncompleteReasons = append(v.IncompleteReasons, reason)
		}
	}
	if !v.AllAuthFailureRules {
		addIncomplete("事件包含认证失败族以外的告警规则")
	}

	assetsByID := map[uuid.UUID]*ent.Asset{}
	groupSet := map[uuid.UUID]bool{}
	var authAlerts []*ent.Alert
	var authAlertIDs []uuid.UUID
	var minAlertTs, maxAlertTs time.Time
	alertCountByAsset := map[uuid.UUID]int{}

	for _, a := range alerts {
		if a.AssetID == nil || a.Edges.Asset == nil {
			addIncomplete("存在未绑定目标资产的告警")
			continue
		}
		as := a.Edges.Asset
		assetsByID[as.ID] = as
		if as.GroupID != nil {
			groupSet[*as.GroupID] = true
		}
		if !IsAuthFailureRule(a.RuleID) {
			continue
		}
		authAlerts = append(authAlerts, a)
		authAlertIDs = append(authAlertIDs, a.ID)
		alertCountByAsset[as.ID] += max(a.Count, 1)
		endTs := a.Ts
		if a.LastTs != nil && a.LastTs.After(endTs) {
			endTs = *a.LastTs
		}
		if minAlertTs.IsZero() || a.Ts.Before(minAlertTs) {
			minAlertTs = a.Ts
		}
		if maxAlertTs.IsZero() || endTs.After(maxAlertTs) {
			maxAlertTs = endTs
		}
	}
	if len(authAlerts) == 0 || len(assetsByID) == 0 {
		addIncomplete("缺少可核验的认证失败告警或目标资产")
		v.Outcome = OutcomeIncomplete
		return v, nil
	}

	var tx *sql.Tx
	if sqlDB != nil {
		ms, err := statementTimeoutMillis(ctx, opts.StatementTimeout)
		if err != nil {
			return nil, err
		}
		tx, err = sqlDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL statement_timeout = '%dms'", ms)); err != nil {
			return nil, err
		}
	}

	// 补充跨主机时序告警（如 temporal:linux-account-auth-burst）关联的证据事件与涉及资产
	temporalEvRows, err := loadTemporalEvidenceEvents(ctx, tx, authAlertIDs, minAlertTs.Add(-2*time.Hour), maxAlertTs.Add(time.Hour))
	if err != nil {
		return nil, err
	}
	for _, ev := range temporalEvRows {
		if ev.assetID != uuid.Nil && assetsByID[ev.assetID] == nil {
			if as, err := db.Asset.Get(ctx, ev.assetID); err == nil {
				assetsByID[as.ID] = as
				if as.GroupID != nil {
					groupSet[*as.GroupID] = true
				}
			}
		}
		if ev.ts.Before(minAlertTs) {
			minAlertTs = ev.ts
		}
		if ev.ts.After(maxAlertTs) {
			maxAlertTs = ev.ts
		}
	}

	assetIDs := sortedUUIDs(assetsByID)
	groupIDs := sortedGroupIDs(groupSet)

	// 1. 仅当告警发生去重折叠（last_ts > ts）或存在缺少明细证据的时序告警时，按实际折叠区间补扫原始失败事件；
	// 单条未折叠告警直接取锚点事件，避免把同主机相邻时刻无关事件的来源 IP 串入本事件。
	var foldFrom, foldTo time.Time
	needFoldScan := false
	for _, a := range authAlerts {
		end := a.Ts
		if a.LastTs != nil && a.LastTs.After(end) {
			end = *a.LastTs
		}
		var from, to time.Time
		switch {
		case a.LastTs != nil && a.LastTs.After(a.Ts):
			from, to = a.Ts.Add(-time.Second), end.Add(time.Second)
		case strings.HasPrefix(a.RuleID, "temporal:") && len(temporalEvRows) == 0:
			from, to = a.Ts.Add(-15*time.Minute), end.Add(time.Second)
		default:
			continue
		}
		if !needFoldScan || from.Before(foldFrom) {
			foldFrom = from
		}
		if !needFoldScan || to.After(foldTo) {
			foldTo = to
		}
		needFoldScan = true
	}

	var failWindowRows []rawEventRow
	if needFoldScan {
		var truncated bool
		failWindowRows, truncated, err = queryAssetAuthEvents(ctx, db, tx, assetIDs, foldFrom, foldTo, false, maxFailureScanRows)
		if err != nil {
			return nil, err
		}
		if truncated {
			addIncomplete("失败窗口内认证事件超出单次核验上限")
		}
	}

	seenEvents := map[uuid.UUID]rawEventRow{}
	for _, r := range failWindowRows {
		seenEvents[r.id] = r
	}
	for _, r := range temporalEvRows {
		seenEvents[r.id] = r
	}
	for _, a := range authAlerts {
		if a.Edges.Event == nil {
			addIncomplete("认证失败告警缺少原始事件引用")
			continue
		}
		ev := a.Edges.Event
		aid := uuid.Nil
		if ev.AssetID != nil {
			aid = *ev.AssetID
		} else if a.AssetID != nil {
			aid = *a.AssetID
		}
		uname := ""
		if ev.Username != nil {
			uname = *ev.Username
		}
		seenEvents[ev.ID] = rawEventRow{
			id:       ev.ID,
			ts:       ev.Ts,
			classUID: ev.ClassUID,
			source:   ev.Source,
			assetID:  aid,
			username: uname,
			raw:      ev.Raw,
		}
	}

	type tupleKey struct {
		srcIP   string
		assetID uuid.UUID
		service string
		account string
	}
	tupleMap := map[tupleKey]*AttemptTuple{}
	targetMap := map[string]ServiceTarget{}
	sourceKindsByAsset := map[uuid.UUID]map[string]bool{}
	eventsCountByAsset := map[uuid.UUID]int{}
	hasAuthentik := false

	orderedIDs := make([]uuid.UUID, 0, len(seenEvents))
	for id := range seenEvents {
		orderedIDs = append(orderedIDs, id)
	}
	slices.SortFunc(orderedIDs, func(a, b uuid.UUID) int {
		ra, rb := seenEvents[a], seenEvents[b]
		return cmp.Or(ra.ts.Compare(rb.ts), strings.Compare(a.String(), b.String()))
	})

	for _, id := range orderedIDs {
		row := seenEvents[id]
		as := assetsByID[row.assetID]
		assetOS, hostname := "", ""
		var gid uuid.UUID
		if as != nil {
			if as.Os != nil {
				assetOS = *as.Os
			}
			hostname = as.Hostname
			if as.GroupID != nil {
				gid = *as.GroupID
			}
		}
		parsed, ok := ParseAuthEvent(row.classUID, row.source, assetOS, row.username, row.raw)
		if !ok || !parsed.Failure {
			continue
		}
		if sourceKindsByAsset[row.assetID] == nil {
			sourceKindsByAsset[row.assetID] = map[string]bool{}
		}
		sourceKindsByAsset[row.assetID][parsed.SourceKind] = true
		if parsed.SourceKind == "authentik" {
			hasAuthentik = true
		}
		if parsed.SrcIP == "" {
			addIncomplete("认证失败事件缺少可核验的来源 IP")
			continue
		}
		eventsCountByAsset[row.assetID]++
		if v.FirstFailure.IsZero() || row.ts.Before(v.FirstFailure) {
			v.FirstFailure = row.ts
		}
		if v.LastFailure.IsZero() || row.ts.After(v.LastFailure) {
			v.LastFailure = row.ts
		}
		tk := tupleKey{srcIP: parsed.SrcIP, assetID: row.assetID, service: parsed.ServiceSlug, account: parsed.Account}
		tup := tupleMap[tk]
		if tup == nil {
			tup = &AttemptTuple{
				SrcIP:        parsed.SrcIP,
				AssetID:      row.assetID,
				Hostname:     hostname,
				ServiceSlug:  parsed.ServiceSlug,
				ServiceLabel: parsed.ServiceLabel,
				Account:      parsed.Account,
				FirstTs:      row.ts,
				LastTs:       row.ts,
			}
			tupleMap[tk] = tup
		}
		tup.Count++
		if row.ts.Before(tup.FirstTs) {
			tup.FirstTs = row.ts
		}
		if row.ts.After(tup.LastTs) {
			tup.LastTs = row.ts
		}
		if !slices.Contains(v.SourceIPs, parsed.SrcIP) {
			v.SourceIPs = append(v.SourceIPs, parsed.SrcIP)
		}
		if parsed.Account != "" && !slices.Contains(v.Accounts, parsed.Account) {
			v.Accounts = append(v.Accounts, parsed.Account)
		}
		tKey := row.assetID.String() + "|" + parsed.ServiceSlug
		if _, exists := targetMap[tKey]; !exists {
			targetMap[tKey] = ServiceTarget{
				GroupID:      gid,
				AssetID:      row.assetID,
				Hostname:     hostname,
				ServiceSlug:  parsed.ServiceSlug,
				ServiceLabel: parsed.ServiceLabel,
			}
		}
	}

	if len(v.SourceIPs) == 0 {
		addIncomplete("未能从认证失败记录提取任何有效来源 IP")
		v.Outcome = OutcomeIncomplete
		return v, nil
	}
	if !minAlertTs.IsZero() && minAlertTs.Before(v.FirstFailure) {
		v.FirstFailure = minAlertTs
	}
	if !maxAlertTs.IsZero() && maxAlertTs.After(v.LastFailure) {
		v.LastFailure = maxAlertTs
	}

	slices.Sort(v.SourceIPs)
	slices.Sort(v.Accounts)
	for _, tup := range tupleMap {
		v.Tuples = append(v.Tuples, *tup)
		v.TotalFailures += tup.Count
	}
	// 若告警去重计数高于留存单条样本事件数（例如去重合并而部分原始事件只保留锚点或单测手工构造 count），取较大值
	alertTotal := 0
	for aid, cnt := range alertCountByAsset {
		alertTotal += max(cnt, eventsCountByAsset[aid])
	}
	if alertTotal > v.TotalFailures {
		v.TotalFailures = alertTotal
		if len(v.Tuples) == 1 {
			v.Tuples[0].Count = alertTotal
		}
	}
	slices.SortFunc(v.Tuples, func(a, b AttemptTuple) int {
		return cmp.Or(a.FirstTs.Compare(b.FirstTs), strings.Compare(a.SrcIP, b.SrcIP), strings.Compare(a.Account, b.Account))
	})
	for _, tgt := range targetMap {
		v.Targets = append(v.Targets, tgt)
	}
	slices.SortFunc(v.Targets, func(a, b ServiceTarget) int {
		return cmp.Or(strings.Compare(a.Hostname, b.Hostname), strings.Compare(a.ServiceSlug, b.ServiceSlug))
	})

	// 2. 计算核验时间窗：[firstFailure - 1h, max(now, lastFailure + 24h)]
	v.WindowFrom = v.FirstFailure.Add(-time.Hour)
	v.WindowTo = maxTime(opts.Now, v.LastFailure.Add(24*time.Hour))
	queryTo := maxTime(opts.Now.Add(5*time.Minute), v.WindowTo)

	// 3. 分区完整性与采集健康核查（任何缺口均记入 IncompleteReasons）
	if tx != nil {
		retired, err := isWindowPartitionRetired(ctx, sqlDB, tx, v.WindowFrom)
		if err != nil {
			return nil, err
		}
		if retired {
			addIncomplete("核验时间窗起点所在的历史事件日分区已退役，无法证明全窗口无成功登录")
		}
	}
	if err := checkCollectionCompleteness(ctx, db, tx, assetsByID, sourceKindsByAsset, hasAuthentik, opts.Now, queryTo, addIncomplete); err != nil {
		return nil, err
	}

	// 4. 判定来源 IP 是否包含内网、纳管主机、已登记通道或有效可信来源网段
	internalAttrs, err := classifySourceIPs(ctx, db, v.SourceIPs, groupIDs, opts.Now, addIncomplete)
	if err != nil {
		return nil, err
	}
	v.InternalSources = internalAttrs

	srcIPSet := make(map[string]bool, len(v.SourceIPs))
	for _, ip := range v.SourceIPs {
		srcIPSet[ip] = true
	}

	// 5. 核查窗口内同来源是否有任何成功认证（events 目标资产 + ssh_logins 全组物化表）
	succRows, succTrunc, err := queryAssetAuthEvents(ctx, db, tx, assetIDs, v.WindowFrom, queryTo, true, maxSuccessScanRows)
	if err != nil {
		return nil, err
	}
	if succTrunc {
		addIncomplete("成功认证候选事件超出单次核验上限")
	}
	seenSuccIDs := map[uuid.UUID]bool{}
	for _, row := range succRows {
		as := assetsByID[row.assetID]
		assetOS, hostname := "", ""
		if as != nil {
			if as.Os != nil {
				assetOS = *as.Os
			}
			hostname = as.Hostname
		}
		parsed, ok := ParseAuthEvent(row.classUID, row.source, assetOS, row.username, row.raw)
		if !ok || !parsed.Success || !srcIPSet[parsed.SrcIP] {
			continue
		}
		seenSuccIDs[row.id] = true
		v.Successes = append(v.Successes, SuccessHit{
			SrcIP:        parsed.SrcIP,
			AssetID:      row.assetID,
			Hostname:     hostname,
			ServiceLabel: parsed.ServiceLabel,
			Account:      parsed.Account,
			Ts:           row.ts,
			Via:          "events",
		})
	}

	sshHits, err := queryGroupSSHLogins(ctx, db, tx, groupIDs, assetIDs, v.SourceIPs, v.WindowFrom, queryTo)
	if err != nil {
		return nil, err
	}
	for _, hit := range sshHits {
		if seenSuccIDs[hit.id] {
			continue
		}
		seenSuccIDs[hit.id] = true
		hostname := hit.hostname
		if hostname == "" {
			if as := assetsByID[hit.assetID]; as != nil {
				hostname = as.Hostname
			}
		}
		v.Successes = append(v.Successes, SuccessHit{
			SrcIP:        hit.srcIP,
			AssetID:      hit.assetID,
			Hostname:     hostname,
			ServiceLabel: "SSH",
			Account:      hit.account,
			Ts:           hit.ts,
			Via:          "ssh_logins",
		})
	}
	slices.SortFunc(v.Successes, func(a, b SuccessHit) int {
		return cmp.Or(a.Ts.Compare(b.Ts), strings.Compare(a.SrcIP, b.SrcIP))
	})

	// 6. 核查窗口内同来源是否有其他命中告警（非本事件）
	otherAlerts, latestSameSrcFailAlert, alertTrunc, err := querySameSourceAlerts(ctx, db, tx, incidentID, groupIDs, assetIDs, srcIPSet, v.WindowFrom, queryTo)
	if err != nil {
		return nil, err
	}
	if alertTrunc {
		addIncomplete("关联窗口内候选告警超出单次核验上限")
	}
	v.OtherAlerts = otherAlerts
	if latestSameSrcFailAlert.After(v.LastFailure) {
		v.LastFailure = latestSameSrcFailAlert
		v.WindowTo = maxTime(opts.Now, v.LastFailure.Add(24*time.Hour))
	}

	if opts.Now.After(v.LastFailure) {
		v.QuietDuration = opts.Now.Sub(v.LastFailure)
	}

	// 7. 按严格优先级产出三态结论（拿不准绝不落入 OutcomeUnsuccessful）
	switch {
	case len(v.Successes) > 0:
		v.Outcome = OutcomeSucceeded
	case len(v.InternalSources) > 0:
		v.Outcome = OutcomeInternalOrRegistered
	case len(v.OtherAlerts) > 0:
		v.Outcome = OutcomeOtherAlerts
	case !v.AllAuthFailureRules || len(v.IncompleteReasons) > 0:
		v.Outcome = OutcomeIncomplete
	default:
		v.Outcome = OutcomeUnsuccessful
	}
	return v, nil
}

func loadTemporalEvidenceEvents(ctx context.Context, tx *sql.Tx, alertIDs []uuid.UUID, from, to time.Time) ([]rawEventRow, error) {
	if tx == nil || len(alertIDs) == 0 {
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT te.event_id
FROM temporal_detections td
JOIN temporal_evidence te ON te.revision = td.revision AND te.rule_id = td.rule_id AND te.anchor_id = td.anchor_id
WHERE td.alert_id = ANY($1)
LIMIT 500`, alertIDs)
	if err != nil {
		return nil, err
	}
	var evIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		evIDs = append(evIDs, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil || len(evIDs) == 0 {
		return nil, err
	}

	evRows, err := tx.QueryContext(ctx, `SELECT id, ts, class_uid, source, COALESCE(asset_id, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(username, ''), raw
FROM events
WHERE id = ANY($1)
  AND ts >= $2 AND ts <= $3
ORDER BY ts ASC`, evIDs, from, to)
	if err != nil {
		return nil, err
	}
	defer evRows.Close()
	var out []rawEventRow
	for evRows.Next() {
		var r rawEventRow
		if err := evRows.Scan(&r.id, &r.ts, &r.classUID, &r.source, &r.assetID, &r.username, &r.raw); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, evRows.Err()
}

// queryAssetAuthEvents 在明确限定 asset_id 与 [from, to] 的前提下查询认证事件，走分区裁剪与 event_asset_id_ts 索引。
func queryAssetAuthEvents(ctx context.Context, db *ent.Client, tx *sql.Tx, assetIDs []uuid.UUID, from, to time.Time, onlySuccess bool, limit int) ([]rawEventRow, bool, error) {
	if len(assetIDs) == 0 {
		return nil, false, nil
	}
	if tx != nil {
		query := `SELECT id, ts, class_uid, source, asset_id, COALESCE(username, ''), raw
FROM events
WHERE asset_id = ANY($1)
  AND ts >= $2 AND ts <= $3
  AND class_uid IN (3002, 100001)`
		if onlySuccess {
			query += `
  AND (
    (class_uid = 3002 AND (raw->>'status_id' = '1' OR lower(COALESCE(raw->>'status', '')) = 'success'))
    OR (class_uid = 100001 AND COALESCE(raw->>'message', '') LIKE 'Accepted %')
  )`
		}
		query += fmt.Sprintf("\nORDER BY ts ASC\nLIMIT %d", limit+1)
		rows, err := tx.QueryContext(ctx, query, assetIDs, from, to)
		if err != nil {
			return nil, false, err
		}
		defer rows.Close()
		var out []rawEventRow
		for rows.Next() {
			var r rawEventRow
			if err := rows.Scan(&r.id, &r.ts, &r.classUID, &r.source, &r.assetID, &r.username, &r.raw); err != nil {
				return nil, false, err
			}
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			return nil, false, err
		}
		if len(out) > limit {
			return out[:limit], true, nil
		}
		return out, false, nil
	}

	evs, err := db.Event.Query().
		Where(
			event.AssetIDIn(assetIDs...),
			event.TsGTE(from),
			event.TsLTE(to),
			event.ClassUIDIn(3002, 100001),
		).
		Order(ent.Asc(event.FieldTs)).
		Limit(limit + 1).
		All(ctx)
	if err != nil {
		return nil, false, err
	}
	truncated := len(evs) > limit
	if truncated {
		evs = evs[:limit]
	}
	out := make([]rawEventRow, 0, len(evs))
	for _, ev := range evs {
		aid := uuid.Nil
		if ev.AssetID != nil {
			aid = *ev.AssetID
		}
		uname := ""
		if ev.Username != nil {
			uname = *ev.Username
		}
		out = append(out, rawEventRow{
			id:       ev.ID,
			ts:       ev.Ts,
			classUID: ev.ClassUID,
			source:   ev.Source,
			assetID:  aid,
			username: uname,
			raw:      ev.Raw,
		})
	}
	return out, truncated, nil
}

type sshLoginRow struct {
	id       uuid.UUID
	ts       time.Time
	assetID  uuid.UUID
	hostname string
	srcIP    string
	account  string
}

func queryGroupSSHLogins(ctx context.Context, db *ent.Client, tx *sql.Tx, groupIDs, assetIDs []uuid.UUID, srcIPs []string, from, to time.Time) ([]sshLoginRow, error) {
	if len(srcIPs) == 0 {
		return nil, nil
	}
	if tx != nil && len(groupIDs) > 0 {
		rows, err := tx.QueryContext(ctx, `SELECT l.id, l.ts, l.asset_id, COALESCE(a.hostname, ''), l.src_ip, l.login_user
FROM ssh_logins l
LEFT JOIN assets a ON a.id = l.asset_id
WHERE l.group_id = ANY($1)
  AND l.ts >= $2 AND l.ts <= $3
  AND l.src_ip = ANY($4)
ORDER BY l.ts ASC
LIMIT 200`, groupIDs, from, to, srcIPs)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []sshLoginRow
		for rows.Next() {
			var r sshLoginRow
			if err := rows.Scan(&r.id, &r.ts, &r.assetID, &r.hostname, &r.srcIP, &r.account); err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, rows.Err()
	}

	q := db.SSHLogin.Query().Where(
		sshlogin.TsGTE(from),
		sshlogin.TsLTE(to),
		sshlogin.SrcIPIn(srcIPs...),
	)
	if len(groupIDs) > 0 {
		q = q.Where(sshlogin.GroupIDIn(groupIDs...))
	} else if len(assetIDs) > 0 {
		q = q.Where(sshlogin.AssetIDIn(assetIDs...))
	} else {
		return nil, nil
	}
	rows, err := q.Order(ent.Asc(sshlogin.FieldTs)).Limit(200).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]sshLoginRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, sshLoginRow{
			id:      r.ID,
			ts:      r.Ts,
			assetID: r.AssetID,
			srcIP:   r.SrcIP,
			account: r.LoginUser,
		})
	}
	return out, nil
}

// querySameSourceAlerts 查询同组（或同资产）在核验窗口内由相同来源 IP 触发的其他告警。
// 使用 LATERAL (id, ts) 精确探测单个日分区主键，绝不触发全分区哈希连接。
func querySameSourceAlerts(
	ctx context.Context,
	db *ent.Client,
	tx *sql.Tx,
	incidentID uuid.UUID,
	groupIDs, assetIDs []uuid.UUID,
	srcIPSet map[string]bool,
	from, to time.Time,
) ([]OtherAlertHit, time.Time, bool, error) {
	var otherHits []OtherAlertHit
	var latestAuthFail time.Time

	processCandidate := func(id uuid.UUID, ts time.Time, lastTs *time.Time, ruleID string, detail *string, classUID int, raw []byte) {
		ips := ExtractAlertIPs(ruleID, detail, classUID, raw)
		matchedIP := ""
		for _, ip := range ips {
			if srcIPSet[ip] {
				matchedIP = ip
				break
			}
		}
		if matchedIP == "" {
			return
		}
		endTs := ts
		if lastTs != nil && lastTs.After(endTs) {
			endTs = *lastTs
		}
		if IsAuthFailureRule(ruleID) {
			if endTs.After(latestAuthFail) {
				latestAuthFail = endTs
			}
			return
		}
		otherHits = append(otherHits, OtherAlertHit{
			AlertID: id,
			RuleID:  ruleID,
			SrcIP:   matchedIP,
			Ts:      ts,
		})
	}

	if tx != nil {
		var rows *sql.Rows
		var err error
		const lateralSelect = `SELECT a.id, a.ts, a.last_ts, a.rule_id, a.detail, a.event_id, COALESCE(e.class_uid, 0), e.raw
FROM alerts a
LEFT JOIN assets s ON s.id = a.asset_id
LEFT JOIN LATERAL (
  SELECT class_uid, raw FROM events e WHERE e.id = a.event_id AND e.ts = a.ts LIMIT 1
) e ON a.event_id IS NOT NULL
WHERE (a.incident_id IS NULL OR a.incident_id <> $1)
  AND ((a.ts >= $2 AND a.ts <= $3) OR (a.last_ts IS NOT NULL AND a.last_ts >= $2 AND a.last_ts <= $3))`

		if len(groupIDs) > 0 {
			rows, err = tx.QueryContext(ctx, lateralSelect+`
  AND (s.group_id = ANY($4) OR a.asset_id = ANY($5))
ORDER BY a.ts ASC
LIMIT $6`, incidentID, from, to, groupIDs, assetIDs, maxAlertScanRows+1)
		} else {
			rows, err = tx.QueryContext(ctx, lateralSelect+`
  AND a.asset_id = ANY($4)
ORDER BY a.ts ASC
LIMIT $5`, incidentID, from, to, assetIDs, maxAlertScanRows+1)
		}
		if err != nil {
			return nil, time.Time{}, false, err
		}
		type alertCand struct {
			id       uuid.UUID
			ts       time.Time
			lastTs   sql.NullTime
			ruleID   string
			detail   sql.NullString
			eventID  uuid.NullUUID
			classUID int
			raw      []byte
		}
		var cands []alertCand
		for rows.Next() {
			var c alertCand
			if err := rows.Scan(&c.id, &c.ts, &c.lastTs, &c.ruleID, &c.detail, &c.eventID, &c.classUID, &c.raw); err != nil {
				rows.Close()
				return nil, time.Time{}, false, err
			}
			cands = append(cands, c)
		}
		if err := rows.Close(); err != nil {
			return nil, time.Time{}, false, err
		}
		if err := rows.Err(); err != nil {
			return nil, time.Time{}, false, err
		}
		truncated := len(cands) > maxAlertScanRows
		if truncated {
			cands = cands[:maxAlertScanRows]
		}
		for _, c := range cands {
			// 若单测中手工写入的 alert.ts 与 event.ts 不完全相等，在有界时间窗内补查一次该 event_id
			if c.eventID.Valid && len(c.raw) == 0 {
				_ = tx.QueryRowContext(ctx, `SELECT class_uid, raw FROM events WHERE id = $1 AND ts >= $2 AND ts <= $3 LIMIT 1`,
					c.eventID.UUID, from.Add(-24*time.Hour), to.Add(24*time.Hour)).Scan(&c.classUID, &c.raw)
			}
			var lastPtr *time.Time
			if c.lastTs.Valid {
				t := c.lastTs.Time
				lastPtr = &t
			}
			var detPtr *string
			if c.detail.Valid {
				d := c.detail.String
				detPtr = &d
			}
			processCandidate(c.id, c.ts, lastPtr, c.ruleID, detPtr, c.classUID, c.raw)
		}
		return otherHits, latestAuthFail, truncated, nil
	}

	q := db.Alert.Query().Where(
		alert.Or(alert.IncidentIDIsNil(), alert.IncidentIDNEQ(incidentID)),
		alert.Or(
			alert.And(alert.TsGTE(from), alert.TsLTE(to)),
			alert.And(alert.LastTsGTE(from), alert.LastTsLTE(to)),
		),
	)
	if len(groupIDs) > 0 {
		q = q.Where(alert.HasAssetWith(entasset.GroupIDIn(groupIDs...)))
	} else {
		q = q.Where(alert.AssetIDIn(assetIDs...))
	}
	rows, err := q.WithEvent().Order(ent.Asc(alert.FieldTs)).Limit(maxAlertScanRows + 1).All(ctx)
	if err != nil {
		return nil, time.Time{}, false, err
	}
	truncated := len(rows) > maxAlertScanRows
	if truncated {
		rows = rows[:maxAlertScanRows]
	}
	for _, r := range rows {
		cuid := 0
		var raw []byte
		if r.Edges.Event != nil {
			cuid = r.Edges.Event.ClassUID
			raw = r.Edges.Event.Raw
		}
		processCandidate(r.ID, r.Ts, r.LastTs, r.RuleID, r.Detail, cuid, raw)
	}
	return otherHits, latestAuthFail, truncated, nil
}

// isWindowPartitionRetired 判断核验窗口起点是否已落入被退役/冷归档的日分区。
// 当库里存在归档分区（events_aYYYYMM，即执行过 eventpart.Retire）且 windowFrom 早于最老热日分区下界时，
// 该日未被告警锚定的普通成功登录事件已被清理，不能再做「无成功登录」阴性证明。
func isWindowPartitionRetired(ctx context.Context, sqlDB *sql.DB, tx *sql.Tx, windowFrom time.Time) (bool, error) {
	var hasArchive bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
  SELECT 1 FROM pg_inherits i
  JOIN pg_class c ON c.oid = i.inhrelid
  WHERE i.inhparent = to_regclass('events') AND c.relname LIKE 'events_a______'
)`).Scan(&hasArchive); err != nil {
		return false, err
	}
	if !hasArchive {
		return false, nil
	}
	oldest, ok, err := eventpart.OldestDaily(ctx, sqlDB)
	if err != nil {
		return false, err
	}
	if !ok {
		return true, nil
	}
	return windowFrom.Before(oldest), nil
}

func checkCollectionCompleteness(
	ctx context.Context,
	db *ent.Client,
	tx *sql.Tx,
	assetsByID map[uuid.UUID]*ent.Asset,
	sourceKindsByAsset map[uuid.UUID]map[string]bool,
	hasAuthentik bool,
	now, queryTo time.Time,
	addIncomplete func(string),
) error {
	for aid, as := range assetsByID {
		if as.RetiredAt != nil {
			addIncomplete(fmt.Sprintf("目标资产 %s 已下线退役", cmp.Or(as.Hostname, aid.String())))
			continue
		}
		if as.SilentSince != nil {
			addIncomplete(fmt.Sprintf("目标资产 %s 处于失联状态", cmp.Or(as.Hostname, aid.String())))
			continue
		}
		kinds := sourceKindsByAsset[aid]
		if kinds["agent"] {
			if as.AgentID == nil {
				addIncomplete(fmt.Sprintf("目标资产 %s 未绑定在线 Agent", cmp.Or(as.Hostname, aid.String())))
				continue
			}
			if as.LastSeen.Before(now.Add(-agentFreshnessLimit)) {
				addIncomplete(fmt.Sprintf("目标资产 %s 的 Agent 心跳过期（最近心跳 %s），无法确认静默期采集完整",
					cmp.Or(as.Hostname, aid.String()), as.LastSeen.UTC().Format(time.RFC3339)))
			}
			checkAgentAuthHealth(as, now, addIncomplete)
		}
		if kinds["syslog"] && as.AgentID == nil {
			alive, err := hasRecentAssetEvent(ctx, db, tx, aid, now.Add(-syslogQuietAliveWindow), queryTo)
			if err != nil {
				return err
			}
			if !alive {
				addIncomplete(fmt.Sprintf("纯 Syslog 资产 %s 近 %s 无任何新日志到达，无法排除日志链路中断",
					cmp.Or(as.Hostname, aid.String()), syslogQuietAliveWindow))
			}
		} else if kinds["syslog"] && as.AgentID != nil && as.LastSeen.Before(now.Add(-agentFreshnessLimit)) {
			addIncomplete(fmt.Sprintf("目标资产 %s 心跳过期，无法确认静默期完整", cmp.Or(as.Hostname, aid.String())))
		}
	}

	if hasAuthentik && tx != nil {
		var raw []byte
		err := tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE id = $1`, authentikPolledAtKey).Scan(&raw)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			var polledAt time.Time
			if json.Unmarshal(raw, &polledAt) != nil || polledAt.Before(now.Add(-authentikFreshnessLimit)) {
				addIncomplete("Authentik 登录事件轮询心跳过期，无法确认静默期采集未中断")
			}
		}
	}
	return nil
}

func checkAgentAuthHealth(as *ent.Asset, now time.Time, addIncomplete func(string)) {
	if len(as.CollectorHealth) == 0 {
		return
	}
	var snap struct {
		ReceivedAt   time.Time `json:"receivedAt"`
		WriteBlocked bool      `json:"writeBlocked"`
		Capabilities map[string]struct {
			State string `json:"state"`
		} `json:"capabilities"`
	}
	if json.Unmarshal(as.CollectorHealth, &snap) != nil {
		addIncomplete(fmt.Sprintf("目标资产 %s 采集健康状态格式异常", cmp.Or(as.Hostname, as.ID.String())))
		return
	}
	if !snap.ReceivedAt.IsZero() && snap.ReceivedAt.Before(now.Add(-agentFreshnessLimit)) {
		addIncomplete(fmt.Sprintf("目标资产 %s 采集健康快照已过期", cmp.Or(as.Hostname, as.ID.String())))
	}
	if snap.WriteBlocked {
		addIncomplete(fmt.Sprintf("目标资产 %s 本地事件缓存写入受阻，可能漏采认证事件", cmp.Or(as.Hostname, as.ID.String())))
	}
	if authCap, ok := snap.Capabilities["auth"]; ok {
		if slices.Contains([]string{"unavailable", "disabled", "degraded"}, authCap.State) {
			addIncomplete(fmt.Sprintf("目标资产 %s 登录采集组件处于 %s 状态", cmp.Or(as.Hostname, as.ID.String()), authCap.State))
		}
	}
}

func hasRecentAssetEvent(ctx context.Context, db *ent.Client, tx *sql.Tx, assetID uuid.UUID, from, to time.Time) (bool, error) {
	if tx != nil {
		var exists bool
		err := tx.QueryRowContext(ctx, `SELECT EXISTS (
  SELECT 1 FROM events WHERE asset_id = $1 AND ts >= $2 AND ts <= $3 LIMIT 1
)`, assetID, from, to).Scan(&exists)
		return exists, err
	}
	return db.Event.Query().Where(event.AssetIDEQ(assetID), event.TsGTE(from), event.TsLTE(to)).Exist(ctx)
}

func classifySourceIPs(
	ctx context.Context,
	db *ent.Client,
	srcIPs []string,
	groupIDs []uuid.UUID,
	now time.Time,
	addIncomplete func(string),
) ([]SourceAttribution, error) {
	var zones []*ent.Zone
	if len(groupIDs) > 0 {
		var err error
		zones, err = db.Zone.Query().Where(zone.GroupIDIn(groupIDs...)).All(ctx)
		if err != nil {
			return nil, err
		}
	}
	managedAssets, err := db.Asset.Query().Where(entasset.RetiredAtIsNil()).Select(entasset.FieldID, entasset.FieldHostname, entasset.FieldIPAddrs).All(ctx)
	if err != nil {
		return nil, err
	}
	assetByIP := map[string]string{}
	for _, a := range managedAssets {
		for _, rawIP := range a.IPAddrs {
			if canon := authfields.CanonicalIP(rawIP); canon != "" {
				assetByIP[canon] = cmp.Or(a.Hostname, a.ID.String())
			}
		}
	}
	channels, err := db.Fact.Query().Where(fact.KindEQ("channel"), facts.Live(now)).All(ctx)
	if err != nil {
		return nil, err
	}
	var trusted []*ent.TrustedSource
	if len(groupIDs) > 0 {
		trusted, err = db.TrustedSource.Query().Where(
			trustedsource.GroupIDIn(groupIDs...),
			trustedsource.RevokedAtIsNil(),
			trustedsource.DeletedAtIsNil(),
			trustedsource.ExpiresAtGT(now),
			trustedsource.SourceCidrNotNil(),
		).All(ctx)
		if err != nil {
			return nil, err
		}
	}

	var out []SourceAttribution
	for _, ip := range srcIPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			addIncomplete("存在格式无效的来源 IP：" + ip)
			continue
		}
		addr = addr.Unmap()

		// 1) 已登记通道事实（最具体的人工权威归属，优先展示）
		matchedFact := false
		for _, ch := range channels {
			if facts.Covers(ch.Subject, ip) {
				out = append(out, SourceAttribution{
					SrcIP:  ip,
					Kind:   "channel_fact",
					Detail: fmt.Sprintf("已登记通道事实 %s（持有人 %s，网段 %s）", facts.Ref("F", ch.ID), ch.Holder, ch.Subject),
				})
				matchedFact = true
				break
			}
		}
		if matchedFact {
			continue
		}

		// 2) 纳管资产自身 IP
		if host, ok := assetByIP[ip]; ok {
			out = append(out, SourceAttribution{
				SrcIP:  ip,
				Kind:   "managed_asset",
				Detail: "平台纳管资产 " + host,
			})
			continue
		}

		// 3) 组内可信自动化来源网段
		matchedTrusted := false
		for _, ts := range trusted {
			if ts.SourceCidr != nil && facts.Covers(*ts.SourceCidr, ip) {
				out = append(out, SourceAttribution{
					SrcIP:  ip,
					Kind:   "trusted_source",
					Detail: fmt.Sprintf("已登记自动化来源 %s（%s）", ts.Name, *ts.SourceCidr),
				})
				matchedTrusted = true
				break
			}
		}
		if matchedTrusted {
			continue
		}

		// 4) 组内自定义内网/DMZ/云网段
		if z := matchZoneCIDR(addr, zones); z != nil && string(z.Kind) != "external" {
			out = append(out, SourceAttribution{
				SrcIP:  ip,
				Kind:   "zone",
				Detail: fmt.Sprintf("组内已划分非公网区域 %s（%s）", cmp.Or(z.Name, string(z.Kind)), z.Kind),
			})
			continue
		}

		// 5) RFC1918 私网、Tailscale/CGNAT、环回、链路本地等非外部公网地址
		if !isPublicAddr(addr) {
			out = append(out, SourceAttribution{
				SrcIP:  ip,
				Kind:   "private_ip",
				Detail: "内网或覆盖网非公网地址",
			})
		}
	}
	return out, nil
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isPublicAddr 判定是否为公网单播地址（排除私网、Tailscale/CGNAT、ULA、环回与链路本地）。
func isPublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnatPrefix.Contains(a)
}

// matchZoneCIDR 按最长前缀匹配组内定义的区域网段。
func matchZoneCIDR(addr netip.Addr, zones []*ent.Zone) *ent.Zone {
	addr = addr.Unmap()
	var best *ent.Zone
	bits := -1
	for _, z := range zones {
		for _, c := range z.Cidrs {
			p, err := netip.ParsePrefix(c)
			if err != nil || p.Bits() <= bits {
				continue
			}
			if p.Contains(addr) {
				best, bits = z, p.Bits()
			}
		}
	}
	return best
}

func statementTimeoutMillis(ctx context.Context, fallback time.Duration) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	d := fallback
	if deadline, ok := ctx.Deadline(); ok {
		rem := time.Until(deadline)
		if rem <= 0 {
			return 0, context.DeadlineExceeded
		}
		if rem < d {
			d = rem
		}
	}
	ms := d.Milliseconds()
	if ms < 50 {
		ms = 50
	}
	if ms > 30000 {
		ms = 30000
	}
	return ms, nil
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "57014" {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "statement timeout")
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func sortedUUIDs(m map[uuid.UUID]*ent.Asset) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	return out
}

func sortedGroupIDs(m map[uuid.UUID]bool) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	return out
}

func summarizeList(items []string, limit int) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) <= limit {
		return strings.Join(items, "、")
	}
	return fmt.Sprintf("%s 等 %d 项", strings.Join(items[:limit], "、"), len(items))
}
