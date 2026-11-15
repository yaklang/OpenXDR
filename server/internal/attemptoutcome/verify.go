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
	"openxdr/server/ent/predicate"
	"openxdr/server/ent/sshlogin"
	"openxdr/server/ent/trustedsource"
	"openxdr/server/ent/zone"
	"openxdr/server/internal/authevents"
	"openxdr/server/internal/authfields"
	"openxdr/server/internal/eventpart"
	"openxdr/server/internal/facts"
)

// Outcome 认证尝试核验的三态细分结论。
type Outcome string

const (
	// OutcomeUnsuccessful 未得手：全部来源为外部公网地址、窗口内无任何成功认证、无其他非本族告警、采集完整且晚于物化起始时刻
	OutcomeUnsuccessful Outcome = "unsuccessful"
	// OutcomeSucceeded 有成功：窗口内存在同来源成功认证
	OutcomeSucceeded Outcome = "succeeded"
	// OutcomeInternalOrRegistered 内网或已登记通道：无同源成功（若有成功优先归入 OutcomeSucceeded），但来源含内网/纳管资产/已登记通道/可信来源
	OutcomeInternalOrRegistered Outcome = "internal_or_registered"
	// OutcomeOtherAlerts 同来源存在其他非认证失败族命中告警，不自动放行
	OutcomeOtherAlerts Outcome = "other_alerts"
	// OutcomeIncomplete 查不全或不适用（存量事件、缺来源 IP、含非本族告警、采集中断、分区已退役、查询超时等），拿不准绝不自动结案
	OutcomeIncomplete Outcome = "incomplete"
)

const (
	defaultStatementTimeout = 5 * time.Second
	maxFailureScanRows      = 50000
	maxSuccessScanRows      = 5000
	maxAlertScanRows        = 2000
	// dedupLookbackSlack 覆盖告警去重折叠最大跨度（DEDUP_WINDOW_MINUTES / SprayWindow），使 alerts 查询只用索引列 a.ts 范围扫描
	dedupLookbackSlack      = time.Hour
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

type authEventRow struct {
	eventID    uuid.UUID
	assetID    uuid.UUID
	hostname   string
	ts         time.Time
	srcIP      string
	service    string
	sourceKind string
	account    string
	success    bool
}

type eventKeyPair struct {
	id uuid.UUID
	ts time.Time
}

type anchorRawRow struct {
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
	// 注意：绝不使用 .WithEvent()（Ent 会生成无 ts 的 WHERE id IN (...) 跨全部分区探主键）
	alerts, err := db.Alert.Query().
		Where(alert.IncidentIDEQ(incidentID)).
		WithAsset().
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
	var anchorEventIDs []uuid.UUID
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
		if a.EventID != nil {
			anchorEventIDs = append(anchorEventIDs, *a.EventID)
		}
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

	// 1. 从 auth_events 物化表读取锚点认证记录与跨主机时序证据明细（零 events 扫描）
	anchorAuthMap, err := queryAuthEventsByIDs(ctx, tx, anchorEventIDs)
	if err != nil {
		return nil, err
	}
	temporalAuthRows, err := loadTemporalEvidenceAuthEvents(ctx, tx, authAlertIDs)
	if err != nil {
		return nil, err
	}
	for _, row := range temporalAuthRows {
		if row.assetID != uuid.Nil && assetsByID[row.assetID] == nil {
			if as, err := db.Asset.Get(ctx, row.assetID); err == nil {
				assetsByID[as.ID] = as
				if as.GroupID != nil {
					groupSet[*as.GroupID] = true
				}
			}
		}
		if row.ts.Before(minAlertTs) {
			minAlertTs = row.ts
		}
		if row.ts.After(maxAlertTs) {
			maxAlertTs = row.ts
		}
	}

	assetIDs := sortedUUIDs(assetsByID)
	groupIDs := sortedGroupIDs(groupSet)

	// 仅当告警发生去重折叠（last_ts > ts）或存在缺少明细证据的时序告警时，按 (asset_id, ts) 索引查 auth_events 折叠区间
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
		case strings.HasPrefix(a.RuleID, "temporal:") && len(temporalAuthRows) == 0:
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

	var foldAuthRows []authEventRow
	if needFoldScan && tx != nil {
		var truncated bool
		foldAuthRows, truncated, err = queryAssetFailedAuthEvents(ctx, tx, assetIDs, foldFrom, foldTo, maxFailureScanRows)
		if err != nil {
			return nil, err
		}
		if truncated {
			addIncomplete("失败窗口内认证事件超出单次核验上限")
		}
	}

	seenAuth := map[uuid.UUID]authEventRow{}
	for _, r := range foldAuthRows {
		seenAuth[r.eventID] = r
	}
	for _, r := range temporalAuthRows {
		seenAuth[r.eventID] = r
	}

	// 锚点优先取自 auth_events；仅当上线前存量告警或未注入 sqlDB 的会话研判在 auth_events 未命中时，才按主键 (id, ts) 单点取锚点事件正文
	var missingAnchorKeys []eventKeyPair
	missingAlertAsset := map[uuid.UUID]uuid.UUID{}
	for _, a := range authAlerts {
		if a.EventID == nil {
			addIncomplete("认证失败告警缺少原始事件引用")
			continue
		}
		if r, ok := anchorAuthMap[*a.EventID]; ok {
			seenAuth[r.eventID] = r
			continue
		}
		missingAnchorKeys = append(missingAnchorKeys, eventKeyPair{id: *a.EventID, ts: a.Ts})
		if a.AssetID != nil {
			missingAlertAsset[*a.EventID] = *a.AssetID
		}
	}
	if len(missingAnchorKeys) > 0 {
		rawAnchors, err := fetchAnchorEventsByPK(ctx, db, tx, missingAnchorKeys)
		if err != nil {
			return nil, err
		}
		foundIDs := map[uuid.UUID]bool{}
		for _, rawEv := range rawAnchors {
			foundIDs[rawEv.id] = true
			aid := rawEv.assetID
			if aid == uuid.Nil {
				aid = missingAlertAsset[rawEv.id]
			}
			assetOS := ""
			if as := assetsByID[aid]; as != nil && as.Os != nil {
				assetOS = *as.Os
			}
			parsed, ok := ParseAuthEvent(rawEv.classUID, rawEv.source, assetOS, rawEv.username, rawEv.raw)
			if !ok {
				continue
			}
			seenAuth[rawEv.id] = authEventRow{
				eventID:    rawEv.id,
				assetID:    aid,
				ts:         rawEv.ts,
				srcIP:      parsed.SrcIP,
				service:    parsed.ServiceSlug,
				sourceKind: parsed.SourceKind,
				account:    parsed.Account,
				success:    parsed.Success,
			}
		}
		for _, k := range missingAnchorKeys {
			if !foundIDs[k.id] {
				addIncomplete("认证失败告警缺少可读取的锚点事件")
			}
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

	orderedIDs := make([]uuid.UUID, 0, len(seenAuth))
	for id := range seenAuth {
		orderedIDs = append(orderedIDs, id)
	}
	slices.SortFunc(orderedIDs, func(a, b uuid.UUID) int {
		ra, rb := seenAuth[a], seenAuth[b]
		return cmp.Or(ra.ts.Compare(rb.ts), strings.Compare(a.String(), b.String()))
	})

	for _, id := range orderedIDs {
		row := seenAuth[id]
		if row.success {
			continue
		}
		as := assetsByID[row.assetID]
		hostname := ""
		var gid uuid.UUID
		if as != nil {
			hostname = as.Hostname
			if as.GroupID != nil {
				gid = *as.GroupID
			}
		}
		svcLabel := authevents.ServiceLabel(row.service)
		if sourceKindsByAsset[row.assetID] == nil {
			sourceKindsByAsset[row.assetID] = map[string]bool{}
		}
		if row.sourceKind != "" {
			sourceKindsByAsset[row.assetID][row.sourceKind] = true
		}
		if row.sourceKind == "authentik" || row.service == "authentik" {
			hasAuthentik = true
		}
		if row.srcIP == "" {
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
		tk := tupleKey{srcIP: row.srcIP, assetID: row.assetID, service: row.service, account: row.account}
		tup := tupleMap[tk]
		if tup == nil {
			tup = &AttemptTuple{
				SrcIP:        row.srcIP,
				AssetID:      row.assetID,
				Hostname:     hostname,
				ServiceSlug:  row.service,
				ServiceLabel: svcLabel,
				Account:      row.account,
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
		if !slices.Contains(v.SourceIPs, row.srcIP) {
			v.SourceIPs = append(v.SourceIPs, row.srcIP)
		}
		if row.account != "" && !slices.Contains(v.Accounts, row.account) {
			v.Accounts = append(v.Accounts, row.account)
		}
		tKey := row.assetID.String() + "|" + row.service
		if _, exists := targetMap[tKey]; !exists {
			targetMap[tKey] = ServiceTarget{
				GroupID:      gid,
				AssetID:      row.assetID,
				Hostname:     hostname,
				ServiceSlug:  row.service,
				ServiceLabel: svcLabel,
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

	// 3. 上线前存量数据边界、分区保留期与采集健康核查（任何缺口均记入 IncompleteReasons，不自动结案）
	if err := checkMaterializedCoverage(ctx, db, sqlDB, tx, v.FirstFailure, v.WindowFrom, addIncomplete); err != nil {
		return nil, err
	}
	if err := checkCollectionCompleteness(ctx, tx, assetsByID, sourceKindsByAsset, hasAuthentik, opts.Now, queryTo, addIncomplete); err != nil {
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

	// 5. 核查窗口内同来源是否有任何成功认证（查 auth_events (src_ip, ts) 索引 + ssh_logins 全组物化表）
	seenSuccIDs := map[uuid.UUID]bool{}
	if tx != nil {
		succRows, succTrunc, err := querySameSourceSuccessAuthEvents(ctx, tx, v.SourceIPs, assetIDs, groupIDs, v.WindowFrom, queryTo, maxSuccessScanRows)
		if err != nil {
			return nil, err
		}
		if succTrunc {
			addIncomplete("成功认证候选事件超出单次核验上限")
		}
		for _, row := range succRows {
			seenSuccIDs[row.eventID] = true
			hostname := row.hostname
			if hostname == "" {
				if as := assetsByID[row.assetID]; as != nil {
					hostname = as.Hostname
				}
			}
			v.Successes = append(v.Successes, SuccessHit{
				SrcIP:        row.srcIP,
				AssetID:      row.assetID,
				Hostname:     hostname,
				ServiceLabel: authevents.ServiceLabel(row.service),
				Account:      row.account,
				Ts:           row.ts,
				Via:          "auth_events",
			})
		}
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

	// 6. 核查窗口内同来源是否有其他命中告警（走 alert_asset_id_ts (asset_id, ts) 索引，锚点事件仅按 (id, ts) 主键点查）
	scopeAssetIDs, err := resolveScopeAssetIDs(ctx, db, groupIDs, assetIDs)
	if err != nil {
		return nil, err
	}
	otherAlerts, latestSameSrcFailAlert, alertTrunc, err := querySameSourceAlerts(ctx, db, tx, incidentID, scopeAssetIDs, srcIPSet, v.WindowFrom, queryTo)
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

// queryAuthEventsByIDs 按主键 event_id 批量读取 auth_events。
func queryAuthEventsByIDs(ctx context.Context, tx *sql.Tx, eventIDs []uuid.UUID) (map[uuid.UUID]authEventRow, error) {
	out := map[uuid.UUID]authEventRow{}
	if tx == nil || len(eventIDs) == 0 {
		return out, nil
	}
	rows, err := tx.QueryContext(ctx, `
SELECT event_id, asset_id, ts, src_ip, service, source_kind, account, success
FROM auth_events
WHERE event_id = ANY($1)`, eventIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r authEventRow
		if err := rows.Scan(&r.eventID, &r.assetID, &r.ts, &r.srcIP, &r.service, &r.sourceKind, &r.account, &r.success); err != nil {
			return nil, err
		}
		out[r.eventID] = r
	}
	return out, rows.Err()
}

// loadTemporalEvidenceAuthEvents 通过时序检测关联表直接按主键连接 auth_events，不碰原始 events 表。
func loadTemporalEvidenceAuthEvents(ctx context.Context, tx *sql.Tx, alertIDs []uuid.UUID) ([]authEventRow, error) {
	if tx == nil || len(alertIDs) == 0 {
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, `
SELECT ae.event_id, ae.asset_id, ae.ts, ae.src_ip, ae.service, ae.source_kind, ae.account, ae.success
FROM temporal_detections td
JOIN temporal_evidence te ON te.revision = td.revision AND te.rule_id = td.rule_id AND te.anchor_id = td.anchor_id
JOIN auth_events ae ON ae.event_id = te.event_id
WHERE td.alert_id = ANY($1)
LIMIT 500`, alertIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []authEventRow
	for rows.Next() {
		var r authEventRow
		if err := rows.Scan(&r.eventID, &r.assetID, &r.ts, &r.srcIP, &r.service, &r.sourceKind, &r.account, &r.success); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// queryAssetFailedAuthEvents 按 auth_events_asset_id_ts (asset_id, ts) 索引查询去重折叠短窗口内的失败认证行。
func queryAssetFailedAuthEvents(ctx context.Context, tx *sql.Tx, assetIDs []uuid.UUID, from, to time.Time, limit int) ([]authEventRow, bool, error) {
	if tx == nil || len(assetIDs) == 0 {
		return nil, false, nil
	}
	rows, err := tx.QueryContext(ctx, `
SELECT event_id, asset_id, ts, src_ip, service, source_kind, account, success
FROM auth_events
WHERE asset_id = ANY($1)
  AND ts >= $2 AND ts <= $3
  AND success = false
LIMIT $4`, assetIDs, from, to, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []authEventRow
	for rows.Next() {
		var r authEventRow
		if err := rows.Scan(&r.eventID, &r.assetID, &r.ts, &r.srcIP, &r.service, &r.sourceKind, &r.account, &r.success); err != nil {
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

// querySameSourceSuccessAuthEvents 按 auth_events_src_ip_ts (src_ip, ts) 索引核查同来源是否存在成功认证。
func querySameSourceSuccessAuthEvents(
	ctx context.Context,
	tx *sql.Tx,
	srcIPs []string,
	assetIDs, groupIDs []uuid.UUID,
	from, to time.Time,
	limit int,
) ([]authEventRow, bool, error) {
	if tx == nil || len(srcIPs) == 0 {
		return nil, false, nil
	}
	var rows *sql.Rows
	var err error
	if len(groupIDs) > 0 {
		rows, err = tx.QueryContext(ctx, `
SELECT ae.event_id, ae.asset_id, COALESCE(a.hostname, ''), ae.ts, ae.src_ip, ae.service, ae.account
FROM auth_events ae
LEFT JOIN assets a ON a.id = ae.asset_id
WHERE ae.src_ip = ANY($1)
  AND ae.ts >= $2 AND ae.ts <= $3
  AND (ae.asset_id = ANY($4) OR a.group_id = ANY($5))
  AND ae.success = true
LIMIT $6`, srcIPs, from, to, assetIDs, groupIDs, limit+1)
	} else {
		rows, err = tx.QueryContext(ctx, `
SELECT ae.event_id, ae.asset_id, COALESCE(a.hostname, ''), ae.ts, ae.src_ip, ae.service, ae.account
FROM auth_events ae
LEFT JOIN assets a ON a.id = ae.asset_id
WHERE ae.src_ip = ANY($1)
  AND ae.ts >= $2 AND ae.ts <= $3
  AND ae.asset_id = ANY($4)
  AND ae.success = true
LIMIT $5`, srcIPs, from, to, assetIDs, limit+1)
	}
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []authEventRow
	for rows.Next() {
		var r authEventRow
		r.success = true
		if err := rows.Scan(&r.eventID, &r.assetID, &r.hostname, &r.ts, &r.srcIP, &r.service, &r.account); err != nil {
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

// fetchAnchorEventsByPK 严格按分区表主键 (id, ts) 单点读取锚点事件正文，每次只命中单个日分区主键索引。
func fetchAnchorEventsByPK(ctx context.Context, db *ent.Client, tx *sql.Tx, keys []eventKeyPair) ([]anchorRawRow, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	if tx != nil {
		ids := make([]uuid.UUID, len(keys))
		tss := make([]time.Time, len(keys))
		minTs, maxTs := keys[0].ts, keys[0].ts
		for i, k := range keys {
			ids[i] = k.id
			tss[i] = k.ts
			if k.ts.Before(minTs) {
				minTs = k.ts
			}
			if k.ts.After(maxTs) {
				maxTs = k.ts
			}
		}
		rows, err := tx.QueryContext(ctx, `
SELECT e.id, e.ts, e.class_uid, e.source, COALESCE(e.asset_id, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(e.username, ''), e.raw
FROM unnest($1::uuid[], $2::timestamptz[]) AS k(id, ts)
JOIN events e ON e.id = k.id AND e.ts = k.ts
WHERE e.ts >= $3 AND e.ts <= $4`, ids, tss, minTs, maxTs)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []anchorRawRow
		for rows.Next() {
			var r anchorRawRow
			if err := rows.Scan(&r.id, &r.ts, &r.classUID, &r.source, &r.assetID, &r.username, &r.raw); err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, rows.Err()
	}

	preds := make([]predicate.Event, len(keys))
	for i, k := range keys {
		preds[i] = event.And(event.IDEQ(k.id), event.TsEQ(k.ts))
	}
	evs, err := db.Event.Query().Where(event.Or(preds...)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]anchorRawRow, 0, len(evs))
	for _, ev := range evs {
		aid := uuid.Nil
		if ev.AssetID != nil {
			aid = *ev.AssetID
		}
		uname := ""
		if ev.Username != nil {
			uname = *ev.Username
		}
		out = append(out, anchorRawRow{
			id:       ev.ID,
			ts:       ev.Ts,
			classUID: ev.ClassUID,
			source:   ev.Source,
			assetID:  aid,
			username: uname,
			raw:      ev.Raw,
		})
	}
	return out, nil
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

func resolveScopeAssetIDs(ctx context.Context, db *ent.Client, groupIDs, assetIDs []uuid.UUID) ([]uuid.UUID, error) {
	seen := make(map[uuid.UUID]bool, len(assetIDs)+16)
	for _, id := range assetIDs {
		if id != uuid.Nil {
			seen[id] = true
		}
	}
	if len(groupIDs) > 0 {
		ids, err := db.Asset.Query().
			Where(entasset.GroupIDIn(groupIDs...)).
			IDs(ctx)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			seen[id] = true
		}
	}
	out := make([]uuid.UUID, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	return out, nil
}

// querySameSourceAlerts 查询同组/目标资产在核验窗口内由相同来源 IP 触发的其他告警。
// 查询条件严格收敛在 alert_asset_id_ts (asset_id, ts) 索引上（不用未建索引的 last_ts OR 或 assets LEFT JOIN）；
// 认证失败族告警从 auth_events 取来源 IP，其余告警仅按主键 (id, ts) 点查锚点事件正文。
func querySameSourceAlerts(
	ctx context.Context,
	db *ent.Client,
	tx *sql.Tx,
	incidentID uuid.UUID,
	scopeAssetIDs []uuid.UUID,
	srcIPSet map[string]bool,
	from, to time.Time,
) ([]OtherAlertHit, time.Time, bool, error) {
	if len(scopeAssetIDs) == 0 || len(srcIPSet) == 0 {
		return nil, time.Time{}, false, nil
	}
	scanFrom := from.Add(-dedupLookbackSlack)

	type alertCand struct {
		id      uuid.UUID
		ts      time.Time
		lastTs  *time.Time
		ruleID  string
		detail  *string
		eventID *uuid.UUID
	}
	var cands []alertCand

	if tx != nil {
		rows, err := tx.QueryContext(ctx, `
SELECT a.id, a.ts, a.last_ts, a.rule_id, a.detail, a.event_id
FROM alerts a
WHERE a.asset_id = ANY($1)
  AND a.ts >= $2 AND a.ts <= $3
  AND (a.incident_id IS NULL OR a.incident_id <> $4)
ORDER BY a.ts ASC
LIMIT $5`, scopeAssetIDs, scanFrom, to, incidentID, maxAlertScanRows+1)
		if err != nil {
			return nil, time.Time{}, false, err
		}
		for rows.Next() {
			var (
				id     uuid.UUID
				ts     time.Time
				lastTs sql.NullTime
				ruleID string
				detail sql.NullString
				evID   uuid.NullUUID
			)
			if err := rows.Scan(&id, &ts, &lastTs, &ruleID, &detail, &evID); err != nil {
				rows.Close()
				return nil, time.Time{}, false, err
			}
			var lastPtr *time.Time
			if lastTs.Valid {
				t := lastTs.Time
				lastPtr = &t
			}
			var detPtr *string
			if detail.Valid {
				d := detail.String
				detPtr = &d
			}
			var evPtr *uuid.UUID
			if evID.Valid {
				eid := evID.UUID
				evPtr = &eid
			}
			cands = append(cands, alertCand{id: id, ts: ts, lastTs: lastPtr, ruleID: ruleID, detail: detPtr, eventID: evPtr})
		}
		if err := rows.Close(); err != nil {
			return nil, time.Time{}, false, err
		}
		if err := rows.Err(); err != nil {
			return nil, time.Time{}, false, err
		}
	} else {
		rows, err := db.Alert.Query().
			Where(
				alert.AssetIDIn(scopeAssetIDs...),
				alert.TsGTE(scanFrom),
				alert.TsLTE(to),
				alert.Or(alert.IncidentIDIsNil(), alert.IncidentIDNEQ(incidentID)),
			).
			Order(ent.Asc(alert.FieldTs)).
			Limit(maxAlertScanRows + 1).
			All(ctx)
		if err != nil {
			return nil, time.Time{}, false, err
		}
		for _, r := range rows {
			cands = append(cands, alertCand{
				id:      r.ID,
				ts:      r.Ts,
				lastTs:  r.LastTs,
				ruleID:  r.RuleID,
				detail:  r.Detail,
				eventID: r.EventID,
			})
		}
	}

	truncated := len(cands) > maxAlertScanRows
	if truncated {
		cands = cands[:maxAlertScanRows]
	}

	// 过滤掉仅落在 [from - 1h, from) 且未延续进 [from, to] 的去重前告警
	activeCands := cands[:0]
	var authEvIDs []uuid.UUID
	for _, c := range cands {
		endTs := c.ts
		if c.lastTs != nil && c.lastTs.After(endTs) {
			endTs = *c.lastTs
		}
		if endTs.Before(from) || c.ts.After(to) {
			continue
		}
		activeCands = append(activeCands, c)
		if c.eventID != nil && IsAuthFailureRule(c.ruleID) {
			authEvIDs = append(authEvIDs, *c.eventID)
		}
	}
	if len(activeCands) == 0 {
		return nil, time.Time{}, truncated, nil
	}

	authByID, err := queryAuthEventsByIDs(ctx, tx, authEvIDs)
	if err != nil {
		return nil, time.Time{}, false, err
	}

	var needPKFetch []eventKeyPair
	for _, c := range activeCands {
		if c.eventID == nil {
			continue
		}
		if _, ok := authByID[*c.eventID]; ok {
			continue
		}
		needPKFetch = append(needPKFetch, eventKeyPair{id: *c.eventID, ts: c.ts})
	}
	rawByID := map[uuid.UUID]anchorRawRow{}
	if len(needPKFetch) > 0 {
		fetched, err := fetchAnchorEventsByPK(ctx, db, tx, needPKFetch)
		if err != nil {
			return nil, time.Time{}, false, err
		}
		for _, r := range fetched {
			rawByID[r.id] = r
		}
	}

	var otherHits []OtherAlertHit
	var latestAuthFail time.Time

	for _, c := range activeCands {
		var ips []string
		if c.eventID != nil {
			if ae, ok := authByID[*c.eventID]; ok {
				if ae.srcIP != "" {
					ips = append(ips, ae.srcIP)
				}
			} else if ev, ok := rawByID[*c.eventID]; ok {
				ips = ExtractAlertIPs(c.ruleID, c.detail, ev.classUID, ev.raw)
			}
		}
		if len(ips) == 0 {
			ips = ExtractAlertIPs(c.ruleID, c.detail, 0, nil)
		}
		matchedIP := ""
		for _, ip := range ips {
			if srcIPSet[ip] {
				matchedIP = ip
				break
			}
		}
		if matchedIP == "" {
			continue
		}
		endTs := c.ts
		if c.lastTs != nil && c.lastTs.After(endTs) {
			endTs = *c.lastTs
		}
		if IsAuthFailureRule(c.ruleID) {
			if endTs.After(latestAuthFail) {
				latestAuthFail = endTs
			}
			continue
		}
		otherHits = append(otherHits, OtherAlertHit{
			AlertID: c.id,
			RuleID:  c.ruleID,
			SrcIP:   matchedIP,
			Ts:      c.ts,
		})
	}
	return otherHits, latestAuthFail, truncated, nil
}

// checkMaterializedCoverage 校验：
//  1. 首次失败时间必须严格晚于 settings['auth_events.recorded_since']（上线前存量事件因 auth_events 缺历史登录，一律走研判不自动结案）；
//  2. 核验窗口起点不得早于已退役的事件保留期边界（janitor 按同保留期清理 auth_events 与退役日分区）。
func checkMaterializedCoverage(
	ctx context.Context,
	db *ent.Client,
	sqlDB *sql.DB,
	tx *sql.Tx,
	firstFailure, windowFrom time.Time,
	addIncomplete func(string),
) error {
	recordedSince, ok, err := loadRecordedSince(ctx, db, tx)
	if err != nil {
		return err
	}
	if !ok {
		addIncomplete("认证事件物化表起始时间未初始化，无法确认历史窗口完整")
	} else if !firstFailure.After(recordedSince) {
		addIncomplete(fmt.Sprintf("首次失败时间（%s）不晚于认证物化表启用时间（%s），上线前存量事件不自动结案",
			firstFailure.UTC().Format(time.RFC3339), recordedSince.UTC().Format(time.RFC3339)))
	}

	if tx != nil {
		retired, err := isWindowPartitionRetired(ctx, sqlDB, tx, windowFrom)
		if err != nil {
			return err
		}
		if retired {
			addIncomplete("核验时间窗起点已超出事件保留期（对应日分区已退役），无法证明全窗口无成功登录")
		}
	}
	return nil
}

func loadRecordedSince(ctx context.Context, db *ent.Client, tx *sql.Tx) (time.Time, bool, error) {
	var raw []byte
	if tx != nil {
		err := tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE id = $1`, authevents.RecordedSinceKey).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, false, nil
		}
		if err != nil {
			return time.Time{}, false, err
		}
	} else {
		row, err := db.Setting.Get(ctx, authevents.RecordedSinceKey)
		if ent.IsNotFound(err) {
			return time.Time{}, false, nil
		}
		if err != nil {
			return time.Time{}, false, err
		}
		raw = row.Value
	}
	var at time.Time
	if err := json.Unmarshal(raw, &at); err != nil || at.IsZero() {
		return time.Time{}, false, nil
	}
	return at, true, nil
}

// isWindowPartitionRetired 判断核验窗口起点是否已超出保留期（存在月归档分区且早于最老热日分区下界）。
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
			alive := as.LastSeen.After(now.Add(-syslogQuietAliveWindow))
			if !alive && tx != nil {
				var err error
				alive, err = hasRecentAssetAuthEvent(ctx, tx, aid, now.Add(-syslogQuietAliveWindow), queryTo)
				if err != nil {
					return err
				}
			}
			if !alive {
				addIncomplete(fmt.Sprintf("纯 Syslog 资产 %s 近 %s 无活跃上报心跳或认证日志，无法排除日志链路中断",
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

func hasRecentAssetAuthEvent(ctx context.Context, tx *sql.Tx, assetID uuid.UUID, from, to time.Time) (bool, error) {
	var exists bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS (
  SELECT 1 FROM auth_events WHERE asset_id = $1 AND ts >= $2 AND ts <= $3 LIMIT 1
)`, assetID, from, to).Scan(&exists)
	return exists, err
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
