package automation

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/event"
	"openxdr/server/ent/schema"
	"openxdr/server/ent/sshlogin"
	"openxdr/server/internal/review"
)

// Config 自动识别的参数，见 docs/deployment.md 配置表
type Config struct {
	Enabled bool
	// 统计窗口（天）：登录规律与告警结论都只看这么久
	WindowDays int
	// 窗口内至少几天有登录、总共至少几次登录
	MinDays   int
	MinLogins int
	// 没有人工误报结论时，至少要有几个 AI 判良性的事件
	AIBenign int
	// 自动识别的有效期（天），持续满足条件时自动续期
	TTLDays int
}

func DefaultConfig() Config {
	return Config{Enabled: true, WindowDays: 7, MinDays: 3, MinLogins: 20, AIBenign: 3, TTLDays: 30}
}

var config = DefaultConfig()

// Configure 启动时按环境变量设置一次，接口的候选解释与后台识别共用
func Configure(c Config) { config = c }

// CurrentConfig 当前生效的参数
func CurrentConfig() Config { return config }

// 一个登录身份没被自动识别的原因。顺序即判断顺序：先看登录本身，再看告警结论
const (
	ReasonEligible    = "eligible"     // 满足全部条件
	ReasonNoKey       = "no_key"       // 不是公钥登录
	ReasonPublic      = "public"       // 来源是公网地址
	ReasonScattered   = "scattered"    // 来源地址不在同一个 /24（IPv6 /64）
	ReasonFlagged     = "flagged"      // 告警被判属实、恶意或可疑
	ReasonIrregular   = "irregular"    // 登录天数或次数不够
	ReasonQuiet       = "quiet"        // 没有触发过告警，不需要识别
	ReasonPending     = "pending"      // 有告警还没有结论
	ReasonFewVerdicts = "few_verdicts" // 良性结论还不够
)

// Assessment 一个登录身份（组 + 用户 + 公钥；非公钥登录再加来源地址）在窗口内的表现
type Assessment struct {
	Group     uuid.UUID
	User      string
	KeyFP     string
	KeyType   string
	Addresses []string
	// 来源地址稳定时的网段：只有一个地址是 /32（/128），否则是共同的 /24（/64）
	CIDR      string
	Logins    int
	Days      int
	Hosts     int
	LastLogin time.Time
	// 触发的告警数，与按事件计的结论
	Alerts      int
	HumanBenign int
	AIBenign    int
	Pending     int
	// 第一个被判属实、恶意或可疑的事件
	Flagged *uuid.UUID
	Reason  string
}

// Evidence 写到自动识别记录上的依据
func (a *Assessment) Evidence(c Config, now time.Time) *schema.AutomationEvidence {
	return &schema.AutomationEvidence{
		WindowDays: c.WindowDays, Days: a.Days, Logins: a.Logins, Hosts: a.Hosts, Addresses: a.Addresses,
		LastLogin: a.LastLogin, HumanBenign: a.HumanBenign, AIBenign: a.AIBenign, Alerts: a.Alerts, CheckedAt: now,
	}
}

// Login 代表性的登录：判断已有来源是否覆盖这个身份用
func (a *Assessment) Login(addr string) Login {
	return Login{User: a.User, SrcIP: addr, KeyFP: a.KeyFP, Method: "publickey"}
}

// Renewable 已生效的自动识别能否续期：登录仍然规律、没有被判可疑以上。
// 生效后它的告警不再研判，良性结论会随窗口滑走，所以续期不再要求新的结论
func (a *Assessment) Renewable() bool {
	switch a.Reason {
	case ReasonEligible, ReasonQuiet, ReasonPending, ReasonFewVerdicts:
		return true
	}
	return false
}

// 告警的结论，按它所在的事件（incident）算
type conclusion int

const (
	neutral     conclusion = iota // 已挂在运维自动化上、不进研判的告警，不算证据
	pending                       // 还没有结论，或良性结论按「需人工复核」口径不作数
	humanBenign                   // 人工判误报
	aiBenign                      // AI 判良性（含系统按良性自动结案、人直接采纳 AI 结论的）
	bad                           // 人工判属实，或 AI 判恶意、可疑
)

// fact 一条带登录归属的告警
type fact struct {
	group    uuid.UUID
	login    Login
	ts       time.Time
	source   *uuid.UUID
	incident *uuid.UUID
	verdict  conclusion
}

func classify(a *ent.Alert, maxSev map[uuid.UUID]int16) conclusion {
	inc := a.Edges.Incident
	if inc == nil {
		if a.AutomationID != nil && !a.AutomationWatch {
			return neutral
		}
		return pending
	}
	switch inc.Status {
	case "closed":
		return bad
	case "false_positive":
		// 系统自动结案、人直接采纳 AI 结论的都不是人的独立判断
		if (inc.ResolvedBy != nil && *inc.ResolvedBy == review.ClosedBy) || (inc.ResolutionSource != nil && *inc.ResolutionSource != "") {
			return aiBenign
		}
		return humanBenign
	}
	switch verdictOf(inc.AiVerdict) {
	case "malicious", "suspicious":
		return bad
	case "benign":
		// 重开待重新研判的旧结论不作数；高危事件的良性结论要人复核，与通知、待复核同一口径
		if inc.Status == "triaged" && maxSev[inc.ID] < review.Severity {
			return aiBenign
		}
	}
	return pending
}

// Assess 窗口内各登录身份的表现。group 为空时看全部组
func Assess(ctx context.Context, db *ent.Client, sqlDB *sql.DB, c Config, group *uuid.UUID, now time.Time) ([]*Assessment, []fact, error) {
	since := now.AddDate(0, 0, -c.WindowDays)
	lq := db.SSHLogin.Query().Where(sshlogin.TsGT(since))
	if group != nil {
		lq = lq.Where(sshlogin.GroupIDEQ(*group))
	}
	logins, err := lq.Order(ent.Asc(sshlogin.FieldTs)).All(ctx)
	if err != nil {
		return nil, nil, err
	}
	facts, err := loadFacts(ctx, db, sqlDB, group, now.AddDate(0, 0, -max(c.WindowDays, c.TTLDays)))
	if err != nil {
		return nil, nil, err
	}

	// 一律按来源地址分开：同一把钥匙从工作站和脚本机都登录时，人手动的会话不能跟着脚本一起被认成自动化
	type key struct {
		group    uuid.UUID
		user, fp string
		addr     string
	}
	keyOf := func(g uuid.UUID, l Login) key {
		k := key{group: g, user: l.User, addr: l.SrcIP}
		if l.Method == "publickey" {
			k.fp = l.KeyFP
		}
		return k
	}
	byKey := map[key]*Assessment{}
	var order []key
	days := map[key]map[int]bool{}
	hosts := map[key]map[uuid.UUID]bool{}
	addrs := map[key]map[string]bool{}
	for _, l := range logins {
		login := Login{User: l.LoginUser, SrcIP: l.SrcIP, Method: l.AuthMethod}
		if l.KeyFp != nil {
			login.KeyFP = *l.KeyFp
		}
		k := keyOf(l.GroupID, login)
		a := byKey[k]
		if a == nil {
			a = &Assessment{Group: l.GroupID, User: login.User}
			if k.fp != "" {
				a.KeyFP = k.fp
			}
			byKey[k] = a
			days[k], hosts[k], addrs[k] = map[int]bool{}, map[uuid.UUID]bool{}, map[string]bool{}
			order = append(order, k)
		}
		if l.KeyType != nil {
			a.KeyType = *l.KeyType
		}
		a.Logins++
		a.LastLogin = l.Ts
		days[k][int(now.Sub(l.Ts)/(24*time.Hour))] = true
		hosts[k][l.AssetID] = true
		addrs[k][l.SrcIP] = true
	}
	counted := map[key]map[uuid.UUID]conclusion{}
	for _, f := range facts {
		k := keyOf(f.group, f.login)
		a := byKey[k]
		if a == nil || f.verdict == neutral {
			continue
		}
		// 被判可疑以上的往回看得比窗口更久（与停用同一个回看期），免得刚识别出来就因旧结论被停用
		if f.verdict == bad && a.Flagged == nil {
			a.Flagged = f.incident
		}
		if f.ts.Before(since) {
			continue
		}
		a.Alerts++
		if f.incident == nil {
			a.Pending++
			continue
		}
		// 结论按事件计：同一个事件里的多条告警只算一次
		if counted[k] == nil {
			counted[k] = map[uuid.UUID]conclusion{}
		}
		if _, ok := counted[k][*f.incident]; ok {
			continue
		}
		counted[k][*f.incident] = f.verdict
		switch f.verdict {
		case humanBenign:
			a.HumanBenign++
		case aiBenign:
			a.AIBenign++
		case pending:
			a.Pending++
		}
	}
	out := make([]*Assessment, 0, len(order))
	for _, k := range order {
		a := byKey[k]
		a.Days, a.Hosts = len(days[k]), len(hosts[k])
		for addr := range addrs[k] {
			a.Addresses = append(a.Addresses, addr)
		}
		sort.Strings(a.Addresses)
		a.CIDR = commonPrefix(a.Addresses)
		a.Reason = c.reason(a)
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Logins > out[j].Logins })
	return out, facts, nil
}

func (c Config) reason(a *Assessment) string {
	switch {
	case a.KeyFP == "":
		return ReasonNoKey
	case !allInternal(a.Addresses):
		return ReasonPublic
	case a.CIDR == "":
		return ReasonScattered
	case a.Flagged != nil:
		return ReasonFlagged
	case a.Days < c.MinDays || a.Logins < c.MinLogins:
		return ReasonIrregular
	case a.Alerts == 0:
		return ReasonQuiet
	case a.Pending > 0:
		return ReasonPending
	case a.HumanBenign == 0 && a.AIBenign < c.AIBenign:
		return ReasonFewVerdicts
	}
	return ReasonEligible
}

// loadFacts 窗口内 agent 事件触发、带登录归属的告警，连同它所在事件的结论。
// 告警表很小，按资产与时间取出后在内存里筛登录归属，比按 JSON 条件扫事件便宜得多
func loadFacts(ctx context.Context, db *ent.Client, sqlDB *sql.DB, group *uuid.UUID, since time.Time) ([]fact, error) {
	q := db.Alert.Query().Where(alert.TsGT(since), alert.CommandIDIsNil(), alert.EventIDNotNil(), alert.AssetIDNotNil())
	if group != nil {
		q = q.Where(alert.HasAssetWith(asset.GroupIDEQ(*group)))
	}
	alerts, err := q.
		WithIncident().
		WithAsset(func(q *ent.AssetQuery) { q.Select(asset.FieldID, asset.FieldGroupID) }).
		All(ctx)
	if err != nil {
		return nil, err
	}
	events, err := alertEvents(ctx, db, sqlDB, alerts)
	if err != nil {
		return nil, err
	}
	var incidents []uuid.UUID
	for _, a := range alerts {
		if a.IncidentID != nil {
			incidents = append(incidents, *a.IncidentID)
		}
	}
	maxSev := map[uuid.UUID]int16{}
	if len(incidents) > 0 {
		var rows []struct {
			IncidentID uuid.UUID `json:"incident_id"`
			Max        int16     `json:"max"`
		}
		if err := db.Alert.Query().Where(alert.IncidentIDIn(incidents...)).GroupBy(alert.FieldIncidentID).
			Aggregate(ent.As(ent.Max(alert.FieldSeverity), "max")).Scan(ctx, &rows); err != nil {
			return nil, err
		}
		for _, r := range rows {
			maxSev[r.IncidentID] = r.Max
		}
	}
	var out []fact
	for _, a := range alerts {
		ev, as := events[*a.EventID], a.Edges.Asset
		if ev == nil || as == nil || as.GroupID == nil || ev.Source != "agent" {
			continue
		}
		login, ok := sessionOf(ev.Raw)
		if !ok {
			continue
		}
		out = append(out, fact{group: *as.GroupID, login: login, ts: a.Ts, source: a.AutomationID,
			incident: a.IncidentID, verdict: classify(a, maxSev)})
	}
	return out, nil
}

// alertEvents 取告警所在事件的来源与原文。events 按天分区，只按 id 查要在每个分区上各探一次（生产 41 个分区、
// 几千条告警要 3–6 秒，还会挡住分区退役拿锁）；告警时间就是事件时间，按 (id, ts) 逐对查只碰一个分区。
// 个别对不上时间的（告警时间取自别处的路径）再按 id 补查
func alertEvents(ctx context.Context, db *ent.Client, sqlDB *sql.DB, alerts []*ent.Alert) (map[uuid.UUID]*ent.Event, error) {
	ids := make([]uuid.UUID, len(alerts))
	tss := make([]time.Time, len(alerts))
	for i, a := range alerts {
		ids[i], tss[i] = *a.EventID, a.Ts
	}
	rows, err := sqlDB.QueryContext(ctx, `SELECT k.id, e.source, e.raw FROM unnest($1::uuid[], $2::timestamptz[]) AS k(id, ts)
 JOIN LATERAL (SELECT source, raw FROM events WHERE id = k.id AND ts = k.ts) e ON true`, ids, tss)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]*ent.Event{}
	for rows.Next() {
		ev := &ent.Event{}
		var raw []byte
		if err := rows.Scan(&ev.ID, &ev.Source, &raw); err != nil {
			return nil, err
		}
		ev.Raw = json.RawMessage(raw)
		out[ev.ID] = ev
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var missing []uuid.UUID
	for _, id := range ids {
		if out[id] == nil {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return out, nil
	}
	rest, err := db.Event.Query().Where(event.IDIn(missing...)).Select(event.FieldID, event.FieldSource, event.FieldRaw).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, ev := range rest {
		out[ev.ID] = ev
	}
	return out, nil
}

// commonPrefix 地址都相同给 /32（/128），都在同一个 /24（/64）给该网段，否则为空
func commonPrefix(addrs []string) string {
	var prefix netip.Prefix
	for i, s := range addrs {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return ""
		}
		addr = addr.Unmap()
		p := netip.PrefixFrom(addr, addr.BitLen())
		if len(addrs) > 1 {
			p, _ = addr.Prefix(minBits(addr))
		}
		if i > 0 && p != prefix {
			return ""
		}
		prefix = p
	}
	if !prefix.IsValid() {
		return ""
	}
	return prefix.String()
}

// cgnat 100.64.0.0/10：运营商级 NAT 与 Tailscale 这类组网用的地址，不在公网上
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// allInternal 来源全是内网地址。公网来源一律不自动识别：同一个出口地址后面可能是任何人，
// 密钥一旦泄露，攻击者从公网登录就直接被当成运维自动化
func allInternal(addrs []string) bool {
	for _, s := range addrs {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return false
		}
		addr = addr.Unmap()
		if !addr.IsPrivate() && !addr.IsLoopback() && !cgnat.Contains(addr) {
			return false
		}
	}
	return len(addrs) > 0
}
