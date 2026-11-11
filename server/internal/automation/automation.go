// Package automation 认出运维自动化（运维脚本、第三方 AI 运维插件）触发的告警。
//
// agent 给 SSH 登录会话里的进程打上 login_session：用户、来源地址、公钥指纹取自 sshd 自己写的认证日志
// （按 journald 记下的内核凭据核对出处），会话归属按内核审计会话号。平台按登录规律与告警结论自动识别
// 运维自动化的登录身份（见 sweep.go），组管理员也可以手工登记；对得上的告警照常入库、挂到条目上，
// 但不进关联、研判与推送——与平台指令（cmdorigin）同一口径。
//
// 识别只认登录事实，不认命令行与进程名：命令行每次不同、攻击者也能随意构造。
// 可信来源被盗用（密钥失窃）时不能全盲，所以高危例外（Watch）即使来自可信来源也照常进研判。
//
// docker 容器的健康检查（HEALTHCHECK）是另一类已知自动化：dockerd 每隔几秒在容器里跑一遍配置好的命令，
// agent 按容器配置逐字认出它和它的后代并打标（Healthcheck），告警同样不进关联与研判，高危例外照常。
package automation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent/alert"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/sigma"
)

type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Login 事件体上的 login_session
type Login struct {
	User   string
	SrcIP  string
	KeyFP  string
	Method string
}

// Session 事件体上 agent 打的登录归属；没有返回 false
func Session(raw map[string]any) (Login, bool) {
	ls, ok := raw["login_session"].(map[string]any)
	if !ok {
		return Login{}, false
	}
	str := func(k string) string { s, _ := ls[k].(string); return s }
	l := Login{User: str("user"), SrcIP: str("src_ip"), KeyFP: str("key_fp"), Method: str("auth_method")}
	return l, l.SrcIP != "" || l.KeyFP != ""
}

// Source 一条可信来源的识别条件，空指针表示不限
type Source struct {
	ID             uuid.UUID
	KeyFingerprint *string
	SourceCIDR     *string
	LoginUser      *string
}

// Matches 登录是否满足来源的全部条件。指纹与网段都没有的来源什么都不认——只按用户名谁都能冒充
func (s Source) Matches(l Login) bool {
	if s.KeyFingerprint == nil && s.SourceCIDR == nil {
		return false
	}
	if s.KeyFingerprint != nil && *s.KeyFingerprint != l.KeyFP {
		return false
	}
	if s.LoginUser != nil && *s.LoginUser != l.User {
		return false
	}
	if s.SourceCIDR != nil {
		prefix, err := netip.ParsePrefix(*s.SourceCIDR)
		addr, aerr := netip.ParseAddr(l.SrcIP)
		// 来源地址解析不了（sshd 开了 UseDNS 记成主机名）就当对不上
		if err != nil || aerr != nil || !prefix.Contains(addr.Unmap()) {
			return false
		}
	}
	return true
}

// Of 事件所属的可信来源：资产所在组里生效（未撤销、按事件时间未过期）且条件全部对得上的最早一条，命中时累加计数。
// 没有登录归属或对不上返回 nil。只该对 agent 上报的事件调用——syslog、探针的事件体由外部内容拼成
func Of(ctx context.Context, q Querier, raw map[string]any, asset *uuid.UUID, ts time.Time) (*uuid.UUID, error) {
	login, ok := Session(raw)
	if !ok || asset == nil || q == nil {
		return nil, nil
	}
	rows, err := q.QueryContext(ctx, `SELECT t.id, t.key_fingerprint, t.source_cidr, t.login_user
FROM trusted_sources t JOIN assets a ON a.group_id = t.group_id
WHERE a.id = $1 AND t.revoked_at IS NULL AND t.expires_at > $2
ORDER BY t.created_at`, *asset, ts)
	if err != nil {
		return nil, err
	}
	var hit *uuid.UUID
	for rows.Next() {
		var s Source
		if err := rows.Scan(&s.ID, &s.KeyFingerprint, &s.SourceCIDR, &s.LoginUser); err != nil {
			rows.Close()
			return nil, err
		}
		if hit == nil && s.Matches(login) {
			hit = &s.ID
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil || hit == nil {
		return nil, err
	}
	_, err = q.ExecContext(ctx, `UPDATE trusted_sources SET matched_count = matched_count + 1,
  last_matched_at = GREATEST(COALESCE(last_matched_at, $2), $2) WHERE id = $1`, *hit, ts)
	return hit, err
}

// 高危例外：可信来源被盗用时最要紧的几类行为——拿凭据、抹痕迹、关防护、搞破坏、往 SSH 授权钥匙里留后门。
// 运维自动化几乎不需要做这些，做了也值得人看一眼。不按 severity 阈值：反弹 shell 特征
// 这类 critical 规则恰恰是运维脚本（/dev/tcp 探测、exec 3<&0 包装）最常误中的，按阈值等于白登记
var (
	watchTactics = map[string]bool{
		"credential-access":  true,
		"defense-impairment": true,
		"impact":             true,
	}
	// 技术按前缀比，子技术一并算：T1070 指标清除（清日志、清历史）、T1562 削弱防御（关审计、关防火墙）、
	// T1003 凭据转储、T1485/T1486/T1490 数据销毁、加密勒索、删备份与卷影、
	// T1098.004 往 authorized_keys 追加钥匙：偷到可信钥匙的人留后门最直接的一步，运维自动化几乎不做。
	// 只收这一项，不收整个持久化战术：装 systemd 服务、写 cron 是运维日常
	watchTechniques = []string{"T1003", "T1070", "T1562", "T1485", "T1486", "T1490", "T1098.004"}
	// 低/中危（severity≤3）规则里仅涉及常规权限/时间戳调整、根证书更新、通用配置文件编辑的技术：
	// SigmaHQ 给这类规则也标了 defense-impairment / impact（如 chmod /tmp、update-ca-certificates、sed /etc/*.conf），
	// 把它们当高危例外会让日常构建和运维脚本跳过（规则, 资产）去重、每半小时触发重研判甚至插队。
	// 仅当规则声明的全部技术均在此窄列表内且 severity≤3 时才豁免；凭据窃取、关防护（T1562）、清日志、破坏或高危（severity≥4）一律保留高危例外。
	routineLowMedTechniques = []string{"T1222", "T1553", "T1565", "T1070.006"}
)

// syntheticWatch 不在规则库里、按自身性质列入高危例外的平台合成规则：爆破得手（凭据）、内部横向喷洒、平台自身监控与审计篡改
var syntheticWatch = map[string]bool{
	sigma.RuleBruteforceSuccess:  true,
	sigma.RuleLateralSpray:       true,
	sigma.RuleControlPlaneChange: true,
	sigma.RuleCoreAgentSilent:    true,
	sigma.RuleAuditTamper:        true,
}

// Watch 来自可信来源的这条命中是否仍要进关联与研判。情报命中（已知恶意的地址、域名、文件）一律进；
// 在本次命中的规则里找不到（不该发生）也进——拿不准就不放过
func Watch(ruleID string, rules []*sigma.Rule) bool {
	critical, known := watch(ruleID, rules)
	return critical || !known
}

// KnownCritical 确知属于高危例外：情报命中、列名的合成规则、规则库里标了高危战术/技术的规则。
// 查不到的规则不算——关联按它判断「高危不被吸收」，兜底算高危会让首次出现这类低危合成告警也不能复发归并
func KnownCritical(ruleID string, rules []*sigma.Rule) bool {
	critical, _ := watch(ruleID, rules)
	return critical
}

func watch(ruleID string, rules []*sigma.Rule) (critical, known bool) {
	if strings.HasPrefix(ruleID, "intel:") || syntheticWatch[ruleID] {
		return true, true
	}
	for _, r := range rules {
		if r.ID == ruleID {
			return Critical(r), true
		}
	}
	return false, false
}

// Critical 规则是否属于高危例外
func Critical(r *sigma.Rule) bool {
	if r.Severity > 0 && r.Severity <= 3 && routineLowMed(r.Techniques) {
		return false
	}
	for _, t := range r.Tactics {
		if watchTactics[t] {
			return true
		}
	}
	for _, t := range r.Techniques {
		if matchesTechnique(strings.ToUpper(t), watchTechniques) {
			return true
		}
	}
	return false
}

func routineLowMed(techniques []string) bool {
	if len(techniques) == 0 {
		return false
	}
	for _, t := range techniques {
		if !matchesTechnique(strings.ToUpper(t), routineLowMedTechniques) {
			return false
		}
	}
	return true
}

func matchesTechnique(tech string, prefixes []string) bool {
	for _, w := range prefixes {
		if tech == w || strings.HasPrefix(tech, w+".") {
			return true
		}
	}
	return false
}

// Counted 进事件关联与态势统计的告警：既不来自可信来源、也不是容器健康检查，或是高危例外
func Counted() predicate.Alert {
	return alert.Or(alert.And(alert.AutomationIDIsNil(), alert.Healthcheck(false)), alert.AutomationWatch(true))
}

// Healthcheck 事件是不是 agent 认出的 docker 容器健康检查（HEALTHCHECK 配置的命令或其后代，见 agent 的 healthcheck_of）。
// 与可信来源同一口径：告警照常入库，不进关联、研判与推送，高危例外（Watch）照常。
// 标记是事件体里的字段，只该对 agent 上报的事件调用——syslog、探针的事件体由外部内容拼成，谁都能写
func Healthcheck(raw map[string]any) bool {
	c, _ := raw["container"].(map[string]any)
	hc, _ := c["healthcheck"].(bool)
	return hc && c["runtime"] == "docker"
}

var fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// MaxDays 有效期上限：可信来源是降低检测的配置，到期要有人重新确认
const MaxDays = 365

// Criteria 登记时的识别条件
type Criteria struct {
	KeyFingerprint string
	SourceCIDR     string
	LoginUser      string
}

// Normalize 校验并规范化条件：指纹是 SHA256:<43 位 base64>（ssh-keygen -lf 的写法）；来源写 CIDR 或单个地址，
// 统一成网络地址；至少要有指纹或来源之一，只填用户名等于按用户名放行，谁都能用那个账号登录
func (c Criteria) Normalize() (Criteria, error) {
	c.KeyFingerprint = strings.TrimSpace(c.KeyFingerprint)
	c.SourceCIDR = strings.TrimSpace(c.SourceCIDR)
	c.LoginUser = strings.TrimSpace(c.LoginUser)
	if c.KeyFingerprint == "" && c.SourceCIDR == "" {
		return c, errors.New("公钥指纹与来源网段至少填一个")
	}
	if c.KeyFingerprint != "" && !fingerprintRe.MatchString(c.KeyFingerprint) {
		return c, errors.New("公钥指纹应形如 SHA256:<43 位 base64>，可用 ssh-keygen -lf <公钥文件> 查看")
	}
	if c.SourceCIDR != "" {
		prefix, err := netip.ParsePrefix(c.SourceCIDR)
		if err != nil {
			addr, aerr := netip.ParseAddr(c.SourceCIDR)
			if aerr != nil {
				return c, fmt.Errorf("来源网段 %q 不是 CIDR 或 IP 地址", c.SourceCIDR)
			}
			prefix = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()).Masked()
		// 太宽的网段等于放行一整片网络里的任何人；没有指纹时只允许收窄到 /24（IPv6 /64）
		if c.KeyFingerprint == "" && prefix.Bits() < minBits(prefix.Addr()) {
			return c, fmt.Errorf("只按来源网段登记时网段不能宽于 /%d", minBits(prefix.Addr()))
		}
		c.SourceCIDR = prefix.String()
	}
	if len(c.LoginUser) > 64 || strings.ContainsAny(c.LoginUser, " \t\n") {
		return c, errors.New("登录用户名无效")
	}
	return c, nil
}

func minBits(a netip.Addr) int {
	if a.Is4() {
		return 24
	}
	return 64
}
