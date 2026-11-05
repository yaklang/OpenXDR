// Package fpstats 误报统计 → 抑制草案：把人反复下的「误报」结论回喂到规则层。
//
// 同一条规则在同一台主机上被人判误报够多次、误报率够高、期间没有一次判属实，
// 就生成一条待批准的抑制草案，交 AI 审计员评审（没配时留给组管理员）。草案从不直接生效。
//
// 只算独立人工结论（resolution_source IS NULL 且 resolved_by 为 users 表中角色为 admin/analyst 的真实账号）：
// 系统自动结案只是复述 AI 的良性判断；原样采纳 AI 结案建议（ai_proposal）的，
// 结论和理由都出自 AI，计进来就成了「AI 提议结案 → AI 统计 → AI 提议抑制」的自我强化，
// 两者单独计数写进依据，不进分子也不进分母。其他任意非 nil resolution_source（含空字符串、ai_verdict、
// ai_review、external_integration 等）或非平台真实人工账号（如 system、ai_reviewer、viewer、已删账号）
// 一律 fail-closed 排除，绝不计入独立人工误报统计。
package fpstats

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/schema"
	"openxdr/server/ent/suppression"
	"openxdr/server/ent/user"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/review"
	"openxdr/server/internal/suppress"
)

// CreatedBy 误报统计草案的 created_by，控制台据此标来源
const CreatedBy = "fp-stats"

// entityFields 按实体收窄时依次尝试的字段：先看规则作用的对象（域名、对端、文件、注册表、模块、具体命令行），
// 最后才是发起的进程映像——同一个进程往往干很多事，按进程压比按对象或具体命令行压宽
var entityFields = []string{
	"query.hostname",
	"dst_endpoint.ip",
	"file.path",
	"reg_key.path",
	"module.file.path",
	"process.cmd_line",
	"process.file.path",
	"src_endpoint.ip",
}

// imageField 按对象收窄后，如果这些命中都出自同一个进程映像，再加一条进程条件
const imageField = "process.file.path"
const cmdLineField = "process.cmd_line"

// genericImages shell、脚本解释器与常被滥用的系统程序：攻击同样经由它们执行，
// 按它们的映像「收窄」压掉的其实是这条规则在这台主机上的全部命中，不算实体
var genericImages = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true, "busybox": true,
	"python": true, "python2": true, "python3": true, "perl": true, "ruby": true, "node": true, "php": true,
	"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "pwsh": true, "wscript.exe": true, "cscript.exe": true,
	"mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true,
}

// generic 取值是否是不能当实体的通用映像或裸解释器命令行
func generic(field, value string) bool {
	if field != imageField && field != cmdLineField {
		return false
	}
	value = strings.TrimSpace(value)
	if field == cmdLineField && strings.ContainsAny(value, " \t") {
		return false
	}
	base := strings.ToLower(value[strings.LastIndexAny(value, `/\`)+1:])
	if genericImages[base] {
		return true
	}
	// python3.11 之类带版本号的
	return strings.HasPrefix(base, "python") || strings.HasPrefix(base, "perl") || strings.HasPrefix(base, "php")
}

// maxDraftsPerKey 同一（规则、主机）一轮最多出几条按实体的草案，免得一次把审批页刷屏
const maxDraftsPerKey = 5

// maxEvidence 依据里最多列多少个事件
const maxEvidence = 20

type Stats struct {
	DB *ent.Client
	// 统计窗口：这段时间内有告警的事件
	Window time.Duration
	// 计入的人工误报至少几次；0 关闭
	MinCount int
	// 误报率下限（百分比）：误报 / (误报 + 属实 + 未结案)
	MinRatio int
	// 草案建议的有效期（天），批准时从批准那一刻起算
	Days int
	// 被拒绝的同范围草案多久内不再生成
	Cooldown time.Duration
	Interval time.Duration
	// Proposed 草案落库后通知评审（后台进行，不阻塞统计）；为空时草案留给人审
	Proposed func(id uuid.UUID)
}

// Run 拿到租约先扫一次再按周期扫
func (s *Stats) Run(ctx context.Context) {
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		if n, err := s.Sweep(ctx, time.Now()); err != nil {
			slog.Error("误报统计失败", "err", err)
		} else if n > 0 {
			slog.Info("误报统计生成抑制草案", "drafts", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type key struct {
	rule  string
	asset uuid.UUID
}

// kind 一个事件对统计的意义
type kind int

const (
	ignored    kind = iota
	fp              // 计入的人工误报
	tp              // 属实，不论谁判的
	pending         // 还没结案
	aiProposal      // 原样采纳 AI 结案建议的误报，不计入
	autoClosed      // 系统自动结案，不计入
)

func classify(inc *ent.Incident, humanUsers map[string]bool) kind {
	switch inc.Status {
	case "closed":
		return tp
	case "open", "triaged":
		return pending
	case "false_positive":
	default:
		return ignored
	}
	switch {
	// 早期结案没记结案人，分不清是不是人判的，不算
	case inc.ResolvedBy == nil:
		return ignored
	case *inc.ResolvedBy == review.ClosedBy:
		return autoClosed
	case inc.ResolutionSource != nil && *inc.ResolutionSource == "ai_proposal":
		return aiProposal
	// 任意非 nil resolution_source（含空字符串、ai_verdict、ai_review、external_integration 等）均非独立人工判断，不推动抑制草案
	case inc.ResolutionSource != nil:
		return ignored
	}
	resolvedBy := strings.TrimSpace(*inc.ResolvedBy)
	if resolvedBy == "" || *inc.ResolvedBy != resolvedBy || len(humanUsers) == 0 || !humanUsers[resolvedBy] {
		return ignored
	}
	return fp
}

// tally 一组事件的结论计数，每个事件只算一次
type tally struct {
	counts map[kind]int
	fps    []*ent.Incident
	seen   map[uuid.UUID]bool
}

func (t *tally) add(inc *ent.Incident, k kind) {
	if t.seen == nil {
		t.seen, t.counts = map[uuid.UUID]bool{}, map[kind]int{}
	}
	if t.seen[inc.ID] {
		return
	}
	t.seen[inc.ID] = true
	t.counts[k]++
	if k == fp {
		t.fps = append(t.fps, inc)
	}
}

func (t *tally) ratio() int {
	total := t.counts[fp] + t.counts[tp] + t.counts[pending]
	if total == 0 {
		return 0
	}
	return t.counts[fp] * 100 / total
}

func (s *Stats) qualifies(t *tally) bool {
	return t.counts[fp] >= s.MinCount && t.counts[tp] == 0 && t.ratio() >= s.MinRatio
}

type draft struct {
	key   key
	conds []suppress.Condition
	t     *tally
}

// Sweep 统计一轮并写入草案，返回新生成的条数。多节点由租约保证单活
func (s *Stats) Sweep(ctx context.Context, now time.Time) (int, error) {
	if s.MinCount <= 0 {
		return 0, nil
	}
	usernames, err := s.DB.User.Query().
		Where(user.RoleIn("admin", "analyst")).
		Select(user.FieldUsername).
		Strings(ctx)
	if err != nil {
		return 0, err
	}
	humanUsers := make(map[string]bool, len(usernames))
	for _, u := range usernames {
		u = strings.TrimSpace(u)
		if u != "" {
			humanUsers[u] = true
		}
	}
	since := now.Add(-s.Window)
	inWindow := alert.Or(alert.TsGTE(since), alert.LastTsGTE(since))
	// 先不带事件体按（规则、主机）粗算，只有人工误报够数的才去读事件体按实体细算
	alerts, err := s.DB.Alert.Query().
		Where(inWindow, alert.CommandIDIsNil(), alert.AssetIDNotNil(), alert.IncidentIDNotNil()).
		WithIncident().All(ctx)
	if err != nil {
		return 0, err
	}
	byKey := map[key]*tally{}
	severe := map[key]bool{}
	for _, a := range alerts {
		if a.Edges.Incident == nil {
			continue
		}
		k := key{a.RuleID, *a.AssetID}
		// 高危及以上的规则不靠统计出草案：和研判同一个口径，高危被一句「良性」吞掉代价太大，要压由人手写条件
		if a.Severity >= review.Severity {
			severe[k] = true
		}
		if byKey[k] == nil {
			byKey[k] = &tally{}
		}
		byKey[k].add(a.Edges.Incident, classify(a.Edges.Incident, humanUsers))
	}
	keys := make([]key, 0, len(byKey))
	for k, t := range byKey {
		if t.counts[fp] >= s.MinCount && !severe[k] {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].rule < keys[j].rule || keys[i].rule == keys[j].rule && keys[i].asset.String() < keys[j].asset.String()
	})
	created := 0
	for _, k := range keys {
		hits, err := s.DB.Alert.Query().
			Where(inWindow, alert.CommandIDIsNil(), alert.RuleIDEQ(k.rule), alert.AssetIDEQ(k.asset), alert.IncidentIDNotNil()).
			WithIncident().WithEvent().All(ctx)
		if err != nil {
			return created, err
		}
		for _, d := range s.drafts(k, byKey[k], hits, humanUsers) {
			ok, err := s.propose(ctx, d, now)
			if err != nil {
				return created, err
			}
			if ok {
				created++
			}
		}
	}
	return created, nil
}

// hit 一条告警的事件体与所属事件
type hit struct {
	inc *ent.Incident
	raw map[string]any // nil 表示事件体已过保留期或读不出
}

// drafts 先按实体找能收窄的值；实体维度分散（没有哪个值单独够数）时才考虑整条规则
func (s *Stats) drafts(k key, whole *tally, alerts []*ent.Alert, humanUsers map[string]bool) []draft {
	hits := make([]hit, 0, len(alerts))
	for _, a := range alerts {
		if a.Edges.Incident == nil {
			continue
		}
		h := hit{inc: a.Edges.Incident}
		if a.Edges.Event != nil && json.Unmarshal(a.Edges.Event.Raw, &h.raw) != nil {
			h.raw = nil
		}
		hits = append(hits, h)
	}
	concentrated := false
	for _, field := range entityFields {
		values := entityTallies(hits, field, humanUsers)
		var out []draft
		for _, v := range values {
			if generic(field, v.value) {
				continue
			}
			if v.t.counts[fp] >= s.MinCount {
				concentrated = true
			}
			if s.qualifies(v.t) && utf8.RuneCountInString(v.value) <= 500 {
				conds := []suppress.Condition{{Field: field, Op: "equals", Value: v.value}}
				if image, ok := sameImage(hits, field, v.value); ok && field != imageField {
					conds = append(conds, suppress.Condition{Field: imageField, Op: "equals", Value: image})
				}
				out = append(out, draft{key: k, conds: conds, t: v.t})
			}
		}
		if len(out) > 0 {
			return out[:min(len(out), maxDraftsPerKey)]
		}
	}
	for _, field := range []string{"file.path", imageField} {
		var out []draft
		for _, v := range entityTalliesBy(hits, field, tempDirPrefix, humanUsers) {
			if v.t.counts[fp] >= s.MinCount {
				concentrated = true
			}
			if s.qualifies(v.t) && utf8.RuneCountInString(v.value) <= 500 {
				conds := []suppress.Condition{{Field: field, Op: "contains", Value: v.value}}
				out = append(out, draft{key: k, conds: conds, t: v.t})
			}
		}
		if len(out) > 0 {
			return out[:min(len(out), maxDraftsPerKey)]
		}
	}
	// 平台合成规则（xdr:new-process 这类 UEBA 首次出现检测）每条命中本来就是不同实体，
	// 整条规则抑制等于关掉这台主机上的这项检测，不出草案
	if concentrated || strings.HasPrefix(k.rule, "xdr:") || !s.qualifies(whole) {
		return nil
	}
	return []draft{{key: k, t: whole}}
}

type valueTally struct {
	value string
	t     *tally
}

// entityTallies 某字段每个取值的结论计数，按误报数从多到少。
// 事件体读不到的命中不知道是哪个值：属实与未结案的从严算进每个值，误报的不算
func entityTallies(hits []hit, field string, humanUsers map[string]bool) []valueTally {
	return entityTalliesBy(hits, field, func(v string) (string, bool) { return v, true }, humanUsers)
}

func entityTalliesBy(hits []hit, field string, extract func(string) (string, bool), humanUsers map[string]bool) []valueTally {
	byValue := map[string]*valueTally{}
	var unknown []*ent.Incident
	for _, h := range hits {
		if h.raw == nil {
			unknown = append(unknown, h.inc)
			continue
		}
		rawVal, ok := suppress.Lookup(h.raw, field)
		if !ok || strings.TrimSpace(rawVal) == "" {
			continue
		}
		v, ok := extract(rawVal)
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		lower := strings.ToLower(v)
		if byValue[lower] == nil {
			byValue[lower] = &valueTally{value: v, t: &tally{}}
		}
		byValue[lower].t.add(h.inc, classify(h.inc, humanUsers))
	}
	out := make([]valueTally, 0, len(byValue))
	for _, v := range byValue {
		for _, inc := range unknown {
			if k := classify(inc, humanUsers); k == tp || k == pending {
				v.t.add(inc, k)
			}
		}
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].t.counts[fp], out[j].t.counts[fp]
		return a > b || a == b && out[i].value < out[j].value
	})
	return out
}

// tempDirPrefix 提取临时构建目录的固定前缀（如 /tmp/go-build3516107513/b001/pkg.test → /tmp/go-build），
// 供每次生成随机后缀的临时构建产物（go test 等）按 contains 收窄，避免退化成整条规则抑制
func tempDirPrefix(path string) (string, bool) {
	for _, root := range []string{"/tmp/", "/var/tmp/"} {
		rest, ok := strings.CutPrefix(path, root)
		if !ok {
			continue
		}
		seg, _, hasSub := strings.Cut(rest, "/")
		if !hasSub {
			return "", false
		}
		trimmed := strings.TrimRight(seg, "0123456789")
		if len(seg)-len(trimmed) >= 4 && len(trimmed) >= 4 {
			return root + trimmed, true
		}
	}
	return "", false
}

// sameImage 取值为 value 的命中是否都出自同一个进程映像
func sameImage(hits []hit, field, value string) (string, bool) {
	image := ""
	for _, h := range hits {
		if h.raw == nil {
			continue
		}
		if v, ok := suppress.Lookup(h.raw, field); !ok || !strings.EqualFold(v, value) {
			continue
		}
		p, ok := suppress.Lookup(h.raw, imageField)
		if !ok || p == "" || image != "" && !strings.EqualFold(p, image) {
			return "", false
		}
		image = p
	}
	return image, image != ""
}

// propose 没有覆盖同范围的生效抑制、待批草案或冷却中的拒绝时写一条草案
func (s *Stats) propose(ctx context.Context, d draft, now time.Time) (bool, error) {
	existing, err := s.DB.Suppression.Query().
		Where(suppression.RuleIDEQ(d.key.rule), suppression.Or(suppression.AssetIDEQ(d.key.asset), suppression.AssetIDIsNil())).
		All(ctx)
	if err != nil {
		return false, err
	}
	for _, e := range existing {
		if covered(e, d.conds, now, s.Cooldown) {
			return false, nil
		}
	}
	ev := evidence(d, s.Window)
	p, err := s.DB.Suppression.Create().
		SetRuleID(d.key.rule).SetAssetID(d.key.asset).SetStatus("proposed").SetCreatedBy(CreatedBy).
		SetReason(reason(d, ev, s.Days)).SetConditions(d.conds).SetEvidence(ev).
		SetExpiresAt(now.AddDate(0, 0, s.Days)).SetCreatedAt(now).Save(ctx)
	if err != nil {
		return false, err
	}
	audit.System(ctx, s.DB, "suppression_proposed", p.ID.String(),
		fmt.Sprintf("误报统计 %s 主机 %s：%d 次人工误报，误报率 %d%%", d.key.rule, d.key.asset, ev.FalsePositives, ev.RatioPercent))
	if s.Proposed != nil {
		s.Proposed(p.ID)
	}
	return true, nil
}

// covered 已有的抑制是否让这条草案多余：
// 生效且范围不比草案窄（条件是草案的子集）的已经压住了；待批的与草案互相包含就是同一件事；
// 冷却期内被拒的，范围不比它窄的草案不再提——拒了窄的，宽的更不该提，更窄的可以再问
func covered(e *ent.Suppression, conds []suppress.Condition, now time.Time, cooldown time.Duration) bool {
	switch e.Status {
	case "active":
		return (e.ExpiresAt == nil || e.ExpiresAt.After(now)) && subset(e.Conditions, conds)
	case "proposed":
		return subset(e.Conditions, conds) || subset(conds, e.Conditions)
	case "rejected":
		return e.ReviewedAt != nil && now.Sub(*e.ReviewedAt) < cooldown && subset(conds, e.Conditions)
	}
	return false
}

// subset a 的每条条件都在 b 里（字段、op 相同，值不区分大小写）
func subset(a, b []suppress.Condition) bool {
	for _, c := range a {
		if !slices.ContainsFunc(b, func(o suppress.Condition) bool {
			return o.Field == c.Field && o.Op == c.Op && strings.EqualFold(o.Value, c.Value)
		}) {
			return false
		}
	}
	return true
}

func evidence(d draft, window time.Duration) *schema.SuppressEvidence {
	scope := "entity"
	if len(d.conds) == 0 {
		scope = "rule"
	}
	fps := slices.Clone(d.t.fps)
	sort.Slice(fps, func(i, j int) bool { return resolvedAt(fps[i]).After(resolvedAt(fps[j])) })
	incidents := make([]schema.EvidenceIncident, 0, min(len(fps), maxEvidence))
	for _, inc := range fps[:min(len(fps), maxEvidence)] {
		e := schema.EvidenceIncident{ID: inc.ID, ResolvedBy: *inc.ResolvedBy, ResolvedAt: resolvedAt(inc)}
		if inc.Title != nil {
			e.Title = *inc.Title
		}
		if inc.ResolutionSource != nil {
			e.Source = *inc.ResolutionSource
		}
		incidents = append(incidents, e)
	}
	return &schema.SuppressEvidence{
		Scope: scope, WindowDays: int(window / (24 * time.Hour)),
		FalsePositives: d.t.counts[fp], TruePositives: d.t.counts[tp], Pending: d.t.counts[pending],
		RatioPercent: d.t.ratio(), AIProposals: d.t.counts[aiProposal], AutoClosed: d.t.counts[autoClosed],
		Incidents: incidents,
	}
}

func resolvedAt(inc *ent.Incident) time.Time {
	if inc.ResolvedAt != nil {
		return *inc.ResolvedAt
	}
	return time.Time{}
}

func reason(d draft, ev *schema.SuppressEvidence, days int) string {
	var who []string
	for _, inc := range d.t.fps {
		if !slices.Contains(who, *inc.ResolvedBy) {
			who = append(who, *inc.ResolvedBy)
		}
	}
	scope := "【整条规则】实体分散、没有哪个域名/地址/路径/进程单独够数，无法按实体收窄。这台主机上的这条规则"
	if len(d.conds) > 0 {
		parts := make([]string, len(d.conds))
		for i, c := range d.conds {
			op := " = "
			if c.Op != "" && c.Op != "equals" {
				op = " " + c.Op + " "
			}
			parts[i] = c.Field + op + c.Value
		}
		scope = "这台主机上 " + strings.Join(parts, " 且 ") + " 的命中"
	}
	r := fmt.Sprintf("误报统计：%s近 %d 天有 %d 个事件被人判为误报（%s），误报率 %d%%（未结案 %d 个），期间没有判属实",
		scope, ev.WindowDays, ev.FalsePositives, strings.Join(who, "、"), ev.RatioPercent, ev.Pending)
	if ev.AIProposals+ev.AutoClosed > 0 {
		r += fmt.Sprintf("；另有采纳 AI 结案建议 %d 个、系统自动结案 %d 个未计入", ev.AIProposals, ev.AutoClosed)
	}
	return r + fmt.Sprintf("。建议有效期 %d 天，到期自动失效。", days)
}
