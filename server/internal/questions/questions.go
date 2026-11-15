// Package questions 自治总控的提问协议（P2）：子 Agent 与结案审计遇到归属、授权、策略、权限类问题时不再直接标「需人工」，
// 而是提问总控。总控先在事实库、意图与平台记录里做确定性查找，答得出就返回结论与引用；答不了的按（类型、主题对象）
// 合并成一条待答问题，管理员在控制台作答一次，答案写回事实库或常设规矩，关联的待办与事件按新事实重新评估。
//
// 总控不调用模型给事实结论：自由文本到结构化主题的映射由提问方在工具调用里完成，合并靠规范化后的主题键。
package questions

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/command"
	"openxdr/server/ent/fact"
	"openxdr/server/ent/intent"
	"openxdr/server/ent/predicate"
	"openxdr/server/ent/question"
	"openxdr/server/ent/schema"
	"openxdr/server/ent/standingrule"
	"openxdr/server/internal/assetretire"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/facts"
)

// Kinds 问题类型
var Kinds = []string{"owner", "authorization", "policy", "permission"}

// SubjectKinds 主题对象类型
var SubjectKinds = []string{"key", "ip", "asset", "domain", "change", "rule", "fact"}

// KindNames 给人看的类型名
var KindNames = map[string]string{"owner": "归属", "authorization": "授权", "policy": "策略", "permission": "权限"}

// SubjectNames 给人看的主题对象名
var SubjectNames = map[string]string{"key": "钥匙", "ip": "地址", "asset": "主机", "domain": "域名", "change": "变更", "rule": "常设规矩", "fact": "到期事实"}

const (
	maxEvidence = 20
	maxRefs     = 200
	maxNote     = 500
	// RenewBefore 授权类事实到期前多久提问是否续期
	RenewBefore = 3 * 24 * time.Hour
	// changeWindow 变更类问题按时间核对平台指令时的容差
	changeWindow = time.Minute
)

// Ref 问题编号
func Ref(id uuid.UUID) string { return facts.Ref("Q", id) }

// Request 一次提问。Groups、Assets 与证据引用由服务端按提问方的会话或材料确定，不接受模型自报
type Request struct {
	Kind        string
	SubjectKind string
	Subject     string
	// At 变更类问题的发生时刻：有它才按时间核对平台指令
	At        *time.Time
	Groups    []uuid.UUID
	Assets    []uuid.UUID
	Incident  *uuid.UUID
	Finding   *uuid.UUID
	Session   *uuid.UUID
	Source    string
	Ref       string
	Note      string
	CreatedBy string
}

// Record 平台自己的记录（指令、意图），作为引用返回
type Record struct {
	Ref    string `json:"ref"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// Result 提问结果：Answered 时 Facts/Records 是结论依据；否则 Question 是合并后的待答问题
type Result struct {
	Answered bool
	Facts    []*ent.Fact
	Records  []Record
	// Context 只作参考、不构成结论的记录（如意图只解释不授权）
	Context  []Record
	Question *ent.Question
	Merged   bool
}

// ErrInvalid 提问参数不合法
type ErrInvalid struct{ error }

var (
	domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	fpRE     = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{20,64}=*$`)
)

// Normalize 校验类型组合并规范化主题：域名小写去尾点、保留完整主机名，地址去掉多余写法
func Normalize(kind, subjectKind, subject string) (string, error) {
	subject = strings.TrimSpace(subject)
	switch {
	case !slices.Contains(Kinds, kind):
		return "", errors.New("type 只能是 " + strings.Join(Kinds, " / "))
	case !slices.Contains(SubjectKinds, subjectKind):
		return "", errors.New("subject.kind 只能是 " + strings.Join(SubjectKinds, " / "))
	case subjectKind == "rule" && kind != "policy":
		return "", errors.New("常设规矩只能问策略")
	case subjectKind == "fact" && kind != "authorization":
		return "", errors.New("到期事实只能问授权续期")
	}
	switch subjectKind {
	case "key":
		if !fpRE.MatchString(subject) {
			return "", errors.New("钥匙须为 SHA256: 开头的公钥指纹")
		}
		return subject, nil
	case "ip":
		p, err := facts.Prefix(subject)
		if err != nil {
			return "", errors.New("地址须为 IP 或 CIDR")
		}
		if p.IsSingleIP() {
			return p.Addr().Unmap().String(), nil
		}
		return p.String(), nil
	case "domain":
		d := strings.TrimSuffix(strings.ToLower(subject), ".")
		if len(d) > 253 || !domainRE.MatchString(d) {
			return "", errors.New("域名格式不对")
		}
		// 用完整主机名，不归到注册域：同一云厂商域下是互不相干的租户，归并会把授权悄悄扩大
		return d, nil
	case "change":
		return normalizeChange(subject)
	default: // asset rule fact
		id, err := uuid.Parse(subject)
		if err != nil {
			return "", errors.New(SubjectNames[subjectKind] + "须为 UUID")
		}
		return id.String(), nil
	}
}

// FactSubject 作答写回的决定或变更事实的主题：<类型>:<对象类型>:<对象>，总控按它确定性地查回来
func FactSubject(kind, subjectKind, subject string) string {
	return kind + ":" + subjectKind + ":" + subject
}

// Ask 提问：先确定性查找，答得出直接返回；答不了合并进同主题的待答问题。整个合并在一个事务里，
// 并发提问撞上唯一索引时重试一次改为合并
func Ask(ctx context.Context, db *ent.Client, req Request, now time.Time) (*Result, error) {
	subject, err := Normalize(req.Kind, req.SubjectKind, req.Subject)
	if err != nil {
		return nil, ErrInvalid{err}
	}
	req.Subject = subject
	if utf8.RuneCountInString(req.Note) > maxNote {
		req.Note = string([]rune(req.Note)[:maxNote])
	}
	res, err := Lookup(ctx, db, req, now)
	if err != nil {
		return nil, err
	}
	if res.Answered {
		var refs []string
		for _, f := range res.Facts {
			refs = append(refs, facts.Ref("F", f.ID))
		}
		for _, r := range res.Records {
			refs = append(refs, r.Ref)
		}
		if err := facts.Cite(ctx, db, &facts.Brief{Facts: res.Facts}, now); err != nil {
			return nil, err
		}
		audit.System(ctx, db, "controller_answered", req.Kind+" "+req.SubjectKind+" "+req.Subject, "source="+req.Source+" refs="+strings.Join(refs, ","))
		return res, nil
	}
	for attempt := 0; ; attempt++ {
		q, merged, err := upsert(ctx, db, req, res.Context, now)
		if err != nil && ent.IsConstraintError(err) && attempt == 0 {
			continue
		}
		if err != nil {
			return nil, err
		}
		res.Question, res.Merged = q, merged
		return res, nil
	}
}

func upsert(ctx context.Context, db *ent.Client, req Request, ctxRecords []Record, now time.Time) (*ent.Question, bool, error) {
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	ev := schema.QuestionEvidence{At: now, Source: req.Source, Incident: req.Incident, Finding: req.Finding, Session: req.Session, Ref: req.Ref, Note: req.Note}
	pinned := contextEvidences(ctxRecords, now)
	cur, err := tx.Question.Query().Where(question.StatusEQ("open"), question.KindEQ(req.Kind), question.SubjectKindEQ(req.SubjectKind), question.SubjectEQ(req.Subject)).
		Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, false, err
	}
	var q *ent.Question
	if cur == nil {
		evidence, _ := mergeEvidence(nil, pinned, &ev)
		c := tx.Question.Create().SetKind(req.Kind).SetSubjectKind(req.SubjectKind).SetSubject(req.Subject).
			SetGroupIds(addIDs(nil, req.Groups...)).SetIncidentIds(addIDs(nil, ptrs(req.Incident)...)).
			SetFindingIds(addIDs(nil, ptrs(req.Finding)...)).SetEvidence(evidence).SetCreatedBy(req.CreatedBy).
			SetCreatedAt(now).SetUpdatedAt(now)
		if q, err = c.Save(ctx); err != nil {
			return nil, false, err
		}
		if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "question_created", q.ID.String(),
			fmt.Sprintf("%s %s %s %s 来源=%s", Ref(q.ID), req.Kind, req.SubjectKind, req.Subject, req.Source)); err != nil {
			return nil, false, err
		}
	} else {
		evidence, _ := mergeEvidence(cur.Evidence, pinned, &ev)
		if q, err = tx.Question.UpdateOne(cur).SetGroupIds(addIDs(cur.GroupIds, req.Groups...)).
			SetIncidentIds(addIDs(cur.IncidentIds, ptrs(req.Incident)...)).SetFindingIds(addIDs(cur.FindingIds, ptrs(req.Finding)...)).
			SetEvidence(evidence).AddAskedCount(1).SetUpdatedAt(now).Save(ctx); err != nil {
			return nil, false, err
		}
	}
	return q, cur != nil, tx.Commit()
}

func isPinnedSource(source string) bool {
	return source == "fact" || source == "platform" || source == "asset"
}

func contextEvidences(records []Record, now time.Time) []schema.QuestionEvidence {
	var out []schema.QuestionEvidence
	for _, r := range records {
		var src string
		switch r.Kind {
		case "key_owner":
			src = "fact"
		case "platform_component":
			src = "platform"
		case "asset_parked":
			src = "asset"
		default:
			continue
		}
		out = append(out, schema.QuestionEvidence{At: now, Source: src, Ref: r.Ref, Note: r.Detail})
	}
	return out
}

// mergeEvidence 合并并固定事实/平台背景证据（按 Source+Ref 去重且不被 20 条滑窗挤掉），返回合并结果及是否新增了固定证据
func mergeEvidence(cur, pinned []schema.QuestionEvidence, tail *schema.QuestionEvidence) ([]schema.QuestionEvidence, bool) {
	var fixed, regular []schema.QuestionEvidence
	for _, e := range cur {
		if isPinnedSource(e.Source) && e.Ref != "" {
			fixed = append(fixed, e)
		} else {
			regular = append(regular, e)
		}
	}
	addedPinned := false
	for _, p := range pinned {
		idx := slices.IndexFunc(fixed, func(x schema.QuestionEvidence) bool {
			return x.Source == p.Source && x.Ref == p.Ref
		})
		if idx < 0 {
			fixed = append(fixed, p)
			addedPinned = true
		} else if fixed[idx].Note != p.Note {
			fixed[idx].Note = p.Note
			addedPinned = true
		}
	}
	if tail != nil {
		regular = append(regular, *tail)
	}
	if len(fixed) > maxEvidence {
		fixed = fixed[:maxEvidence]
	}
	budget := maxEvidence - len(fixed)
	if len(regular) > budget {
		regular = regular[len(regular)-budget:]
	}
	return append(fixed, regular...), addedPinned
}

func ptrs(ids ...*uuid.UUID) []uuid.UUID {
	var out []uuid.UUID
	for _, id := range ids {
		if id != nil {
			out = append(out, *id)
		}
	}
	return out
}

// addIDs 去重追加，超过上限只保留最早的（影响计数已经足够说明问题）
func addIDs(cur []uuid.UUID, add ...uuid.UUID) []uuid.UUID {
	out := slices.Clone(cur)
	if out == nil {
		out = []uuid.UUID{}
	}
	for _, id := range add {
		if id != uuid.Nil && !slices.Contains(out, id) && len(out) < maxRefs {
			out = append(out, id)
		}
	}
	return out
}

func formatKeyFact(f *ent.Fact) string {
	content := strings.TrimSpace(f.Content)
	holder := strings.TrimSpace(f.Holder)
	if holder != "" && !strings.Contains(content, holder) {
		return "已登记钥匙归属（持有人：" + holder + "）：" + content
	}
	return "已登记钥匙归属：" + content
}

// Lookup 确定性查找：事实库（按组裁剪，全局事实对所有组可见）、退役/停机保留资产状态、平台自身组件、平台指令与运维意图。
// 授权类只认授权事实与平台自己下发的指令；钥匙归属事实在非归属类问题上只进 Context 并附进问题证据，不单独充当授权；意图只作参考
func Lookup(ctx context.Context, db *ent.Client, req Request, now time.Time) (*Result, error) {
	res := &Result{}
	where := []predicate.Fact{facts.Live(now)}
	if len(req.Groups) > 0 {
		where = append(where, fact.Or(fact.GroupIDIsNil(), fact.GroupIDIn(req.Groups...)))
	}
	own := FactSubject(req.Kind, req.SubjectKind, req.Subject)
	var match []predicate.Fact
	switch req.SubjectKind {
	case "key":
		// 无论问归属还是问授权，都一并取出有效的 key 事实：归属问题直接作答，非归属问题附进 Context 与问题证据
		match = append(match, fact.And(fact.KindEQ("key"), fact.SubjectEQ(req.Subject)))
		match = append(match, fact.SubjectEQ(own))
	case "ip":
		if req.Kind == "owner" {
			match = append(match, fact.KindEQ("channel"))
		}
		match = append(match, fact.SubjectEQ(own))
	case "domain":
		match = append(match, fact.SubjectEQ(own))
		if tree := treeSubjects(req.Kind, req.Subject); len(tree) > 0 {
			match = append(match, fact.SubjectIn(tree...))
		}
	case "asset", "change":
		id, _ := SubjectAsset(req.SubjectKind, req.Subject)
		host, err := db.Asset.Get(ctx, id)
		if err != nil && !ent.IsNotFound(err) {
			return nil, err
		}
		if host != nil && (len(req.Groups) == 0 || (host.GroupID != nil && slices.Contains(req.Groups, *host.GroupID))) {
			switch {
			case host.RetiredAt != nil:
				res.Records = append(res.Records, Record{
					Ref:    facts.Ref("A", host.ID),
					Kind:   "asset_retired",
					Detail: "资产已退役：" + assetretire.FormatResolution([]*ent.Asset{host}),
				})
			case host.ParkedAt != nil:
				rec := Record{
					Ref:    facts.Ref("A", host.ID),
					Kind:   "asset_parked",
					Detail: assetretire.FormatParked(host),
				}
				if req.SubjectKind == "asset" && (req.Kind == "owner" || req.Kind == "policy") {
					res.Records = append(res.Records, rec)
				} else {
					res.Context = append(res.Context, rec)
				}
			}
		}
		if req.SubjectKind == "change" {
			// 变更授权只认同一变更标识写回的事实：批准一项变更不等于批准这台资产上的所有变更。
			// 存量裸 UUID 主题没有标识，任何事实都不代答；资产角色只作上下文
			if changeKey(req.Subject) != "" {
				match = append(match, fact.SubjectEQ(own))
			}
			roles, err := db.Fact.Query().Where(append(where, fact.AssetIDEQ(id), fact.KindEQ("asset_role"))...).Limit(10).All(ctx)
			if err != nil {
				return nil, err
			}
			for _, f := range roles {
				res.Context = append(res.Context, Record{Ref: facts.Ref("F", f.ID), Kind: "asset_role", Detail: "资产角色（只作背景，不代表批准这项变更）：" + f.Content})
			}
			break
		}
		switch req.Kind {
		case "owner":
			match = append(match, fact.And(fact.AssetIDEQ(id), fact.KindEQ("asset_role")))
		case "authorization":
			// 管理员在事实页直接录入的「已授权变更」也算主机级授权；问题作答写回的（带 类型: 前缀，含具体变更的授权）不算
			match = append(match, fact.And(fact.AssetIDEQ(id), fact.KindEQ("change"), fact.Not(fact.SubjectHasPrefix("authorization:")),
				fact.Not(fact.SubjectHasPrefix("permission:")), fact.Not(fact.SubjectHasPrefix("policy:")), fact.Not(fact.SubjectHasPrefix("owner:"))))
		}
		// 只认同类型、同主机的主机级作答，不再按前缀把这台主机上具体变更的作答也算进来
		match = append(match, fact.And(fact.AssetIDEQ(id), fact.SubjectEQ(own)))
	case "rule":
		match = append(match, fact.SubjectEQ(own))
		rule, err := db.StandingRule.Get(ctx, uuid.MustParse(req.Subject))
		if err != nil && !ent.IsNotFound(err) {
			return nil, err
		}
		if rule != nil && rule.Tier != standingrule.TierHuman {
			res.Records = append(res.Records, Record{Ref: facts.Ref("R", rule.ID), Kind: "standing_rule", Detail: "常设规矩已定为 " + string(rule.Tier) + " 档"})
		}
	case "fact":
		// 续期问题：事实已续过（不在提醒窗口内）就不用再问
		f, err := db.Fact.Get(ctx, uuid.MustParse(req.Subject))
		if err != nil && !ent.IsNotFound(err) {
			return nil, err
		}
		if f == nil || f.RetiredAt != nil || f.ExpiresAt == nil || f.ExpiresAt.After(now.Add(RenewBefore)) {
			res.Answered = true
		}
		return res, nil
	}
	var rows []*ent.Fact
	if len(match) > 0 {
		var err error
		if rows, err = db.Fact.Query().Where(append(where, fact.Or(match...))...).Order(ent.Asc(fact.FieldCreatedAt)).Limit(50).All(ctx); err != nil {
			return nil, err
		}
	}
	for _, f := range rows {
		if f.Kind == "channel" && !facts.Covers(f.Subject, req.Subject) {
			continue
		}
		if req.SubjectKind == "key" && f.Kind == "key" && req.Kind != "owner" {
			res.Context = append(res.Context, Record{
				Ref:    facts.Ref("F", f.ID),
				Kind:   "key_owner",
				Detail: formatKeyFact(f),
			})
			continue
		}
		res.Facts = append(res.Facts, f)
	}
	if err := lookupPlatform(ctx, db, req, res); err != nil {
		return nil, err
	}
	if req.SubjectKind == "change" {
		if err := changeRecords(ctx, db, req, res); err != nil {
			return nil, err
		}
	}
	res.Answered = len(res.Facts) > 0 || len(res.Records) > 0
	return res, nil
}

// changeRecords 变更类：发生时刻落在平台自己下发、成功执行的写指令窗口内，就是平台的变更；覆盖这台主机的运维意图只作参考
func changeRecords(ctx context.Context, db *ent.Client, req Request, res *Result) error {
	asset, _ := SubjectAsset(req.SubjectKind, req.Subject)
	if req.At != nil {
		at := *req.At
		cmds, err := db.Command.Query().Where(command.AssetIDEQ(asset), command.KindEQ("exec"), command.StatusEQ("succeeded"),
			command.CreatedAtLTE(at.Add(changeWindow)), command.CreatedAtGTE(at.Add(-24*time.Hour)), command.CompletedAtGTE(at.Add(-changeWindow))).
			Order(ent.Desc(command.FieldCreatedAt)).Limit(20).All(ctx)
		if err != nil {
			return err
		}
		for _, c := range cmds {
			if c.Cmd == nil || commandgate.ReadOnly(*c.Cmd) {
				continue
			}
			res.Records = append(res.Records, Record{Ref: facts.Ref("C", c.ID), Kind: "command", Detail: "平台指令，发起人 " + c.IssuedBy + "，下发于 " + c.CreatedAt.Format(time.RFC3339)})
		}
	}
	ins, err := db.Intent.Query().Where(intent.EndedAtIsNil(), intent.ExpiresAtGT(time.Now().Add(-24*time.Hour))).Order(ent.Desc(intent.FieldCreatedAt)).Limit(200).All(ctx)
	if err != nil {
		return err
	}
	for _, in := range ins {
		if !slices.Contains(in.AssetIds, asset) || (req.At != nil && (req.At.Before(in.StartsAt) || req.At.After(in.ExpiresAt))) {
			continue
		}
		late := ""
		if in.Late {
			late = "（事后补登）"
		}
		res.Context = append(res.Context, Record{Ref: facts.Ref("I", in.ID), Kind: "intent", Detail: "运维意图" + late + "：登记人 " + in.CreatedBy + "，用途「" + facts.CategoryNames[in.Category] + "」，至 " + in.ExpiresAt.Format(time.RFC3339)})
	}
	return nil
}

// OpenFor 这条待办关联的待答问题编号；没有返回空
func OpenFor(ctx context.Context, db *ent.Client, finding uuid.UUID) (string, error) {
	q, err := db.Question.Query().Where(question.StatusEQ("open"), containsID(question.FieldFindingIds, finding)).
		Order(ent.Desc(question.FieldUpdatedAt)).First(ctx)
	if ent.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return Ref(q.ID), nil
}

// FactsForIncident 已答问题为这个事件写回、仍有效的事实：结案审计把它们放进权威事实一节，
// 审计员看得到新事实，快照指纹随之变化，被拒过的事件按新事实重审
func FactsForIncident(ctx context.Context, db *ent.Client, incident uuid.UUID, now time.Time) ([]*ent.Fact, error) {
	rows, err := db.Question.Query().Where(question.StatusEQ("answered"), question.FactIDNotNil(), containsID(question.FieldIncidentIds, incident)).
		Select(question.FieldFactID).Limit(50).All(ctx)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	factIDs := make([]uuid.UUID, 0, len(rows))
	for _, q := range rows {
		factIDs = append(factIDs, *q.FactID)
	}
	return db.Fact.Query().Where(fact.IDIn(factIDs...), facts.Live(now)).Order(ent.Asc(fact.FieldCreatedAt)).All(ctx)
}

// containsID jsonb 数组含某个 UUID
func containsID(col string, id uuid.UUID) predicate.Question {
	return func(s *sql.Selector) {
		s.Where(sql.P(func(b *sql.Builder) {
			b.Ident(s.C(col)).WriteString(" @> ").Arg(`["` + id.String() + `"]`).WriteString("::jsonb")
		}))
	}
}
