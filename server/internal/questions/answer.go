package questions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/question"
	"openxdr/server/ent/schema"
	"openxdr/server/ent/standingrule"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/findings"
)

const (
	// DefaultGrantDays 授权类事实默认有效期
	DefaultGrantDays = 30
	// MaxGrantDays 授权类事实最长有效期：授权不给长期的，到期前再问一次
	MaxGrantDays = 365
	maxContent   = 1000
)

// AnswerInput 管理员作答。按问题类型取用：
//
//	owner：Choice=claim（Holder + Content 用途）或 unknown（Content 可选说明）
//	authorization / permission：Choice=grant 或 deny，Content 范围，ExpiresInDays 1–365（续期问题 grant 即续期）
//	policy：Choice=rule（RuleID + Tier）或 decision（Content）
//
// 域名问题另有 Scope：空为仅此主机名（默认）；或 DomainScopes 给出的某一级父域，表示该父域及其全部子域
type AnswerInput struct {
	Scope         string     `json:"scope"`
	Choice        string     `json:"choice"`
	Holder        string     `json:"holder"`
	Content       string     `json:"content"`
	RuleID        *uuid.UUID `json:"ruleId"`
	Tier          string     `json:"tier"`
	ExpiresInDays int        `json:"expiresInDays"`
}

// ErrAnswered 问题已经答过（并发作答或重复提交）
var ErrAnswered = errors.New("问题已作答")

// Outcome 作答的结果：写回了什么，重新排队了多少待办
type Outcome struct {
	Fact     *ent.Fact
	Rule     *ent.StandingRule
	Findings int
}

// Answer 在调用方的事务里写回事实或常设规矩、标记问题已答、落审计，并把关联待办解除阻塞重新排队。
// 事件不在这里改：新事实进入结案审计的权威事实一节，快照指纹变化后审计员自然重审
func Answer(ctx context.Context, tx *ent.Tx, id uuid.UUID, in AnswerInput, actor, remote string, now time.Time) (*Outcome, error) {
	q, err := tx.Question.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if q.Status != "open" {
		return nil, ErrAnswered
	}
	in.Holder, in.Content = strings.TrimSpace(in.Holder), strings.TrimSpace(in.Content)
	if utf8.RuneCountInString(in.Content) > maxContent || utf8.RuneCountInString(in.Holder) > 200 {
		return nil, ErrInvalid{fmt.Errorf("内容最多 %d 字，持有人最多 200 字", maxContent)}
	}
	if in.Scope != "" && q.SubjectKind != "domain" {
		return nil, ErrInvalid{errors.New("只有域名问题能选范围")}
	}
	out := &Outcome{}
	record := &schema.QuestionAnswer{Choice: in.Choice, Holder: in.Holder, Content: in.Content}
	switch {
	case q.SubjectKind == "fact":
		err = renew(ctx, tx, q, in, record, actor, remote, now, out)
	case q.Kind == "owner":
		err = owner(ctx, tx, q, in, record, actor, out)
	case q.Kind == "authorization" || q.Kind == "permission":
		err = grant(ctx, tx, q, in, record, actor, now, out)
	case q.Kind == "policy":
		err = policy(ctx, tx, q, in, record, actor, remote, now, out)
	default:
		err = ErrInvalid{errors.New("未知问题类型")}
	}
	if err != nil {
		return nil, err
	}
	u := tx.Question.Update().Where(question.IDEQ(q.ID), question.StatusEQ("open")).SetStatus("answered").
		SetAnswer(record).SetAnsweredBy(actor).SetAnsweredAt(now)
	if out.Fact != nil {
		u.SetFactID(out.Fact.ID)
	}
	if out.Rule != nil {
		u.SetRuleID(out.Rule.ID)
	}
	n, err := u.Save(ctx)
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, ErrAnswered
	}
	q.Answer = record
	if out.Findings, err = requeue(ctx, tx, q, now); err != nil {
		return nil, err
	}
	target := "无写回"
	switch {
	case out.Fact != nil:
		target = facts.Ref("F", out.Fact.ID)
	case out.Rule != nil:
		target = facts.Ref("R", out.Rule.ID) + " tier=" + string(out.Rule.Tier)
	}
	detail := fmt.Sprintf("%s %s %s %s choice=%s 写回=%s 重新排队待办=%d 关联事件=%d", Ref(q.ID), q.Kind, q.SubjectKind, q.Subject, in.Choice, target, out.Findings, len(q.IncidentIds))
	return out, audit.Checked(ctx, tx.AuditLog.Create(), actor, remote, "question_answered", q.ID.String(), detail)
}

// subjectFor 写回事实的主题与范围说明。域名问题按选中的范围：仅此主机名写 <类型>:domain:<主机名>，
// 父域写 <类型>:domain-tree:<父域>；父域只能从 DomainScopes 里选，共享托管、外带、隧道类域一个都不给
func subjectFor(q *ent.Question, in AnswerInput, record *schema.QuestionAnswer) (subject, scope string, err error) {
	if q.SubjectKind != "domain" {
		if in.Scope != "" {
			return "", "", ErrInvalid{errors.New("只有域名问题能选范围")}
		}
		if q.SubjectKind == "change" {
			// 只批准这一项变更：主题带变更标识，内容写明
			return changeFactSubject(q), "仅这一项变更（" + changeLabel(q) + "）：", nil
		}
		return FactSubject(q.Kind, q.SubjectKind, q.Subject), "", nil
	}
	if in.Scope == "" || in.Scope == q.Subject {
		return FactSubject(q.Kind, "domain", q.Subject), "仅 " + q.Subject + "：", nil
	}
	if !slices.Contains(DomainScopes(q.Subject), in.Scope) {
		return "", "", ErrInvalid{errors.New("范围只能是这个主机名，或它到注册域为止的某一级父域；共享托管、外带、隧道类域只能按完整主机名")}
	}
	record.Scope = in.Scope
	return FactSubject(q.Kind, "domain-tree", in.Scope), in.Scope + " 及其全部子域：", nil
}

// scopeGroup 证据只涉及一个组就写到该组，否则写全局（只有平台管理员能作答，与录入全局事实同一权限）
func scopeGroup(q *ent.Question) *uuid.UUID {
	if len(q.GroupIds) == 1 {
		g := q.GroupIds[0]
		return &g
	}
	return nil
}

func expiry(days int, now time.Time) (time.Time, error) {
	if days == 0 {
		days = DefaultGrantDays
	}
	if days < 1 || days > MaxGrantDays {
		return time.Time{}, ErrInvalid{fmt.Errorf("授权有效期须为 1–%d 天", MaxGrantDays)}
	}
	return now.AddDate(0, 0, days), nil
}

// createFact 写一条人工事实；资产类事实的组跟资产走，与控制台录入一致
func createFact(ctx context.Context, tx *ent.Tx, q *ent.Question, kind, subject, holder, content, actor string, expires *time.Time) (*ent.Fact, error) {
	var assetID *uuid.UUID
	group := scopeGroup(q)
	if id, ok := SubjectAsset(q.SubjectKind, q.Subject); ok {
		a, err := tx.Asset.Get(ctx, id)
		if err != nil {
			return nil, ErrInvalid{errors.New("主机不存在")}
		}
		assetID, group = &id, a.GroupID
	}
	content = content + "（总控问题 " + Ref(q.ID) + "）"
	if err := facts.ValidateFact(kind, subject, assetID, content); err != nil {
		return nil, ErrInvalid{err}
	}
	f, err := tx.Fact.Create().SetKind(kind).SetSubject(subject).SetNillableGroupID(group).SetNillableAssetID(assetID).
		SetHolder(holder).SetContent(content).SetSource("human").SetCreatedBy(actor).SetNillableExpiresAt(expires).Save(ctx)
	if err != nil {
		return nil, err
	}
	return f, audit.Checked(ctx, tx.AuditLog.Create(), actor, "", "fact_created", f.ID.String(),
		fmt.Sprintf("%s %s 持有人=%s：%s", kind, subject, holder, content))
}

// owner 归属：钥匙 → key 事实，地址 → channel 事实，主机 → asset_role 事实，其余写决定或变更事实
func owner(ctx context.Context, tx *ent.Tx, q *ent.Question, in AnswerInput, record *schema.QuestionAnswer, actor string, out *Outcome) error {
	holder, content := in.Holder, in.Content
	switch in.Choice {
	case "claim":
		if holder == "" || content == "" {
			return ErrInvalid{errors.New("认领须填持有人与用途")}
		}
		content = "持有人 " + holder + "，用途：" + content
	case "unknown":
		holder = ""
		content = strings.TrimSpace("管理员不认识这个对象，未授权，按可疑对待。" + content)
	default:
		return ErrInvalid{errors.New("归属问题只能认领（claim）或不认识（unknown）")}
	}
	// 主机的「不认识」写决定事实而不是资产角色：资产角色与已授权变更会被当作高危告警的业务兜底
	subject, scope, err := subjectFor(q, in, record)
	if err != nil {
		return err
	}
	kind, content := "decision", scope+content
	switch {
	case q.SubjectKind == "key":
		kind, subject = "key", q.Subject
	case q.SubjectKind == "ip":
		kind, subject = "channel", q.Subject
	case q.SubjectKind == "asset" && in.Choice == "claim":
		kind = "asset_role"
	}
	out.Fact, err = createFact(ctx, tx, q, kind, subject, holder, content, actor, nil)
	return err
}

// grant 授权与权限：一律带到期时间，到期前 RenewBefore 自动再问一次
func grant(ctx context.Context, tx *ent.Tx, q *ent.Question, in AnswerInput, record *schema.QuestionAnswer, actor string, now time.Time, out *Outcome) error {
	if in.Content == "" {
		return ErrInvalid{errors.New("须写明授权范围")}
	}
	prefix := map[string]string{"grant": "授权：", "deny": "不授权："}[in.Choice]
	if prefix == "" {
		return ErrInvalid{errors.New("授权问题只能授权（grant）或不授权（deny）")}
	}
	if q.Kind == "permission" {
		prefix = map[string]string{"grant": "准许：", "deny": "不准许："}[in.Choice]
	}
	exp, err := expiry(in.ExpiresInDays, now)
	if err != nil {
		return err
	}
	subject, scope, err := subjectFor(q, in, record)
	if err != nil {
		return err
	}
	record.ExpiresAt = &exp
	// 只有授权写成主机的已授权变更；不授权写决定事实，免得被当成高危告警的业务兜底
	kind := "decision"
	if in.Choice == "grant" && (q.SubjectKind == "asset" || q.SubjectKind == "change") {
		kind = "change"
	}
	out.Fact, err = createFact(ctx, tx, q, kind, subject, "", prefix+scope+in.Content, actor, &exp)
	return err
}

// renew 授权到期续期：续期即延长原事实的到期时间；不续期则让它按时失效
func renew(ctx context.Context, tx *ent.Tx, q *ent.Question, in AnswerInput, record *schema.QuestionAnswer, actor, remote string, now time.Time, out *Outcome) error {
	f, err := tx.Fact.Get(ctx, uuid.MustParse(q.Subject))
	if err != nil {
		return ErrInvalid{errors.New("要续期的事实不存在")}
	}
	switch in.Choice {
	case "deny":
		return nil
	case "grant":
	default:
		return ErrInvalid{errors.New("续期问题只能续期（grant）或不续期（deny）")}
	}
	if f.RetiredAt != nil {
		return ErrInvalid{errors.New("事实已停用，不能续期")}
	}
	exp, err := expiry(in.ExpiresInDays, now)
	if err != nil {
		return err
	}
	if f.ExpiresAt != nil && f.ExpiresAt.After(now) {
		exp = f.ExpiresAt.Add(exp.Sub(now))
	}
	record.ExpiresAt = &exp
	if out.Fact, err = tx.Fact.UpdateOne(f).SetExpiresAt(exp).Save(ctx); err != nil {
		return err
	}
	return audit.Checked(ctx, tx.AuditLog.Create(), actor, remote, "fact_renewed", f.ID.String(),
		fmt.Sprintf("%s 续期至 %s（总控问题 %s）", facts.Ref("F", f.ID), exp.Format(time.RFC3339), Ref(q.ID)))
}

// policy 策略：改常设规矩档位（档位须在模板允许范围内，由调用方核对），或写一条决定事实
func policy(ctx context.Context, tx *ent.Tx, q *ent.Question, in AnswerInput, record *schema.QuestionAnswer, actor, remote string, now time.Time, out *Outcome) error {
	switch in.Choice {
	case "decision":
		if in.Content == "" {
			return ErrInvalid{errors.New("须写明决定内容")}
		}
		subject, scope, err := subjectFor(q, in, record)
		if err != nil {
			return err
		}
		out.Fact, err = createFact(ctx, tx, q, "decision", subject, "", scope+in.Content, actor, nil)
		return err
	case "rule":
	default:
		return ErrInvalid{errors.New("策略问题只能选规矩档位（rule）或写决定（decision）")}
	}
	if in.RuleID == nil || !slices.Contains([]string{"auto", "propose", "human"}, in.Tier) {
		return ErrInvalid{errors.New("须选规矩与档位")}
	}
	if q.SubjectKind == "rule" && in.RuleID.String() != q.Subject {
		return ErrInvalid{errors.New("规矩问题只能调整被问到的这条规矩")}
	}
	rule, err := tx.StandingRule.Get(ctx, *in.RuleID)
	if err != nil {
		return ErrInvalid{errors.New("常设规矩不存在")}
	}
	record.RuleID, record.Tier = in.RuleID, in.Tier
	old := rule.Tier
	u := tx.StandingRule.UpdateOne(rule).SetTier(standingrule.Tier(in.Tier))
	if string(old) != in.Tier {
		u.SetConsecutiveFailures(0).ClearDegradedAt().SetDegradedReason("")
	}
	if out.Rule, err = u.Save(ctx); err != nil {
		return err
	}
	return audit.Checked(ctx, tx.AuditLog.Create(), actor, remote, "standing_rule_tier_changed", rule.ID.String(),
		fmt.Sprintf("ref=%s tier=%s->%s（总控问题 %s）", facts.Ref("R", rule.ID), old, in.Tier, Ref(q.ID)))
}

// requeue 提过这个问题的关联待办解除阻塞、交回平台、立即重新排队，下一轮跟进按新事实重新评估。
// 以问题自己的 finding_ids 为准：待办只在转成 manual_business_decision 时才记 work.question，
// 以退役确认、外部依赖或观察状态提问的待办没有这个字段，同样在等这个答案
func requeue(ctx context.Context, tx *ent.Tx, q *ent.Question, now time.Time) (int, error) {
	if len(q.FindingIds) == 0 {
		return 0, nil
	}
	rows, err := tx.Finding.Query().Where(finding.IDIn(q.FindingIds...), finding.StatusEQ("open")).All(ctx)
	if err != nil {
		return 0, err
	}
	ref, n := Ref(q.ID), 0
	for _, f := range rows {
		var w findings.Work
		if err := json.Unmarshal(f.Work, &w); err != nil && len(f.Work) > 0 {
			continue
		}
		w.Blocker, w.BlockedReason, w.BlockerDetail, w.BlockedRounds = "", "", "", 0
		w.Stage, w.WakeOn, w.LastWakeReason = "waiting", "next_check", "总控问题 "+ref+" 已答"
		w.Plan = "总控问题 " + ref + " 已由管理员作答，按新事实重新评估"
		if q.Answer != nil && q.Answer.Content != "" {
			w.Plan = "总控问题 " + ref + " 已由管理员作答（" + q.Answer.Choice + "）：" + q.Answer.Content + "。按此重新评估，不重复提问"
		}
		w.Question = ""
		c, err := tx.Finding.Update().Where(finding.IDEQ(f.ID), finding.StatusEQ("open"), findings.Snapshot(f)).
			SetWorkOwner("ai").SetWorkNextCheckAt(now).SetWork(findings.EncodeWork(w)).Save(ctx)
		if err != nil {
			return 0, err
		}
		n += c
	}
	return n, nil
}
