package questions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/question"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/facts"
	"openxdr/server/internal/findings"
)

// 变更问题的主题是「资产 UUID/变更标识」：管理员批准的是一项具体变更，不是这台资产上的所有变更。
// 写回的事实主题带同一个变更标识，确定性查找只在变更标识完全相同时才作答；同一资产上的其他变更照常进人工队列。
// 存量问题的主题是裸资产 UUID，没有变更标识，查找时不用任何事实作答，作答写回时按问题编号补一个标识。
var changeKeyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,79}$`)

// ChangeSubject 拼变更主题
func ChangeSubject(asset uuid.UUID, key string) string { return asset.String() + "/" + key }

// SubjectAsset 主机或变更主题里的资产 ID；变更主题去掉变更标识，存量裸 UUID 也认
func SubjectAsset(subjectKind, subject string) (uuid.UUID, bool) {
	if subjectKind != "asset" && subjectKind != "change" {
		return uuid.Nil, false
	}
	raw, _, _ := strings.Cut(subject, "/")
	id, err := uuid.Parse(raw)
	return id, err == nil
}

// changeKey 变更主题里的变更标识；存量裸 UUID 返回空
func changeKey(subject string) string {
	_, key, _ := strings.Cut(subject, "/")
	return key
}

func normalizeChange(subject string) (string, error) {
	raw, key, ok := strings.Cut(subject, "/")
	id, err := uuid.Parse(raw)
	if err != nil {
		return "", errors.New("变更须为「主机 UUID/变更标识」")
	}
	key = strings.ToLower(strings.TrimSpace(key))
	if !ok || !changeKeyRE.MatchString(key) {
		return "", errors.New("变更须带变更标识（小写字母、数字与 . _ -，不超过 80 位），同一项变更每次用同一个标识")
	}
	return ChangeSubject(id, key), nil
}

// changeFactSubject 作答写回的变更事实主题：带变更标识；存量问题没有标识，按问题编号补一个，只回答这一个问题
func changeFactSubject(q *ent.Question) string {
	subject := q.Subject
	if changeKey(subject) == "" {
		subject += "/" + legacyKey(q.ID)
	}
	return FactSubject(q.Kind, "change", subject)
}

// changeLabel 变更标识，给人看；存量问题显示补的标识
func changeLabel(q *ent.Question) string {
	if k := changeKey(q.Subject); k != "" {
		return k
	}
	return legacyKey(q.ID)
}

func legacyKey(id uuid.UUID) string { return "legacy-" + strings.ToLower(Ref(id)) }

// ReopenCrossChangeAnswers 启动时扫一遍：变更类问题此前被 auto_lookup 拿别的问题（或手工录入的同资产变更事实）写回的事实自动答成已授权的，
// 置回待答、补上只属于自己的变更标识、关联待办重新挂回阻塞，留审计让人重新确认。顺带给存量裸 UUID 的待答变更问题补标识，
// 免得它们彼此合并或撞唯一索引。幂等：处理过的不再是 auto_lookup，也不再是裸 UUID
func ReopenCrossChangeAnswers(ctx context.Context, db *ent.Client, now time.Time) (reopened int, err error) {
	rows, err := db.Question.Query().Where(question.SubjectKindEQ("change"), question.StatusIn("open", "answered")).Limit(1000).All(ctx)
	if err != nil {
		return 0, err
	}
	for _, q := range rows {
		cross := q.Status == "answered" && q.Answer != nil && q.Answer.Choice == "auto_lookup" && q.FactID != nil
		if cross {
			f, err := db.Fact.Get(ctx, *q.FactID)
			if err != nil && !ent.IsNotFound(err) {
				return reopened, err
			}
			// 自己作答写回的事实内容里带自己的问题编号；带的是别人的、或手工录入没有编号的，都是跨问题复用
			cross = f == nil || !strings.Contains(f.Content, "总控问题 "+Ref(q.ID))
		}
		bare := changeKey(q.Subject) == ""
		if !cross && !(bare && q.Status == "open") {
			continue
		}
		ok, err := reopenChange(ctx, db, q.ID, cross, now)
		if err != nil {
			return reopened, err
		}
		if ok && cross {
			reopened++
		}
	}
	return reopened, nil
}

func reopenChange(ctx context.Context, db *ent.Client, id uuid.UUID, cross bool, now time.Time) (bool, error) {
	tx, err := db.Tx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	q, err := tx.Question.Query().Where(question.IDEQ(id)).Where(func(s *sql.Selector) { s.ForUpdate() }).Only(ctx)
	if err != nil {
		return false, err
	}
	subject := q.Subject
	if changeKey(subject) == "" {
		subject += "/" + legacyKey(q.ID)
	}
	u := tx.Question.UpdateOneID(q.ID).SetSubject(subject).SetUpdatedAt(now)
	if cross {
		u.SetStatus("open").ClearAnswer().ClearAnsweredBy().ClearAnsweredAt().ClearFactID()
	}
	if err := u.Exec(ctx); err != nil {
		return false, err
	}
	if !cross {
		return true, tx.Commit()
	}
	prior := ""
	if q.FactID != nil {
		prior = facts.Ref("F", *q.FactID)
	}
	blocked, err := reblock(ctx, tx, q, now)
	if err != nil {
		return false, err
	}
	detail := fmt.Sprintf("%s %s change %s→%s 此前由 auto_lookup 引用其他变更的事实 %s 自动作答，变更授权不能按资产复用，已置回待答请人重新确认；重新挂回阻塞的待办=%d",
		Ref(q.ID), q.Kind, q.Subject, subject, prior, blocked)
	if err := audit.Checked(ctx, tx.AuditLog.Create(), "system", "server", "question_reopened", q.ID.String(), detail); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// reblock 自动作答时被解除阻塞、之后没有新阻塞的关联待办，重新挂回这个问题
func reblock(ctx context.Context, tx *ent.Tx, q *ent.Question, now time.Time) (int, error) {
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
		if w.Blocker != "" || w.Question != "" || w.LastWakeReason != "总控问题 "+ref+" 已答" {
			continue
		}
		w.Blocker, w.BlockedReason, w.Question, w.Stage = "manual_business_decision", "manual_business_decision", ref, "blocked"
		w.BlockerDetail = "总控问题 " + ref + " 此前被错误自动作答，已置回待答，等管理员确认这项具体变更"
		c, err := tx.Finding.Update().Where(finding.IDEQ(f.ID), finding.StatusEQ("open"), findings.Snapshot(f)).
			SetWork(findings.EncodeWork(w)).SetWorkNextCheckAt(now.Add(24 * time.Hour)).Save(ctx)
		if err != nil {
			return 0, err
		}
		n += c
	}
	return n, nil
}
