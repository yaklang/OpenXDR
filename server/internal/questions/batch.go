package questions

import (
	"context"
	"slices"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/question"
)

// BatchKeys 同一次结案审计拒绝里一并提出的同类问题共用的键：一段探测脚本连了十几个地址，审计员按地址各提一问，
// 理由一字不差，管理员不该答十几遍。只认地址、域名与钥匙这类对象；资产、变更、规矩问题各有各的含义，不成批
func BatchKeys(q *ent.Question) []string {
	if !slices.Contains([]string{"ip", "domain", "key"}, q.SubjectKind) {
		return nil
	}
	var keys []string
	for _, e := range q.Evidence {
		if e.Source == "closure_review" && e.Incident != nil && e.Ref != "" {
			keys = append(keys, q.Kind+"|"+q.SubjectKind+"|"+e.Incident.String()+"|"+e.Ref)
		}
	}
	return keys
}

// Siblings 与 q 同批、仍待答的其他问题
func Siblings(ctx context.Context, c *ent.QuestionClient, q *ent.Question) ([]*ent.Question, error) {
	keys := BatchKeys(q)
	if len(keys) == 0 {
		return nil, nil
	}
	rows, err := c.Query().Where(question.StatusEQ("open"), question.KindEQ(q.Kind), question.SubjectKindEQ(q.SubjectKind), question.IDNEQ(q.ID)).
		Order(ent.Asc(question.FieldCreatedAt)).Limit(200).All(ctx)
	if err != nil {
		return nil, err
	}
	var out []*ent.Question
	for _, s := range rows {
		if slices.ContainsFunc(BatchKeys(s), func(k string) bool { return slices.Contains(keys, k) }) {
			out = append(out, s)
		}
	}
	return out, nil
}

// AnswerBatch 作答 id，并在 in.Siblings 时把同一答复用到同批问题上：每个问题各自写事实、各自落审计。
// 选了父域范围的域名答复只对被问到的那个域名有意义，不外推到同批
func AnswerBatch(ctx context.Context, tx *ent.Tx, q *ent.Question, in AnswerInput, actor, remote string, now time.Time) (*Outcome, int, error) {
	var siblings []*ent.Question
	if in.Siblings && in.Scope == "" {
		var err error
		if siblings, err = Siblings(ctx, tx.Question, q); err != nil {
			return nil, 0, err
		}
	}
	in.Siblings = false
	out, err := Answer(ctx, tx, q.ID, in, actor, remote, now)
	if err != nil {
		return nil, 0, err
	}
	for _, s := range siblings {
		more, err := Answer(ctx, tx, s.ID, in, actor, remote, now)
		if err != nil {
			return nil, 0, err
		}
		out.Findings += more.Findings
	}
	return out, len(siblings), nil
}
