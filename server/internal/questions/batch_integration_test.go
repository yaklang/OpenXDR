//go:build integration

package questions

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent/fact"
	"openxdr/server/ent/question"
	"openxdr/server/internal/testdb"
)

// 同一次结案审计拒绝按地址各提一问：答一个可一并答掉同批，各写各的事实；别的事件提的同类问题不受影响
func TestAnswerBatchCoversSameReviewOnly(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("g").SaveX(ctx)
	now := time.Now()
	inc, other := uuid.New(), uuid.New()
	ask := func(ip string, incident uuid.UUID) uuid.UUID {
		res, err := Ask(ctx, db, Request{Kind: "authorization", SubjectKind: "ip", Subject: ip, Groups: []uuid.UUID{g.ID}, Incident: &incident,
			Source: "closure_review", Ref: "snapshot=abc", Note: "探测脚本连了这些地址", CreatedBy: "system"}, now)
		if err != nil || res.Question == nil {
			t.Fatal(err, res)
		}
		return res.Question.ID
	}
	first, second, third := ask("36.133.109.81", inc), ask("36.133.115.51", inc), ask("218.206.21.130", inc)
	elsewhere := ask("8.8.4.4", other)
	q := db.Question.GetX(ctx, first)
	if sib, err := Siblings(ctx, db.Question, q); err != nil || len(sib) != 2 {
		t.Fatalf("同批应有另外两个问题：%v %d", err, len(sib))
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, n, err := AnswerBatch(ctx, tx, q, AnswerInput{Choice: "grant", Content: "客户站点连通性测试", ExpiresInDays: 30, Siblings: true}, "admin", "127.0.0.1", now)
	if err != nil || n != 2 {
		_ = tx.Rollback()
		t.Fatalf("应一并答掉两个同批问题：%v %d", err, n)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	facts := map[uuid.UUID]bool{}
	for _, id := range []uuid.UUID{first, second, third} {
		got := db.Question.GetX(ctx, id)
		if got.Status != "answered" || got.FactID == nil || !db.Fact.Query().Where(fact.IDEQ(*got.FactID)).ExistX(ctx) {
			t.Fatalf("同批问题应各自作答并写事实：%+v", got)
		}
		facts[*got.FactID] = true
	}
	if len(facts) != 3 {
		t.Fatalf("每个对象各写一条事实，不共用：%d", len(facts))
	}
	if db.Question.Query().Where(question.IDEQ(elsewhere)).OnlyX(ctx).Status != "open" {
		t.Fatal("别的事件提的问题不应被顺带答掉")
	}
}
