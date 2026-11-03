//go:build integration

package suppressreview

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

type fixture struct {
	ctx     context.Context
	db      *ent.Client
	host    uuid.UUID
	store   *suppress.Store
	r       *Reviewer
	models  []string
	answer  func() (bool, string, error)
	content string
}

func setup(t *testing.T) *fixture {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("运维").SaveX(ctx)
	host := db.Asset.Create().SetHostname("dns-01").SetOs("linux").SetGroupID(g.ID).SaveX(ctx)
	for _, name := range []string{"updates.example.com", "evil.example.net"} {
		ev := db.Event.Create().SetTs(time.Now()).SetClassUID(4003).SetSource("agent").SetAssetID(host.ID).
			SetRaw(json.RawMessage(`{"query":{"hostname":"` + name + `"},"process":{"cmd_line":"apt-get update","file":{"path":"/usr/bin/apt"}}}`)).SaveX(ctx)
		db.Alert.Create().SetTs(time.Now()).SetRuleID("probe").SetSeverity(2).SetAssetID(host.ID).SetEventID(ev.ID).SaveX(ctx)
	}
	f := &fixture{ctx: ctx, db: db, host: host.ID, store: suppress.New(db, time.Hour)}
	f.r = &Reviewer{DB: db, Store: f.store, Model: func() string { return "platform-model" }, Interval: time.Hour,
		Judge: func(_ context.Context, model, material string) (bool, string, error) {
			f.models, f.content = append(f.models, model), material
			return f.answer()
		}}
	return f
}

func (f *fixture) draft(session *uuid.UUID, created time.Time) *ent.Suppression {
	return f.db.Suppression.Create().SetRuleID("probe").SetAssetID(f.host).SetStatus("proposed").SetCreatedBy("fp-stats").
		SetReason("误报统计：apt 每天解析更新域名").SetConditions([]suppress.Condition{{Field: "query.hostname", Op: "equals", Value: "updates.example.com"}}).
		SetNillableSessionID(session).SetCreatedAt(created).SetExpiresAt(created.AddDate(0, 0, 30)).SaveX(f.ctx)
}

func (f *fixture) audit(id uuid.UUID) string {
	rows := f.db.AuditLog.Query().Where(auditlog.ActionEQ("suppression_ai_reviewed"), auditlog.TargetEQ(id.String())).AllX(f.ctx)
	if len(rows) != 1 || rows[0].Username != "ai-reviewer" || rows[0].Detail == nil {
		return ""
	}
	return *rows[0].Detail
}

// 批准：与人工批准同样生效、有效期从批准时重算，决定人 ai-reviewer，理由进审计；有会话用会话的模型
func TestApprove(t *testing.T) {
	f := setup(t)
	session := f.db.AgentSession.Create().SetKind("chat").SetGroupID(f.db.Group.Query().OnlyX(f.ctx).ID).SetInitiator("a").SetModel("session-model").SaveX(f.ctx)
	d := f.draft(&session.ID, time.Now().AddDate(0, 0, -10))
	f.answer = func() (bool, string, error) { return true, "只压 apt 的更新域名", nil }
	status, reason, err := f.r.Review(f.ctx, d.ID)
	if err != nil || status != "active" || reason != "只压 apt 的更新域名" {
		t.Fatalf("应批准: %s %q %v", status, reason, err)
	}
	if len(f.models) != 1 || f.models[0] != "session-model" {
		t.Fatalf("有会话应用会话模型: %v", f.models)
	}
	got := f.db.Suppression.GetX(f.ctx, d.ID)
	if got.Status != "active" || got.ReviewedBy == nil || *got.ReviewedBy != "ai-reviewer" || got.ReviewedAt == nil ||
		got.ExpiresAt.Before(time.Now().AddDate(0, 0, 29)) {
		t.Fatalf("批准后应生效、有效期从批准时重算: %+v", got)
	}
	if !f.store.Suppressed("probe", &f.host, map[string]any{"query": map[string]any{"hostname": "updates.example.com"}}, time.Now()) {
		t.Fatal("批准后应立即进抑制索引")
	}
	if detail := f.audit(d.ID); detail != "approved: 只压 apt 的更新域名" {
		t.Fatalf("审计: %q", detail)
	}
	// 材料：规则、主机、条件、理由，以及条件压得住与压不住的样本
	for _, want := range []string{"规则 ID：probe", "主机：dns-01（linux）", "所在组：运维", `query.hostname equals "updates.example.com"`,
		"有效期：30 天", "apt 每天解析更新域名", "2 次，其中条件压得住 1 次、压不住 1 次", `query.hostname="evil.example.net"`, `process.cmd_line="apt-get update"`} {
		if !strings.Contains(f.content, want) {
			t.Errorf("材料缺少 %q:\n%s", want, f.content)
		}
	}
	// 已处理的不再评审
	if status, _, err := f.r.Review(f.ctx, d.ID); err != nil || status != "active" || len(f.models) != 1 {
		t.Fatalf("已处理的不该再调模型: %s %v %v", status, err, f.models)
	}
}

// 拒绝与回复不合格都记为拒绝；会话已不在时退到平台模型
func TestRejectAndError(t *testing.T) {
	f := setup(t)
	gone := uuid.New()
	d := f.draft(&gone, time.Now())
	f.answer = func() (bool, string, error) { return false, "高危规则不能按域名后缀压", nil }
	if status, _, err := f.r.Review(f.ctx, d.ID); err != nil || status != "rejected" {
		t.Fatalf("应拒绝: %s %v", status, err)
	}
	if f.models[0] != "platform-model" {
		t.Fatalf("会话不在应用平台模型: %v", f.models)
	}
	got := f.db.Suppression.GetX(f.ctx, d.ID)
	if got.Status != "rejected" || *got.ReviewedBy != "ai-reviewer" {
		t.Fatalf("拒绝: %+v", got)
	}
	if detail := f.audit(d.ID); detail != "rejected: 高危规则不能按域名后缀压" {
		t.Fatalf("审计: %q", detail)
	}

	// 收到了回复但不合格：按拒绝
	e := f.draft(nil, time.Now())
	f.answer = func() (bool, string, error) { return false, "", errors.New("审计员回复不是 JSON：好的") }
	if status, reason, err := f.r.Review(f.ctx, e.ID); err != nil || status != "rejected" || !strings.Contains(reason, "评审失败") {
		t.Fatalf("回复不合格应按拒绝: %s %q %v", status, reason, err)
	}
	if detail := f.audit(e.ID); !strings.HasPrefix(detail, "rejected: 审计员评审失败") {
		t.Fatalf("审计: %q", detail)
	}
	if f.store.Suppressed("probe", &f.host, map[string]any{"query": map[string]any{"hostname": "updates.example.com"}}, time.Now()) {
		t.Fatal("拒绝的不能生效")
	}
}

// 没配模型时草案留给人审；兜底循环只接生成够久的待批草案
func TestSweep(t *testing.T) {
	f := setup(t)
	f.answer = func() (bool, string, error) { return true, "ok", nil }
	f.r.Model = func() string { return "" }
	old := f.draft(nil, time.Now().Add(-time.Hour))
	if status, _, err := f.r.Review(f.ctx, old.ID); err != nil || status != "proposed" || len(f.models) != 0 {
		t.Fatalf("没配模型应留在待批准: %s %v %v", status, err, f.models)
	}
	f.r.Model = func() string { return "platform-model" }
	fresh := f.draft(nil, time.Now())
	if err := f.r.Sweep(f.ctx, time.Now().Add(-settle)); err != nil {
		t.Fatal(err)
	}
	if got := f.db.Suppression.GetX(f.ctx, old.ID); got.Status != "active" {
		t.Fatalf("积压的草案应被评审: %s", got.Status)
	}
	if got := f.db.Suppression.GetX(f.ctx, fresh.ID); got.Status != "proposed" {
		t.Fatalf("刚生成的留给生成时那次评审: %s", got.Status)
	}
	if len(f.models) != 1 {
		t.Fatalf("应只评审一条: %v", f.models)
	}
}

// 模型调不通：草案留在待批准、不写审计，兜底循环本轮遇到就停，下一轮再试
func TestUnavailable(t *testing.T) {
	f := setup(t)
	f.answer = func() (bool, string, error) { return false, "", fmt.Errorf("%w：connection refused", ErrUnavailable) }
	a := f.draft(nil, time.Now().Add(-2*time.Hour))
	b := f.draft(nil, time.Now().Add(-time.Hour))
	if status, _, err := f.r.Review(f.ctx, a.ID); !errors.Is(err, ErrUnavailable) || status != "proposed" {
		t.Fatalf("调不通应返回 ErrUnavailable 且留在待批准: %s %v", status, err)
	}
	if err := f.r.Sweep(f.ctx, time.Now().Add(-settle)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("本轮应因调不通结束: %v", err)
	}
	if len(f.models) != 2 {
		t.Fatalf("遇到调不通就停，不该逐条重试: %v", f.models)
	}
	for _, d := range []*ent.Suppression{a, b} {
		if got := f.db.Suppression.GetX(f.ctx, d.ID); got.Status != "proposed" || got.ReviewedBy != nil || f.audit(d.ID) != "" {
			t.Fatalf("调不通不该改动草案或写审计: %+v", got)
		}
	}
	// 端点恢复后下一轮评审
	f.answer = func() (bool, string, error) { return true, "ok", nil }
	if err := f.r.Sweep(f.ctx, time.Now().Add(-settle)); err != nil {
		t.Fatal(err)
	}
	for _, d := range []*ent.Suppression{a, b} {
		if got := f.db.Suppression.GetX(f.ctx, d.ID); got.Status != "active" {
			t.Fatalf("恢复后应评审: %s", got.Status)
		}
	}
}
