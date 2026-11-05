//go:build integration

package janitor

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/incidentwork"
	"openxdr/server/internal/testdb"
)

// 过期只产生独立复核候选；没有当前绑定提案或复核批准，等待再久也不直接按误报关掉。
func TestAutoCloseRequiresCurrentProposalAndIndependentReview(t *testing.T) {
	ctx, db := testdb.New(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	old := now.AddDate(0, 0, -8)
	create := func(verdict string, severity int16, at time.Time, proposal bool) *ent.Incident {
		inc := db.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SetCreatedAt(at).SetTriagedAt(at).SetAiVerdict(json.RawMessage(verdict)).SaveX(ctx)
		db.Alert.Create().SetTs(at).SetRuleID("r").SetSeverity(severity).SetIncidentID(inc.ID).ExecX(ctx)
		if proposal {
			db.Incident.UpdateOneID(inc.ID).SetClosureProposal(&schema.ClosureProposal{Status: "false_positive", Note: "提交复核，不代表已有独立结论", At: now, EvidenceKey: "fixture-bound-key", VerdictHash: "fixture-verdict-hash"}).ExecX(ctx)
		}
		if err := incidentwork.Refresh(ctx, db, db.Incident.GetX(ctx, inc.ID), now); err != nil {
			t.Fatal(err)
		}
		return db.Incident.GetX(ctx, inc.ID)
	}
	benign := `{"verdict":"benign","action_codes":["monitor"]}`
	accepted := create(benign, 3, old, true)
	rejected := create(benign, 4, old, true)
	noProposal := create(benign, 3, old, false)
	staleProposal := create(benign, 3, old, true)
	p := *staleProposal.ClosureProposal
	p.At = old.Add(-time.Minute)
	db.Incident.UpdateOneID(staleProposal.ID).SetClosureProposal(&p).ExecX(ctx)
	unbound := create(benign, 3, old, true)
	p = *unbound.ClosureProposal
	p.EvidenceKey = ""
	db.Incident.UpdateOneID(unbound.ID).SetClosureProposal(&p).ExecX(ctx)
	gapped := create(`{"verdict":"benign","action_codes":["collect_original_records"]}`, 3, old, true)
	suspicious := create(`{"verdict":"suspicious","action_codes":["monitor"]}`, 3, old, true)
	malicious := create(`{"verdict":"malicious","action_codes":["monitor"]}`, 3, old, true)
	fresh := create(benign, 3, now, true)
	pending := create(benign, 3, old, true)
	db.Incident.UpdateOneID(pending.ID).SetEvidenceAt(now).ExecX(ctx)

	if n, err := (&AutoClose{DB: db, Days: 7}).sweep(ctx); err != nil || n != 0 {
		t.Fatalf("无独立复核回调必须保持未结案 n=%d err=%v", n, err)
	}
	calls := map[uuid.UUID]int{}
	reviewer := func(ctx context.Context, id uuid.UUID) (bool, error) {
		calls[id]++
		if id != accepted.ID {
			return false, nil
		}
		// 这里仅替身验证janitor将结案交给复核器；正面证据与原子结案由closurereview集成测试验证。
		err := db.Incident.UpdateOneID(id).SetStatus("false_positive").SetResolution("独立复核器确认").SetResolutionSource("ai_review").SetResolvedBy("system").SetResolvedAt(now).ClearClosureProposal().Exec(ctx)
		return err == nil, err
	}
	if n, err := (&AutoClose{DB: db, Days: 0, Review: reviewer}).sweep(ctx); err != nil || n != 0 || len(calls) != 0 {
		t.Fatal("禁用时不应调用复核", n, err, calls)
	}
	a := &AutoClose{DB: db, Days: 7, Review: reviewer}
	if n, err := a.sweep(ctx); err != nil || n != 1 {
		t.Fatalf("只统计独立复核器实际通过的结案 n=%d err=%v", n, err)
	}
	if len(calls) != 2 || calls[accepted.ID] != 1 || calls[rejected.ID] != 1 {
		t.Fatalf("错误候选进入独立复核: %v", calls)
	}
	got := db.Incident.GetX(ctx, accepted.ID)
	if got.Status != "false_positive" || got.ResolutionSource == nil || *got.ResolutionSource != "ai_review" || got.ResolvedBy == nil || *got.ResolvedBy != "system" {
		t.Fatal("未保留独立复核来源", got)
	}
	for _, inc := range []*ent.Incident{rejected, noProposal, staleProposal, unbound, gapped, suspicious, malicious, fresh, pending} {
		got = db.Incident.GetX(ctx, inc.ID)
		if got.Status != "triaged" || got.ResolvedBy != nil || got.ResolvedAt != nil {
			t.Fatalf("TTL或缺证被当作良性证明: %s %+v", inc.ID, got)
		}
	}
	if n, err := a.sweep(ctx); err != nil || n != 0 {
		t.Fatal("重复执行不可重复结案", n, err)
	}
}
