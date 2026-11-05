//go:build integration

package triage

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/triagerun"
	"openxdr/server/internal/review"
	"openxdr/server/internal/testdb"
)

func upgradeIncident(f *retriageFixture, title string) *ent.Incident {
	inc := f.triaged(title, time.Hour)
	return f.client.Incident.UpdateOne(inc).SetAiVerdict(json.RawMessage(`{"verdict":"benign","summary":"旧结论需补证","action_codes":["collect_original_records"]}`)).SaveX(f.ctx)
}

func TestCapabilityUpgradeQueueBoundaries(t *testing.T) {
	ctx, db := testdb.New(t)
	f := &retriageFixture{t: t, ctx: ctx, client: db}
	e := &Engine{DB: db, Cooldown: 30 * time.Minute}
	old := upgradeIncident(f, "旧补证")
	other := upgradeIncident(f, "另一条补证")
	db.Incident.UpdateOne(other).SetTriagedAt(time.Now()).ExecX(ctx)
	closed := upgradeIncident(f, "人工结案")
	db.Incident.UpdateOne(closed).SetStatus("closed").ExecX(ctx)
	backoff := upgradeIncident(f, "退避")
	db.Incident.UpdateOne(backoff).SetTriageRetryAt(time.Now().Add(time.Hour)).ExecX(ctx)
	current := upgradeIncident(f, "已用新能力")
	db.Incident.UpdateOne(current).SetAiVerdict(withEvidenceCapability(current.AiVerdict)).ExecX(ctx)
	queued, err := e.queue(ctx, time.Now())
	if err != nil || len(queued) != 1 || queued[0].ID != old.ID {
		t.Fatalf("升级筛选错误：%v %v", queued, err)
	}
	for i := range batchSize {
		f.fresh("新事件", time.Now().Add(time.Duration(i)*time.Second))
	}
	queued, err = e.queue(ctx, time.Now())
	if err != nil || len(queued) != batchSize {
		t.Fatal(queued, err)
	}
	for _, inc := range queued {
		if inc.Status != "open" {
			t.Fatal("升级抢占新事件名额")
		}
	}
}

func TestCapabilityUpgradeAttemptBudgetAndNewEvidence(t *testing.T) {
	ctx, db := testdb.New(t)
	f := &retriageFixture{t: t, ctx: ctx, client: db}
	e := &Engine{DB: db, Cooldown: time.Minute}
	inc := upgradeIncident(f, "预算")
	for attempt := range capabilityMaxAttempts {
		queued, err := e.queue(ctx, time.Now())
		if err != nil || len(queued) != 1 {
			t.Fatal("提前耗尽预算", attempt, queued, err)
		}
		row, err := e.beginRun(ctx, queued[0], time.Now().UTC().Truncate(time.Microsecond), "m")
		if err != nil || row == nil || row.Trigger != capabilityTrigger {
			t.Fatal(row, err)
		}
		e.failRun(row, &runTiming{}, "model", http.ErrHandlerTimeout)
		db.Incident.UpdateOneID(inc.ID).ClearTriageStartedAt().ClearTriageHeartbeatAt().ExecX(ctx)
	}
	queued, err := e.queue(ctx, time.Now())
	if err != nil || len(queued) != 0 {
		t.Fatal("能力升级超过尝试预算", queued, err)
	}
	f.evidence(inc, "new", 4, true)
	queued, err = e.queue(ctx, time.Now())
	if err != nil || len(queued) != 1 {
		t.Fatal("升级失败不能阻塞真正的新证据", queued, err)
	}
}

func TestCapabilityUpgradeClaimFencesChangedState(t *testing.T) {
	for _, change := range []string{"closed", "version", "evidence", "concurrent"} {
		t.Run(change, func(t *testing.T) {
			ctx, db := testdb.New(t)
			f := &retriageFixture{t: t, ctx: ctx, client: db}
			e := &Engine{DB: db, Cooldown: time.Minute}
			stale := upgradeIncident(f, "过期快照")
			switch change {
			case "closed":
				db.Incident.UpdateOne(stale).SetStatus("closed").ExecX(ctx)
			case "version":
				db.Incident.UpdateOne(stale).SetAiVerdict(withEvidenceCapability(stale.AiVerdict)).ExecX(ctx)
			case "evidence":
				f.evidence(stale, "new", 3, false)
			case "concurrent":
				var wg sync.WaitGroup
				for range 4 {
					wg.Go(func() {
						_, err := e.beginRun(ctx, stale, time.Now().UTC().Truncate(time.Microsecond), "m")
						if err != nil {
							t.Error(err)
						}
					})
				}
				wg.Wait()
			}
			row, err := e.beginRun(ctx, stale, time.Now().UTC().Truncate(time.Microsecond), "m")
			if err != nil || row != nil {
				t.Fatal("过期资格仍可领取", row, err)
			}
			want := 0
			if change == "concurrent" {
				want = 1
			}
			if got := db.TriageRun.Query().Where(triagerun.IncidentIDEQ(stale.ID)).CountX(ctx); got != want {
				t.Fatal("出现重复或虚假尝试", got)
			}
		})
	}
}

func TestCapabilityUpgradeSuccessDoesNotInventEvidenceOrClose(t *testing.T) {
	ctx, db := testdb.New(t)
	f := &retriageFixture{t: t, ctx: ctx, client: db}
	inc := upgradeIncident(f, "仍缺记录")
	var prompt string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Messages []Message }
		_ = json.NewDecoder(r.Body).Decode(&req)
		prompt = req.Messages[1].Content
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": Message{Role: "assistant", Content: `{"verdict":"benign","confidence":70,"summary":"仍缺非纳管客户端原始记录，不证明业务授权","action_codes":["collect_original_records"],"evidence_capability_version":999}`}}}})
	}))
	defer srv.Close()
	e := &Engine{DB: db, Cooldown: time.Minute, LLM: NewLLM(srv.URL, "m", "", time.Second)}
	if err := e.triageOne(ctx, inc); err != nil {
		t.Fatal(err)
	}
	got := db.Incident.GetX(ctx, inc.ID)
	if got.Status != "triaged" || got.EvidenceAt != nil || got.UrgentAt != nil || needsCapabilityUpgrade(got) {
		t.Fatal("伪造证据、结案或未记录能力版本", got)
	}
	if !strings.Contains(prompt, "没有宣称新增告警或新增攻击证据") {
		t.Fatal("未向模型区分能力升级与新增攻击证据", prompt)
	}
	if !db.Incident.Query().Where(incident.IDEQ(inc.ID), review.Needed()).ExistX(ctx) {
		t.Fatal("补证不足仍须保留人工边界")
	}
	queued, err := e.queue(ctx, time.Now().Add(time.Hour))
	if err != nil || len(queued) != 0 {
		t.Fatal("成功后因仍缺证反复研判", queued, err)
	}
}
