//go:build integration

package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent/triagerun"
	"openxdr/server/internal/testdb"
)

func TestCapabilityUpgradeCannotOverwriteManualClosureInFlight(t *testing.T) {
	for _, status := range []string{"closed", "false_positive"} {
		t.Run(status, func(t *testing.T) {
			ctx, db := testdb.New(t)
			f := &retriageFixture{t: t, ctx: ctx, client: db}
			inc := upgradeIncident(f, "模型调用中人工结案")
			called := false
			stub := &stubLLM{hook: func() {
				db.Incident.UpdateOneID(inc.ID).SetStatus(status).SetResolvedBy("analyst").
					SetResolution("人工独立调查的结论").ExecX(ctx)
			}}
			e := &Engine{DB: db, Cooldown: time.Minute, LLM: stub.llm(t), OnVerdict: func(context.Context, uuid.UUID, json.RawMessage) { called = true }}
			if err := e.triageOne(ctx, inc); !errors.Is(err, context.Canceled) {
				t.Fatal("人工终态应中止旧执行", err)
			}
			got := db.Incident.GetX(ctx, inc.ID)
			if got.Status != status || got.Resolution == nil || *got.Resolution != "人工独立调查的结论" || !bytes.Equal(got.AiVerdict, inc.AiVerdict) || !got.TriagedAt.Equal(*inc.TriagedAt) || got.TriageCount != inc.TriageCount {
				t.Fatal("人工终态或此前结论被覆写", got)
			}
			if called || got.IntegrationRevision != inc.IntegrationRevision || db.IntegrationEvent.Query().CountX(ctx) != 0 {
				t.Fatal("已结案后仍广播研判结果或触发处置回调")
			}
			runs := db.TriageRun.Query().AllX(ctx)
			if len(runs) != 1 || runs[0].Status != triagerun.StatusInterrupted {
				t.Fatal("旧尝试未正确记录为中断", runs)
			}
		})
	}
}
