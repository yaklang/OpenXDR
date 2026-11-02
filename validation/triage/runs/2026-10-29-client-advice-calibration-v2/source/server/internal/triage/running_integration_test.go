//go:build integration

package triage

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

func TestRunningLifecycle(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			ctx, db := testdb.New(t)
			f := &retriageFixture{t: t, ctx: ctx, client: db}
			inc := f.fresh("运行状态", time.Now())
			var seen atomic.Bool
			stub := &stubLLM{fail: func(string) bool { return fail }, hook: func() {
				row, err := db.Incident.Get(ctx, inc.ID)
				if err != nil {
					t.Error(err)
					return
				}
				if RunningStartedAt(row, time.Now()) == nil {
					t.Error("模型执行中缺少有效运行状态")
				}
				seen.Store(true)
			}}
			engine := &Engine{DB: db, LLM: stub.llm(t)}
			err := engine.triageOne(ctx, inc)
			if (err != nil) != fail {
				t.Fatalf("err=%v, fail=%v", err, fail)
			}
			if !seen.Load() {
				t.Fatal("未调用模型")
			}
			row := f.get(inc)
			if row.TriageStartedAt != nil || row.TriageHeartbeatAt != nil {
				t.Fatal("执行结束未清理状态")
			}
		})
	}
}

func TestRunningClaimAndRecovery(t *testing.T) {
	ctx, db := testdb.New(t)
	f := &retriageFixture{t: t, ctx: ctx, client: db}
	inc := f.fresh("重复执行", time.Now())
	started := time.Now().UTC().Truncate(time.Microsecond)
	db.Incident.UpdateOneID(inc.ID).SetTriageStartedAt(started).SetTriageHeartbeatAt(started).ExecX(ctx)
	stub := &stubLLM{}
	engine := &Engine{DB: db, LLM: stub.llm(t)}
	if err := engine.triageOne(ctx, inc); err != nil {
		t.Fatal(err)
	}
	if stub.calls() != 0 {
		t.Fatal("有效运行状态被重复执行")
	}
	db.Incident.UpdateOneID(inc.ID).SetTriageHeartbeatAt(started.Add(-2 * RunningTTL)).ExecX(ctx)
	if RunningStartedAt(f.get(inc), time.Now()) != nil {
		t.Fatal("过期心跳仍显示运行中")
	}
	if err := engine.triageOne(ctx, inc); err != nil {
		t.Fatal(err)
	}
	if stub.calls() != 1 {
		t.Fatal("未接管过期执行")
	}
}

func TestRunningCleanupOwnershipAndCancellation(t *testing.T) {
	ctx, db := testdb.New(t)
	f := &retriageFixture{t: t, ctx: ctx, client: db}
	inc := f.fresh("执行归属", time.Now())
	started := time.Now().UTC().Truncate(time.Microsecond)
	db.Incident.UpdateOneID(inc.ID).SetTriageStartedAt(started).SetTriageHeartbeatAt(started).ExecX(ctx)
	engine := &Engine{DB: db}
	parent, cancel := context.WithCancel(ctx)
	_, finish := engine.keepRunning(parent, inc.ID, started)
	newer := started.Add(time.Second)
	db.Incident.UpdateOneID(inc.ID).SetTriageStartedAt(newer).SetTriageHeartbeatAt(newer).ExecX(ctx)
	cancel()
	finish()
	if got := f.get(inc); got.TriageStartedAt == nil || !got.TriageStartedAt.Equal(newer) {
		t.Fatal("旧执行清除了新执行状态")
	}
	parent, cancel = context.WithCancel(ctx)
	_, finish = engine.keepRunning(parent, inc.ID, newer)
	cancel()
	finish()
	if f.get(inc).TriageStartedAt != nil {
		t.Fatal("取消执行后未清理状态")
	}
}

func TestRunningHeartbeat(t *testing.T) {
	ctx, db := testdb.New(t)
	f := &retriageFixture{t: t, ctx: ctx, client: db}
	inc := f.fresh("长时间研判", time.Now())
	started := time.Now().Add(-30 * time.Second).UTC().Truncate(time.Microsecond)
	db.Incident.UpdateOneID(inc.ID).SetTriageStartedAt(started).SetTriageHeartbeatAt(started).ExecX(ctx)
	engine := &Engine{DB: db}
	_, finish := engine.keepRunning(ctx, inc.ID, started)
	defer finish()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		row := f.get(inc)
		if row.TriageHeartbeatAt.After(started) && row.TriageStartedAt.Equal(started) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("持续研判未续心跳")
}
