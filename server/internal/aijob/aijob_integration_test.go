//go:build integration

package aijob_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"openxdr/server/internal/aijob"
	"openxdr/server/internal/testdb"
)

// 同一对象同时发起只跑一次；名额照样释放；卡死的 running 不挡重新发起
func TestStartOnePerSubject(t *testing.T) {
	ctx, db := testdb.New(t)
	k := aijob.Key{Kind: "explain", Subject: "e1", Owner: "u1"}
	gate := make(chan struct{})
	var released sync.WaitGroup
	var mu sync.Mutex
	started := 0
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		released.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := aijob.Start(ctx, db, k, func(context.Context) (any, error) {
				<-gate
				return map[string]any{"ok": true}, nil
			}, released.Done)
			if err != nil {
				t.Error(err)
				return
			}
			if ok {
				mu.Lock()
				started++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if started != 1 {
		t.Fatalf("同时发起 8 次，跑了 %d 次", started)
	}
	close(gate)
	released.Wait()

	// 跑它的进程没了：running 停在很早以前
	old, err := db.AIJob.Create().SetKind("explain").SetSubject("e2").SetOwner("u1").
		SetCreatedAt(time.Now().Add(-time.Hour)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := aijob.Start(ctx, db, aijob.Key{Kind: "explain", Subject: "e2", Owner: "u1"},
		func(context.Context) (any, error) { return map[string]any{}, nil }, nil)
	if err != nil || !ok {
		t.Fatalf("卡死的任务挡住了重新发起：ok=%v err=%v", ok, err)
	}
	if j, _ := db.AIJob.Get(ctx, old.ID); j.Status != "failed" {
		t.Fatalf("卡死的任务应记为失败，实际 %s", j.Status)
	}

	// 返回无法反序列化为 JSON 对象的切片时，必须落库为 failed 并带错误信息，不得卡死在 running
	var unmarshalDone sync.WaitGroup
	unmarshalDone.Add(1)
	badKey := aijob.Key{Kind: "explain", Subject: "e-bad-shape", Owner: "u1"}
	badJob, ok, err := aijob.Start(ctx, db, badKey, func(context.Context) (any, error) {
		return []string{"not-an-object"}, nil
	}, unmarshalDone.Done)
	if err != nil || !ok {
		t.Fatalf("发起任务失败：ok=%v err=%v", ok, err)
	}
	unmarshalDone.Wait()
	gotBad, err := db.AIJob.Get(ctx, badJob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotBad.Status != "failed" || gotBad.Error == "" {
		t.Fatalf("Unmarshal 失败时应标记为 failed 且记录错误，实际 status=%q error=%q", gotBad.Status, gotBad.Error)
	}
}
