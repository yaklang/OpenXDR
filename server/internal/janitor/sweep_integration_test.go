//go:build integration

package janitor

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/testdb"
)

// 保留策略：只删过期且无任何告警引用的事件。
// 被告警引用的事件是 incident 证据，跟着 incident 生命周期走，不能到期就抹掉。
func TestJanitorSweep(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	retention := 24 * time.Hour
	cutoff := now.Add(-retention)

	// 过期且无引用 → 应删
	expired, err := client.Event.Create().
		SetTs(cutoff.Add(-time.Hour)).
		SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{}`)).
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 过期但被告警引用 → 保留
	expiredRef, err := client.Event.Create().
		SetTs(cutoff.Add(-time.Minute)).
		SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{}`)).
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(expiredRef.Ts).SetRuleID("r-ref").SetSeverity(1).SetEventID(expiredRef.ID).
		Save(ctx); err != nil {
		t.Fatal(err)
	}

	// 未过期无人问津 → 保留
	fresh, err := client.Event.Create().
		SetTs(now).
		SetClassUID(1007).SetSource("agent").SetRaw(json.RawMessage(`{}`)).
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	j := &Janitor{DB: client, Retention: retention}
	deleted, err := j.sweep(ctx)
	if err != nil {
		t.Fatalf("sweep 失败: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("应只删 1 条过期无引用事件，实际删了 %d", deleted)
	}

	left, err := client.Event.Query().IDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expect := map[uuid.UUID]bool{
		expiredRef.ID: true,
		fresh.ID:      true,
		expired.ID:    false,
	}
	if len(left) != 2 {
		t.Fatalf("剩余事件数应为 2，实际 %d", len(left))
	}
	for id, want := range expect {
		got := contains(left, id)
		if got != want {
			t.Errorf("id=%v 存在=%v, want=%v", id, got, want)
		}
	}
}

func contains(ids []uuid.UUID, id uuid.UUID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// Run 每轮除了清过期事件，还会顺手清过期会话——认证早已拒它们，行留着是纯垃圾。
func TestJanitorCleansExpiredSessions(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()

	expired, err := client.Session.Create().
		SetTokenHash("tok-expired").SetUserID(uuid.New()).
		SetExpiresAt(now.Add(-time.Hour)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := client.Session.Create().
		SetTokenHash("tok-fresh").SetUserID(uuid.New()).
		SetExpiresAt(now.Add(time.Hour)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	ctxRun, cancel := context.WithCancel(ctx)
	j := &Janitor{DB: client, Retention: 0, Interval: 20 * time.Millisecond} // retention 0：不碰事件，仍清会话
	go func() { j.Run(ctxRun); cancel() }()

	// 轮询等待过期会话被清掉。
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := client.Session.Get(ctx, expired.ID)
		if err != nil {
			break // 已被清理
		}
		if time.Now().After(deadline) {
			t.Fatal("过期会话未被清理")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 未过期会话必须仍在。
	if _, err := client.Session.Get(ctx, fresh.ID); err != nil {
		t.Errorf("未过期会话应保留: %v", err)
	}
	cancel()
}
