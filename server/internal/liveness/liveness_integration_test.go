//go:build integration

package liveness

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/testdb"
)

// 失联只报一次，恢复报一次；没有 agent 的资产（syslog 来源）不参与；推送失败下轮重试。
func TestSilentAndRecovered(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	stale := now.Add(-20 * time.Minute)
	pve1, _ := client.Asset.Create().SetHostname("pve1").SetAgentID(uuid.New()).SetLastSeen(stale).Save(ctx)
	client.Asset.Create().SetHostname("pve2").SetAgentID(uuid.New()).SetLastSeen(now).SaveX(ctx)
	client.Asset.Create().SetHostname("syslog-only").SetLastSeen(stale).SaveX(ctx)

	var titles, bodies []string
	fail := true
	w := &Watcher{DB: client, SilentAfter: 10 * time.Minute, Notify: func(_ context.Context, title, body, path string) error {
		if fail {
			return context.DeadlineExceeded
		}
		titles, bodies = append(titles, title), append(bodies, body)
		return nil
	}}

	if err := w.sweep(ctx, now); err == nil {
		t.Fatal("推送失败应返回错误")
	}
	if got := client.Asset.GetX(ctx, pve1.ID); got.SilentSince != nil {
		t.Fatal("推送失败不应落失联标记")
	}

	fail = false
	for range 2 {
		if err := w.sweep(ctx, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(titles) != 1 || titles[0] != "1 台主机失联" || !strings.Contains(bodies[0], "pve1") {
		t.Fatalf("应只报一次 pve1 失联，实际 %v %v", titles, bodies)
	}

	client.Asset.UpdateOneID(pve1.ID).SetLastSeen(now.Add(time.Minute)).ExecX(ctx)
	if err := w.sweep(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(titles) != 2 || titles[1] != "1 台主机恢复" {
		t.Fatalf("应报一次恢复，实际 %v", titles)
	}
	if got := client.Asset.GetX(ctx, pve1.ID); got.SilentSince != nil {
		t.Fatal("恢复后应清掉失联标记")
	}
}

func TestParkedAndRetiredSkippedUntilUnparked(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	stale := now.Add(-30 * time.Minute)
	parked := client.Asset.Create().
		SetHostname("TESTSRV").
		SetAgentID(uuid.New()).
		SetLastSeen(stale).
		SetParkedAt(now).
		SetParkedBy("admin").
		SetParkedReason("测试机平时关机保留").
		SaveX(ctx)
	client.Asset.Create().
		SetHostname("gym").
		SetAgentID(uuid.New()).
		SetLastSeen(stale).
		SetRetiredAt(now).
		SetRetiredBy("admin").
		SetRetiredReason("销毁").
		SaveX(ctx)

	var titles []string
	w := &Watcher{DB: client, SilentAfter: 10 * time.Minute, Notify: func(_ context.Context, title, _, _ string) error {
		titles = append(titles, title)
		return nil
	}}
	if err := w.sweep(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(titles) != 0 {
		t.Fatalf("停机保留与已退役资产不应触发失联通知：%v", titles)
	}
	if got := client.Asset.GetX(ctx, parked.ID); got.SilentSince != nil {
		t.Fatal("停机保留资产不应写入 silent_since")
	}

	// 取消停机保留后，失联检测恢复
	client.Asset.UpdateOneID(parked.ID).ClearParkedAt().ClearParkedBy().ClearParkedReason().ExecX(ctx)
	if err := w.sweep(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(titles) != 1 || titles[0] != "1 台主机失联" {
		t.Fatalf("取消停机保留后应恢复失联通知：%v", titles)
	}
}
