//go:build integration

package ueba

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func procEvent(t *testing.T, ctx context.Context, c *ent.Client, assetID uuid.UUID, exe string, ts time.Time) *ent.Event {
	t.Helper()
	raw := fmt.Sprintf(`{"process":{"pid":1,"name":"x","file":{"path":"%s"}}}`, exe)
	ev, err := c.Event.Create().
		SetTs(ts).SetClassUID(classProcess).SetSource("agent").
		SetAssetID(assetID).SetRaw(json.RawMessage(raw)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func newEngine(c *ent.Client) *Engine {
	return &Engine{
		DB: c, Suppress: suppress.New(c, time.Hour),
		LearningPeriod: 7 * 24 * time.Hour, Interval: time.Second,
	}
}

// 学习期内只建基线不告警；学习期满后新出现的可执行文件才升为告警；
// 已入基线的组合永不重复告警。
func TestFirstSeenLifecycle(t *testing.T) {
	ctx, client := testdb.New(t)
	asset, err := client.Asset.Create().SetHostname("h1").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(client)

	// 阶段一：首次观测，全部进基线，零告警
	now := time.Now()
	procEvent(t, ctx, client, asset.ID, "/usr/bin/bash", now.Add(-8*24*time.Hour))
	procEvent(t, ctx, client, asset.ID, "/usr/bin/sshd", now.Add(-8*24*time.Hour))
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := client.ProcessBaseline.Query().Count(ctx); n != 2 {
		t.Fatalf("应建 2 条基线，实际 %d", n)
	}
	if n, _ := client.Alert.Query().Count(ctx); n != 0 {
		t.Fatalf("学习期内不应告警，实际 %d 条", n)
	}

	// 阶段二：8 天后（学习期满）新程序出现 → low 告警；老程序再跑不告警
	procEvent(t, ctx, client, asset.ID, "/tmp/miner", now)
	procEvent(t, ctx, client, asset.ID, "/usr/bin/bash", now)
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	alerts, err := client.Alert.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].RuleID != sigma.RuleNewProcess {
		t.Fatalf("应产出 1 条首次出现告警，实际 %+v", alerts)
	}
	if alerts[0].Severity != 2 {
		t.Errorf("首次出现应为 low(2)，实际 %d", alerts[0].Severity)
	}

	// 阶段三：同一程序再次出现，基线已有，不再告警
	procEvent(t, ctx, client, asset.ID, "/tmp/miner", now.Add(time.Minute))
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := client.Alert.Query().Where(alert.RuleIDEQ(sigma.RuleNewProcess)).Count(ctx); n != 1 {
		t.Errorf("重复出现不应再告警，实际 %d 条", n)
	}
	if n, _ := client.ProcessBaseline.Query().Count(ctx); n != 3 {
		t.Errorf("基线应为 3 条，实际 %d", n)
	}
}

// 新接入的资产从零开始学习：即使别的资产已过学习期，它也不受连坐。
func TestLearningIsPerAsset(t *testing.T) {
	ctx, client := testdb.New(t)
	old, _ := client.Asset.Create().SetHostname("old").Save(ctx)
	fresh, _ := client.Asset.Create().SetHostname("fresh").Save(ctx)
	e := newEngine(client)

	now := time.Now()
	// old 资产 8 天前已有基线
	procEvent(t, ctx, client, old.ID, "/usr/bin/bash", now.Add(-8*24*time.Hour))
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	// fresh 资产今天才接入，跑了一个程序
	procEvent(t, ctx, client, fresh.ID, "/opt/app/server", now)
	if _, err := e.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := client.Alert.Query().Count(ctx); n != 0 {
		t.Errorf("新资产在学习期内不应告警，实际 %d 条", n)
	}
}
