//go:build integration

package response

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/command"
	"openxdr/server/internal/testdb"
)

func seedIncident(t *testing.T, ctx context.Context, c *ent.Client, hostname string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	asset, err := c.Asset.Create().
		SetHostname(hostname).SetAgentID(uuid.New()).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inc, err := c.Incident.Create().
		SetStatus("triaged").SetGraph(json.RawMessage("{}")).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Alert.Create().
		SetTs(time.Now()).SetRuleID("r1").SetSeverity(5).
		SetAssetID(asset.ID).SetIncidentID(inc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	return inc.ID, asset.ID
}

func malicious(confidence int) json.RawMessage {
	v, _ := json.Marshal(map[string]any{"verdict": "malicious", "confidence": confidence})
	return v
}

// 高置信度 malicious → 对涉事资产下发 dry-run 隔离；重复触发不再下发。
func TestAutoIsolate(t *testing.T) {
	ctx, client := testdb.New(t)
	incID, assetID := seedIncident(t, ctx, client, "victim")

	auto := &Auto{Hub: NewHub(client, true), MinConfidence: 90}
	auto.React(ctx, incID, malicious(95))

	cmds, err := client.Command.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("应下发 1 条隔离指令，实际 %d", len(cmds))
	}
	cmd := cmds[0]
	if cmd.Kind != "isolate_host" || cmd.AssetID != assetID || cmd.IssuedBy != "auto" {
		t.Errorf("指令内容不对: %+v", cmd)
	}
	if !cmd.DryRun {
		t.Error("未配置 Live 时必须 dry-run")
	}
	// agent 未连接指令通道 → 状态 failed，但决策已留痕
	if cmd.Status != "failed" {
		t.Errorf("agent 不在线应记 failed，实际 %s", cmd.Status)
	}

	// 重开重判再次触发：同一 incident 同一资产不重复下发
	auto.React(ctx, incID, malicious(99))
	if n, _ := client.Command.Query().Count(ctx); n != 1 {
		t.Errorf("重复触发不应再下发，实际 %d 条", n)
	}
}

// 置信度不足、非 malicious、白名单主机——三种情况都不动手。
func TestAutoRestraint(t *testing.T) {
	ctx, client := testdb.New(t)
	incID, _ := seedIncident(t, ctx, client, "prod-db")

	hub := NewHub(client, true)

	// 置信度不足
	(&Auto{Hub: hub, MinConfidence: 90}).React(ctx, incID, malicious(80))
	// 非 malicious
	benign, _ := json.Marshal(map[string]any{"verdict": "benign", "confidence": 100})
	(&Auto{Hub: hub, MinConfidence: 90}).React(ctx, incID, benign)
	// 白名单
	(&Auto{Hub: hub, MinConfidence: 90, Exempt: map[string]bool{"prod-db": true}}).
		React(ctx, incID, malicious(99))

	if n, _ := client.Command.Query().Where(command.KindEQ("isolate_host")).Count(ctx); n != 0 {
		t.Errorf("三种克制场景都不应下发指令，实际 %d 条", n)
	}
}
