//go:build integration

package response

import (
	"testing"

	"github.com/google/uuid"

	"openxdr/server/internal/testdb"
)

// Issue 三道闸门：能力未启用、资产无 agent、agent 未连接——三种都不得真执行。
func TestIssueGateways(t *testing.T) {
	ctx, client := testdb.New(t)

	agentID := uuid.New()
	asset, err := client.Asset.Create().
		SetHostname("victim").SetAgentID(agentID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 闸门一：RESPONSE_ENABLED=false，一律拒绝，且不落库
	off := NewHub(client, false)
	if _, err := off.Issue(ctx, Request{AssetID: asset.ID, Kind: "isolate_host", IssuedBy: "admin"}); err == nil {
		t.Fatal("能力未启用时 Issue 应拒绝")
	}
	if n, _ := client.Command.Query().Count(ctx); n != 0 {
		t.Fatalf("被拒绝的指令不应落库，实际 %d 条", n)
	}

	// 闸门二：资产没有 agent，无法下发
	noAgent, err := client.Asset.Create().SetHostname("orphan").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	on := NewHub(client, true)
	if _, err := on.Issue(ctx, Request{AssetID: noAgent.ID, Kind: "kill_process", IssuedBy: "admin"}); err == nil {
		t.Fatal("无 agent 的资产应拒绝下发")
	}

	// 闸门三：agent 在线但未连接指令通道（无 Router）→ 记 failed 而不是假装成功
	cmd, err := on.Issue(ctx, Request{AssetID: asset.ID, Kind: "isolate_host", DryRun: true, IssuedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := client.Command.Get(ctx, cmd.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "failed" {
		t.Errorf("agent 未连接应记 failed，实际 %q", stored.Status)
	}
	if stored.CompletedAt == nil {
		t.Error("failed 指令应记录完成时间")
	}
	if !stored.DryRun {
		t.Error("默认 dry-run，不允许裸执行")
	}
}
