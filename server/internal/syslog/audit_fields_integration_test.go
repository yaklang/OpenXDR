//go:build integration

package syslog

import (
	"encoding/json"
	"net"
	"testing"

	"openxdr/server/internal/testdb"
)

// 验证实际入队路径保留 audit 原始归因及主机绑定。
func TestAuditEvidenceSurvivesEnqueue(t *testing.T) {
	ctx, client := testdb.New(t)
	asset := client.Asset.Create().SetHostname("audit-test").SetOs("linux").SaveX(ctx)
	bus := &recordBus{}
	s := &Server{DB: client, Events: bus}
	line := `<86>1 2026-11-02T00:00:00Z audit-test auditd - - - type=CONFIG_CHANGE msg=audit(1793577600.123:42): auid=1000 ses=2 op=remove_rule key="auth" list=4 res=1`
	if err := s.enqueue(ctx, incoming{line: line, from: net.ParseIP("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	if len(bus.envs) != 1 || bus.envs[0].AssetID == nil || *bus.envs[0].AssetID != asset.ID {
		t.Fatal("主机归属丢失")
	}
	var raw map[string]any
	if err := json.Unmarshal(bus.envs[0].Raw, &raw); err != nil {
		t.Fatal(err)
	}
	evidence, ok := raw["audit"].(map[string]any)
	if !ok || evidence["auid"] != "1000" || evidence["serial"] != "42" {
		t.Fatal("队列丢失审计归因")
	}
}
