//go:build integration

package containment

import (
	"testing"

	entasset "openxdr/server/ent/asset"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/pb"
)

// 公网来源的封锁在边界网关上一并执行；内网地址不上边界；原动作被跳过（核心资产）时边界也跳过
func TestPublicBlocksAlsoLandOnEdge(t *testing.T) {
	f := setup(t)
	web := f.host(t, "web", "10.1.1.183", nil, "")
	f.host(t, "gateway", "10.1.1.100", tierPtr(entasset.ResponseTierCore), "")
	core := f.host(t, "db", "10.1.1.51", tierPtr(entasset.ResponseTierCore), "")
	shell := func(peer string) string {
		return `{"activity_id":99,"process":{"pid":31337,"name":"bash","file":{"path":"/usr/bin/bash"}},` +
			`"stdio_socket":{"fd":0,"protocol":"tcp"},"dst_endpoint":{"ip":"` + peer + `","port":4444}}`
	}
	f.alertOn(t, web, RuleShellStdio, 1007, "", shell("203.0.113.9"))
	f.alertOn(t, web, RuleShellStdio, 1007, "", shell("10.1.1.77"))
	f.alertOn(t, core, RuleShellStdio, 1007, "", shell("198.51.100.4"))
	e := f.engine(ScopeAll)
	e.EdgeHosts = []string{"gateway"}
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	got := f.received("gateway")
	if len(got) != 1 || got[0].Kind != pb.CommandKind_BLOCK_NETWORK || got[0].Target != "203.0.113.9" {
		t.Fatalf("边界只应封锁公网来源 203.0.113.9：%v", got)
	}
	edge := f.client.Containment.Query().Where(entcontainment.RoleEQ(entcontainment.RoleEdge)).AllX(f.ctx)
	states := map[string]entcontainment.State{}
	for _, c := range edge {
		states[c.Target] = c.State
	}
	if _, ok := states["10.1.1.77"]; ok {
		t.Fatalf("内网地址不该上边界：%v", states)
	}
	if states["198.51.100.4"] != entcontainment.StateSkipped {
		t.Fatalf("核心资产上被跳过的封锁，边界也应跳过：%v", states)
	}
}
