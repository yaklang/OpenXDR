//go:build integration

package containment

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"openxdr/server/ent"
	entasset "openxdr/server/ent/asset"
	entcontainment "openxdr/server/ent/containment"
	"openxdr/server/pb"
)

func (f *fixture) verdictEngine() *Engine {
	e := f.engine(ScopeAll)
	e.Verdicts = VerdictPolicy{Auto: true, AutoConfidence: 90, ProposeConfidence: 70, ProposalTTL: 4 * time.Hour}
	return e
}

// incidentWith 一个研判过的事件，把告警挂进去
func (f *fixture) incidentWith(t *testing.T, verdict string, confidence int, alerts ...*ent.Alert) *ent.Incident {
	raw, _ := json.Marshal(map[string]any{"verdict": verdict, "confidence": confidence, "summary": "测试"})
	inc := f.client.Incident.Create().SetTitle("测试事件").SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).
		SetAiVerdict(raw).SetTriagedAt(f.now.Add(-time.Minute)).SaveX(f.ctx)
	for _, al := range alerts {
		f.client.Alert.UpdateOne(al).SetIncidentID(inc.ID).ExecX(f.ctx)
	}
	return inc
}

const curlShell = `{"process":{"pid":4242,"name":"sh","file":{"path":"/usr/bin/sh"}},"dst_endpoint":{"ip":"203.0.113.7","port":443},"connection_info":{"direction":"outbound"}}`

// 恶意且高置信度：结束涉事进程、封锁外部地址，不隔离主机
func TestMaliciousVerdictContainsMinimally(t *testing.T) {
	f := setup(t)
	web := f.host(t, "web", "10.1.1.183", nil, "")
	f.incidentWith(t, "malicious", 95, f.alertOn(t, web, "rule-x", 1007, "", curlShell))
	if err := f.verdictEngine().Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	got := f.received("web")
	if len(got) != 2 || got[0].Kind != pb.CommandKind_KILL_PROCESS || got[0].Pid != 4242 ||
		got[1].Kind != pb.CommandKind_BLOCK_NETWORK || got[1].Target != "203.0.113.7" {
		t.Fatalf("应结束进程并封锁外部地址：%v", got)
	}
}

// 容器里的告警只隔离容器；内网地址不封
func TestMaliciousVerdictIsolatesContainer(t *testing.T) {
	f := setup(t)
	web := f.host(t, "web", "10.1.1.183", nil, "")
	raw := `{"process":{"pid":77,"name":"bash"},"dst_endpoint":{"ip":"10.1.1.50"},"container":{"uid":"4f173e0d45b0","name":"app","runtime":"docker"}}`
	f.incidentWith(t, "malicious", 92, f.alertOn(t, web, "rule-x", 1007, "", raw))
	if err := f.verdictEngine().Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("web"); len(got) != 1 || got[0].Kind != pb.CommandKind_ISOLATE_CONTAINER || got[0].Target != "4f173e0d45b0" {
		t.Fatalf("应只隔离容器：%v", got)
	}
}

// 可疑：只提出处置，不执行；批准后才下发，驳回的作废，过期的作废
func TestSuspiciousVerdictWaitsForApproval(t *testing.T) {
	f := setup(t)
	web := f.host(t, "web", "10.1.1.183", nil, "")
	f.incidentWith(t, "suspicious", 75, f.alertOn(t, web, "rule-x", 1007, "", curlShell))
	e := f.verdictEngine()
	var pushed []string
	e.Notify = func(_ context.Context, title, text, path string) error { pushed = append(pushed, title); return nil }
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("web"); len(got) != 0 {
		t.Fatalf("可疑结论不该直接执行：%v", got)
	}
	if st := f.states(); st["block_network 203.0.113.7"] != entcontainment.StateProposed || len(pushed) != 1 {
		t.Fatalf("应提出两条处置并推送一次：%v %v", st, pushed)
	}
	// 再跑一轮不重复提出、不重复推送
	if err := e.Tick(f.ctx); err != nil || len(pushed) != 1 {
		t.Fatal("重复推送", err, pushed)
	}
	kill := f.client.Containment.Query().Where(entcontainment.KindEQ("kill_process")).OnlyX(f.ctx)
	approved, err := e.Approve(f.ctx, kill, "admin")
	if err != nil || approved.State == entcontainment.StateProposed || approved.DecidedBy == nil || *approved.DecidedBy != "admin" {
		t.Fatalf("批准后应下发：%v %v", approved, err)
	}
	if got := f.received("web"); len(got) != 1 || got[0].Kind != pb.CommandKind_KILL_PROCESS {
		t.Fatalf("批准后应下发结束进程：%v", got)
	}
	if _, err := e.Approve(f.ctx, approved, "admin"); err != ErrNotProposed {
		t.Fatalf("不能重复批准：%v", err)
	}
	block := f.client.Containment.Query().Where(entcontainment.KindEQ("block_network")).OnlyX(f.ctx)
	f.now = f.now.Add(5 * time.Hour)
	if err := e.Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if st := f.client.Containment.GetX(f.ctx, block.ID).State; st != entcontainment.StateDeclined {
		t.Fatalf("审批超时应作废：%v", st)
	}
	if got := f.received("web"); len(got) != 0 {
		t.Fatalf("过期的不能执行：%v", got)
	}
}

// 认不出更小的处置对象：实验等级自动隔离主机，生产只提出，核心不动；低于门槛、诱饵观察都不处置
func TestVerdictHostIsolationByTier(t *testing.T) {
	f := setup(t)
	lab := f.host(t, "range", "10.1.1.170", tierPtr(entasset.ResponseTierLab), "")
	prod := f.host(t, "web", "10.1.1.183", nil, "")
	core := f.host(t, "db", "10.1.1.51", tierPtr(entasset.ResponseTierCore), "")
	low := f.host(t, "dev", "10.1.1.52", nil, "")
	login := `{"src_endpoint":{"ip":"10.1.1.9"},"user":{"name":"root"}}`
	f.incidentWith(t, "malicious", 95, f.alertOn(t, lab, "rule-x", 3002, "root", login),
		f.alertOn(t, prod, "rule-x", 3002, "root", login), f.alertOn(t, core, "rule-x", 3002, "root", login))
	f.incidentWith(t, "suspicious", 50, f.alertOn(t, low, "rule-x", 1007, "", curlShell))
	f.incidentWith(t, "malicious", 99, f.alertOn(t, low, "decoy.observation.x", 1007, "", curlShell))
	if err := f.verdictEngine().Tick(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.received("range"); len(got) != 1 || got[0].Kind != pb.CommandKind_ISOLATE_HOST {
		t.Fatalf("实验等级应自动隔离：%v", got)
	}
	if got := f.received("web"); len(got) != 0 {
		t.Fatalf("生产不自动隔离：%v", got)
	}
	if c := f.client.Containment.Query().Where(entcontainment.AssetIDEQ(prod.ID)).OnlyX(f.ctx); c.Kind != "isolate_host" || c.State != entcontainment.StateProposed {
		t.Fatalf("生产应提出隔离等批准：%v", c)
	}
	for _, h := range []*ent.Asset{core, low} {
		if n := f.client.Containment.Query().Where(entcontainment.AssetIDEQ(h.ID)).CountX(f.ctx); n != 0 {
			t.Fatalf("%s 不该有处置：%d", h.Hostname, n)
		}
	}
}
