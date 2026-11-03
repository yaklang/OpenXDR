//go:build integration

package correlate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
)

// 跨容器、跨主机攻击的关联（见 docs/attack-campaign-design.md）：每个场景按「每条告警一批」与「全部一批」各跑一遍，
// 批次边界不能改变结论。
type campaignFixture struct {
	t       *testing.T
	ctx     context.Context
	client  *ent.Client
	eng     *Engine
	pending []*ent.Alert
	perOne  bool
}

func newCampaignFixture(t *testing.T, perOne bool) *campaignFixture {
	ctx, client := testdb.New(t)
	return &campaignFixture{t: t, ctx: ctx, client: client, perOne: perOne, eng: &Engine{
		DB: client, Rules: &sigma.Engine{}, Window: 30 * time.Minute, MaxGraphNodes: 200, RecurSpan: 24 * time.Hour,
	}}
}

func (f *campaignFixture) asset(name string, group uuid.UUID, ips ...string) *ent.Asset {
	f.t.Helper()
	return f.client.Asset.Create().SetHostname(name).SetGroupID(group).SetIPAddrs(ips).SaveX(f.ctx)
}

// alert 造一条告警；perOne 时立即关联，否则攒到 flush
func (f *campaignFixture) alert(a *ent.Asset, ts time.Time, rule string, sev int16, class int, raw string) *ent.Alert {
	f.t.Helper()
	evt := f.client.Event.Create().SetTs(ts).SetClassUID(class).SetSource("agent").
		SetAssetID(a.ID).SetRaw(json.RawMessage(raw)).SaveX(f.ctx)
	al := f.client.Alert.Create().SetTs(ts).SetRuleID(rule).SetSeverity(sev).
		SetEventID(evt.ID).SetAssetID(a.ID).SaveX(f.ctx)
	if f.perOne {
		f.flush()
	}
	return al
}

func (f *campaignFixture) proc(a *ent.Asset, ts time.Time, rule string, sev int16, container, cmd string) *ent.Alert {
	doc := map[string]any{"process": map[string]any{"name": "sh", "pid": 1, "cmd_line": cmd, "file": map[string]any{"path": "/bin/sh"}}}
	if container != "" {
		doc["container"] = map[string]any{"runtime": "docker", "uid": container}
	}
	raw, _ := json.Marshal(doc)
	return f.alert(a, ts, rule, sev, 1007, string(raw))
}

func (f *campaignFixture) loginFailure(a *ent.Asset, ts time.Time, rule string, sev int16, from string) *ent.Alert {
	return f.alert(a, ts, rule, sev, 3002, `{"status_id":2,"user":{"name":"root"},"service":{"name":"sshd"},"src_endpoint":{"ip":"`+from+`"}}`)
}

func (f *campaignFixture) flush() {
	f.t.Helper()
	if err := f.eng.batch(f.ctx); err != nil {
		f.t.Fatalf("batch 失败: %v", err)
	}
}

func (f *campaignFixture) incidentOf(al *ent.Alert) *ent.Incident {
	f.t.Helper()
	got := f.client.Alert.GetX(f.ctx, al.ID)
	if got.IncidentID == nil {
		f.t.Fatalf("告警 %s 未归属", al.RuleID)
	}
	return f.client.Incident.GetX(f.ctx, *got.IncidentID)
}

func bothBatchings(t *testing.T, run func(t *testing.T, f *campaignFixture)) {
	for _, perOne := range []bool{true, false} {
		t.Run(fmt.Sprintf("perOne=%v", perOne), func(t *testing.T) { run(t, newCampaignFixture(t, perOne)) })
	}
}

// 宿主机上持续的巡检噪声撑着一个老 incident；容器里的攻击告警自成 incident，不被吸收
func TestContainerBucketsApart(t *testing.T) {
	bothBatchings(t, func(t *testing.T, f *campaignFixture) {
		host := f.asset("uos-server", uuid.New(), "10.1.1.170")
		base := time.Now().Add(-3 * time.Hour)
		var noise []*ent.Alert
		for i := 0; i < 12; i++ {
			noise = append(noise, f.proc(host, base.Add(time.Duration(i)*5*time.Minute), "recon", 3, "", "whoami"))
		}
		attack := f.proc(host, base.Add(52*time.Minute), "python-b64", 4, "4f173e0d45b0", "python3 -c import base64")
		later := f.proc(host, base.Add(53*time.Minute), "recon", 3, "4f173e0d45b0", "uname -a")
		hostLater := f.proc(host, base.Add(56*time.Minute), "recon", 3, "", "whoami")
		f.flush()

		old := f.incidentOf(noise[0])
		for _, al := range noise {
			if f.incidentOf(al).ID != old.ID {
				t.Fatal("宿主机上 5 分钟一次的同级告警应连成一个 incident")
			}
		}
		if f.incidentOf(attack).ID == old.ID || f.incidentOf(later).ID != f.incidentOf(attack).ID {
			t.Error("容器里的告警应自成 incident，且同容器的后续告警并入")
		}
		if f.incidentOf(hostLater).ID != old.ID {
			t.Error("宿主机自身的告警仍按资产归并")
		}
	})
}

// 低危重复只并入、不续期：窗口锚点停在最后一条有意义的告警，过了窗口的有意义告警另开 incident
func TestLowSeverityDoesNotRenew(t *testing.T) {
	bothBatchings(t, func(t *testing.T, f *campaignFixture) {
		host := f.asset("dev", uuid.New())
		base := time.Now().Add(-3 * time.Hour)
		first := f.proc(host, base, "recon", 3, "", "id")
		var probes []*ent.Alert
		for i := 1; i <= 8; i++ {
			probes = append(probes, f.proc(host, base.Add(time.Duration(i)*5*time.Minute), "probe", 2, "", fmt.Sprintf("bash -c </dev/tcp/127.0.0.1/%d", 8000+i)))
		}
		attack := f.proc(host, base.Add(45*time.Minute), "nohup", 3, "", "nohup python3 p8.py")
		f.flush()

		inc := f.incidentOf(first)
		for i, al := range probes {
			// 锚点停在 first：30 分钟内的并入，之后的低危自己开一个（第一条即锚点），后续低危跟着它。
			// 端口各不相同：同一条命令行的重复会按复发并回，那是另一条路
			in := f.incidentOf(al).ID == inc.ID
			if want := i < 6; in != want {
				t.Errorf("第 %d 条低危重复并入老 incident=%v，期望 %v", i+1, in, want)
			}
		}
		if f.incidentOf(attack).ID == inc.ID {
			t.Error("有意义的告警超出最后一条有意义告警的时间窗，不应被低危重复续期的 incident 吸收")
		}
		if f.incidentOf(attack).ID != f.incidentOf(probes[6]).ID {
			t.Error("新开 incident 的第一条告警就是锚点，窗口内的有意义告警应并入")
		}
	})
}

// 高危不挂到 AI 已判良性的 incident 上；普通告警照常并入
func TestHighRiskSkipsBenign(t *testing.T) {
	f := newCampaignFixture(t, true)
	host := f.asset("gw", uuid.New())
	base := time.Now().Add(-time.Hour)
	first := f.proc(host, base, "recon", 3, "", "id")
	inc := f.incidentOf(first)
	f.client.Incident.UpdateOneID(inc.ID).SetStatus("triaged").SetTriagedAt(time.Now()).
		SetAiVerdict(json.RawMessage(`{"verdict":"benign"}`)).ExecX(f.ctx)
	low := f.proc(host, base.Add(time.Minute), "recon", 3, "", "uname -a")
	high := f.proc(host, base.Add(2*time.Minute), "python-b64", 4, "", "python3 -c x")
	if f.incidentOf(low).ID != inc.ID {
		t.Error("普通告警应照常并入良性 incident")
	}
	if f.incidentOf(high).ID == inc.ID {
		t.Error("高危告警不应挂到已判良性的 incident 上")
	}
}

// 受害方证据：登录失败的来源是另一台（别组的）纳管主机，并进源主机级别最高的 incident，图上记横向边；
// 多台主机共用的地址认不出是谁，不认
func TestVictimSideLateral(t *testing.T) {
	bothBatchings(t, func(t *testing.T, f *campaignFixture) {
		uos := f.asset("uos-server", uuid.New(), "10.1.1.170", "172.17.0.1")
		node1 := f.asset("openxdr-node1", uuid.New(), "10.1.1.198", "172.17.0.1")
		base := time.Now().Add(-time.Hour)
		noise := f.proc(uos, base, "recon", 3, "", "whoami")
		attack := f.proc(uos, base.Add(2*time.Minute), "python-b64", 4, "4f173e0d45b0", "python3 -c x")
		noiseLater := f.proc(uos, base.Add(5*time.Minute), "recon", 3, "", "whoami")
		// 共用地址：node1 自己没有别的告警时认不出来源，自成 incident
		shared := f.loginFailure(node1, base.Add(3*time.Minute), "login-failure-docker", 3, "172.17.0.1")
		spray := f.loginFailure(node1, base.Add(8*time.Minute), "login-failure", 3, "10.1.1.170")
		after := f.proc(node1, base.Add(9*time.Minute), "recon", 3, "", "id")
		f.flush()

		target := f.incidentOf(attack)
		if f.incidentOf(noise).ID == target.ID || f.incidentOf(noiseLater).ID == target.ID {
			t.Fatal("宿主机噪声与容器攻击应分开")
		}
		if f.incidentOf(spray).ID != target.ID {
			t.Fatal("受害方登录失败应并进源主机级别最高的 incident")
		}
		if f.incidentOf(shared).ID == target.ID {
			t.Error("多台主机共用的地址不应认作横向来源")
		}
		if f.incidentOf(after).ID != target.ID {
			t.Error("受害主机随后的告警应沿时间窗留在攻击 incident 里")
		}
		var g Graph
		if err := json.Unmarshal(f.client.Incident.GetX(f.ctx, target.ID).Graph, &g); err != nil {
			t.Fatal(err)
		}
		lateral := 0
		for _, e := range g.Edges {
			if e.Rel == "lateral" {
				lateral++
				if e.From != "asset:"+uos.ID.String() || e.To != "asset:"+node1.ID.String() {
					t.Errorf("横向边方向不对：%+v", e)
				}
			}
		}
		if lateral != 1 {
			t.Errorf("应只有一条 uos-server → node1 的横向边，实际 %d：%s", lateral, strings.TrimSpace(string(f.client.Incident.GetX(f.ctx, target.ID).Graph)))
		}
	})
}
