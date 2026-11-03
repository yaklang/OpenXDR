//go:build integration

package triage

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/testdb"
)

// 长期 incident：大量早期低危噪声，后期另一个容器里出现少量高危告警。
// 明细要选出后期的高危告警、每条规则至少一条、每台主机与容器至少一条；失败减半后仍按级别优先覆盖。
func TestBuildContextSamplesSevereAndDiverse(t *testing.T) {
	ctx, client := testdb.New(t)
	host := client.Asset.Create().SetHostname("uos-server").SaveX(ctx)
	other := client.Asset.Create().SetHostname("node1").SaveX(ctx)
	inc := client.Incident.Create().SetStatus("open").SetTitle("长期事件").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	start := time.Now().Add(-72 * time.Hour).Truncate(time.Second)

	add := func(asset uuid.UUID, at time.Time, rule string, sev int16, raw string) {
		ev := client.Event.Create().SetTs(at).SetClassUID(1007).SetSource("agent").SetAssetID(asset).
			SetRaw(json.RawMessage(raw)).SaveX(ctx)
		client.Alert.Create().SetTs(at).SetRuleID(rule).SetSeverity(sev).SetAssetID(asset).
			SetEventID(ev.ID).SetIncidentID(inc.ID).SaveX(ctx)
	}
	for i := range 200 {
		add(host.ID, start.Add(time.Duration(i)*time.Minute), "noise-health", 2,
			fmt.Sprintf(`{"container":{"uid":"aaaaaaaaaaaa1111","name":"web"},"process":{"cmd_line":"health-%d"}}`, i))
	}
	for i := range 100 {
		add(host.ID, start.Add(time.Duration(i)*time.Minute+30*time.Second), "noise-inspect", 1,
			fmt.Sprintf(`{"process":{"cmd_line":"inspect-%d"}}`, i))
	}
	add(other.ID, start.Add(10*time.Minute), "noise-inspect", 1, `{"process":{"cmd_line":"node1-inspect"}}`)
	late := start.Add(60 * time.Hour)
	for i := range 3 {
		add(host.ID, late.Add(time.Duration(i)*time.Minute), "attack-recon", 4,
			fmt.Sprintf(`{"container":{"uid":"bbbbbbbbbbbb2222","name":"jump"},"process":{"cmd_line":"attack-recon-%d"}}`, i))
	}
	add(host.ID, late.Add(5*time.Minute), "attack-escape", 5,
		`{"container":{"uid":"bbbbbbbbbbbb2222","name":"jump"},"process":{"cmd_line":"attack-escape"}}`)
	// 攻击之后噪声还在继续
	for i := range 60 {
		add(host.ID, late.Add(time.Duration(10+i)*time.Minute), "noise-health", 2,
			fmt.Sprintf(`{"container":{"uid":"aaaaaaaaaaaa1111","name":"web"},"process":{"cmd_line":"late-health-%d"}}`, i))
	}

	e := &Engine{DB: client}
	out, err := e.buildContext(ctx, inc)
	if err != nil {
		t.Fatal(err)
	}
	details := out[strings.Index(out, "## 告警明细"):]
	for _, want := range []string{"告警明细（50 条，共 365 条", "明细是抽样", "attack-recon-0", "attack-recon-1", "attack-recon-2", "attack-escape",
		"node1-inspect", "rule=noise-inspect", "rule=noise-health", "container=jump(bbbbbbbbbbbb…)", "container=web(aaaaaaaaaaaa…)"} {
		if !strings.Contains(details, want) {
			t.Errorf("明细缺少 %q：\n%s", want, details)
		}
	}
	if strings.Contains(details, `"health-0"`) {
		t.Errorf("最早的低危噪声不该挤进明细：\n%s", details)
	}
	for _, want := range []string{"- noise-health：260 条告警", "- noise-inspect：101 条告警", "- attack-recon：3 条告警", "- attack-escape：1 条告警"} {
		if !strings.Contains(out, want) {
			t.Errorf("汇总应是全量，缺少 %q", want)
		}
	}
	if strings.Index(details, "attack-recon-0") > strings.Index(details, "attack-escape") {
		t.Errorf("明细应按时间排序：\n%s", details)
	}

	// 失败四次只剩 5 条：最高级别、每条规则、每台主机、每个容器仍各有一条
	inc.TriageFailures = 4
	out, err = e.buildContext(ctx, inc)
	if err != nil {
		t.Fatal(err)
	}
	details = out[strings.Index(out, "## 告警明细"):]
	for _, want := range []string{"告警明细（5 条", "attack-escape", "rule=attack-recon", "rule=noise-health", "rule=noise-inspect",
		"node1-inspect", "container=jump(", "container=web("} {
		if !strings.Contains(details, want) {
			t.Errorf("预算减半后明细缺少 %q：\n%s", want, details)
		}
	}
}

// 重研判的新增明细：先每条规则一条，再按级别补，不被同一条高频规则占满
func TestRetriageFreshDiverseRules(t *testing.T) {
	ctx, client := testdb.New(t)
	host := client.Asset.Create().SetHostname("h1").SaveX(ctx)
	triaged := time.Now().Add(-time.Hour)
	inc := client.Incident.Create().SetStatus("triaged").SetTitle("重研判").SetGraph(json.RawMessage(`{}`)).
		SetAiVerdict(json.RawMessage(`{"verdict":"suspicious","confidence":60,"summary":"旧结论"}`)).
		SetTriageCount(3).SetTriagedAt(triaged).SaveX(ctx)
	// 告警主键是 UUIDv7，「新增」按入库时间判断：下面这些都在上次研判之后入库
	client.Alert.Create().SetTs(time.Now()).SetRuleID("rare").SetSeverity(2).SetAssetID(host.ID).SetIncidentID(inc.ID).SaveX(ctx)
	for range 20 {
		client.Alert.Create().SetTs(time.Now()).SetRuleID("repeat").SetSeverity(3).SetAssetID(host.ID).SetIncidentID(inc.ID).SaveX(ctx)
	}
	out, err := (&Engine{DB: client}).buildContext(ctx, inc)
	if err != nil {
		t.Fatal(err)
	}
	from := strings.Index(out, "### 新增告警明细")
	if from < 0 {
		t.Fatalf("缺少新增明细：\n%s", out)
	}
	fresh := out[from:strings.Index(out, "## 告警明细")]
	if !strings.Contains(fresh, "新增告警明细（10 条") || !strings.Contains(fresh, "rule=rare") || strings.Count(fresh, "rule=repeat") != 9 {
		t.Errorf("新增明细应先覆盖每条规则再按级别补：\n%s", fresh)
	}
}
