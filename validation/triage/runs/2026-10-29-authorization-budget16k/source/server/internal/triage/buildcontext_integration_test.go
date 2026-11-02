//go:build integration

package triage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/internal/testdb"
)

// buildContext 生成给 LLM 的研判上下文：标题、图、按时间排序的告警明细，
// 超长事件原文截断。
func TestBuildContext(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()

	// 超长事件原文（>500，应截断加省略号）
	longRaw := json.RawMessage(`{"process":{"name":"` + strings.Repeat("x", 600) + `"}}`)
	evt1, err := client.Event.Create().
		SetTs(now.Add(-2 * time.Minute)).SetClassUID(1007).SetSource("agent").
		SetRaw(longRaw).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	evt2, err := client.Event.Create().
		SetTs(now.Add(-time.Minute)).SetClassUID(1007).SetSource("agent").
		SetRaw(json.RawMessage(`{"process":{"name":"parent.exe"}}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	title := "SSH brute force"
	inc, err := client.Incident.Create().
		SetStatus("open").SetTitle(title).SetGraph(json.RawMessage(`{"nodes":[]}`)).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(now).SetRuleID("r-loud").SetSeverity(4).SetCount(3).
		SetEventID(evt1.ID).SetIncidentID(inc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Alert.Create().
		SetTs(now).SetRuleID("r-quiet").SetSeverity(2).
		SetEventID(evt2.ID).SetIncidentID(inc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	// 复发归并进来的同类告警：汇总里要能看到重复次数
	if _, err := client.Alert.Create().
		SetTs(now.Add(time.Hour)).SetRuleID("r-quiet").SetSeverity(2).
		SetEventID(evt2.ID).SetIncidentID(inc.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}

	e := &Engine{DB: client}
	out, err := e.buildContext(ctx, inc)
	if err != nil {
		t.Fatalf("buildContext 失败: %v", err)
	}
	for _, want := range []string{
		title,          // 标题
		`{"nodes":[]}`, // 图
		"r-loud", "r-quiet", "severity=4", "count=3",
		"parent.exe", // 未截断事件原文
		"…",          // 超长事件截断标记
		"- r-quiet：2 条告警（去重前累计命中 2 次）\n- r-loud：1 条告警（去重前累计命中 3 次）", // 按规则汇总，多的在前
	} {
		if !strings.Contains(out, want) {
			t.Errorf("上下文缺少 %q，实际:\n%s", want, out)
		}
	}
}

// 同规则或同主机的人工结案回流进上下文，带 AI 当时的判断与备注；无关事件不出现。
func TestBuildContextCaseHistory(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	host := client.Asset.Create().SetHostname("h1").SaveX(ctx)
	other := client.Asset.Create().SetHostname("h2").SaveX(ctx)
	mk := func(status, title, verdict, note, rule string, asset uuid.UUID) {
		c := client.Incident.Create().SetStatus(status).SetTitle(title).SetGraph(json.RawMessage(`{}`)).SetResolvedBy("analyst").SetResolvedAt(now)
		if verdict != "" {
			c.SetAiVerdict(json.RawMessage(`{"verdict":"` + verdict + `"}`))
		}
		if note != "" {
			c.SetResolution(note)
		}
		inc := c.SaveX(ctx)
		client.Alert.Create().SetTs(now.Add(-24 * time.Hour)).SetRuleID(rule).SetSeverity(3).
			SetAssetID(asset).SetIncidentID(inc.ID).SaveX(ctx)
	}
	mk("false_positive", "扫描器噪声", "malicious", "运维巡检脚本", "r-noisy", other.ID)
	mk("closed", "同机真入侵", "benign", "已确认被植入后门并重装", "r-other", host.ID)
	mk("triaged", "未结案的", "benign", "", "r-noisy", host.ID)
	mk("closed", "无关事件", "", "", "r-unrelated", other.ID)

	inc := client.Incident.Create().SetStatus("open").SetTitle("新事件").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("r-noisy").SetSeverity(3).SetAssetID(host.ID).SetIncidentID(inc.ID).SaveX(ctx)

	out, err := (&Engine{DB: client}).buildContext(ctx, inc)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"历史结案参考", `"title":"扫描器噪声"`, `"previous_ai_verdict":"malicious"`, `"resolution_excerpt":"运维巡检脚本"`,
		`"title":"同机真入侵"`, `"previous_ai_verdict":"benign"`, `"resolution_excerpt":"已确认被植入后门并重装"`, `"source":"human"`, `"resolved_by":"analyst"`} {
		if !strings.Contains(out, want) {
			t.Errorf("上下文缺少 %q：\n%s", want, out)
		}
	}
	for _, bad := range []string{"未结案的", "无关事件", "「新事件」："} {
		if strings.Contains(out, bad) {
			t.Errorf("不该出现 %q：\n%s", bad, out)
		}
	}

	lone := client.Incident.Create().SetStatus("open").SetTitle("另一事件").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	loneHost := client.Asset.Create().SetHostname("no-history").SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("r-clean").SetSeverity(3).SetAssetID(loneHost.ID).SetIncidentID(lone.ID).SaveX(ctx)
	out2, err := (&Engine{DB: client}).buildContext(ctx, lone)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out2, "本次返回 0 条") || !strings.Contains(out2, "未返回不代表不存在其他人工确认或工单") || strings.Contains(out2, `"source":"human"`) {
		t.Errorf("空查询必须保留覆盖范围，不伪造人工案例：\n%s", out2)
	}
}

// 告警里的公网地址带上平台缓存的背景：情报命中的地址与事件两端都算，离线库与 VirusTotal 分开写；没缓存的不写
func TestBuildContextIPInfo(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	client.IPInfo.Create().SetIP("203.0.113.7").SetIpdbAsn(64500).SetIpdbOrg("Example Net A").SetIpdbCountry("AU").SetIpdbAt(now).SaveX(ctx)
	client.IPInfo.Create().SetIP("198.51.100.44").SetPtr("scan.example.net").SetAsOwner("Some ISP").SetAsn(64501).SetCountry("RU").
		SetMalicious(3).SetVtAt(now).SaveX(ctx)
	client.IPInfo.Create().SetIP("192.0.2.99").SetIpdbAsn(64999).SetIpdbAt(now).SaveX(ctx) // 与本事件无关
	ev := client.Event.Create().SetTs(now).SetClassUID(4001).SetSource("agent").
		SetRaw(json.RawMessage(`{"src_endpoint":{"ip":"198.51.100.44"},"dst_endpoint":{"ip":"10.0.0.5"}}`)).SaveX(ctx)
	inc := client.Incident.Create().SetStatus("open").SetTitle("外联").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("intel:ip:203.0.113.7").SetSeverity(3).SetIncidentID(inc.ID).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("ssh-brute").SetSeverity(3).SetEventID(ev.ID).SetIncidentID(inc.ID).SaveX(ctx)

	out, err := (&Engine{DB: client}).buildContext(ctx, inc)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## 公网地址背景", "- 203.0.113.7：离线库 AS64500 Example Net A，国家 AU",
		"- 198.51.100.44：反查 scan.example.net；VirusTotal AS64501 Some ISP，国家 RU，3 个引擎判恶意、0 个可疑"} {
		if !strings.Contains(out, want) {
			t.Errorf("上下文缺少 %q：\n%s", want, out)
		}
	}
	if strings.Contains(out, "192.0.2.99") {
		t.Errorf("无关地址不该出现：\n%s", out)
	}
}

func TestCaseHistoryRequiresRecordedHumanProvenance(t *testing.T) {
	ctx, client := testdb.New(t)
	now := time.Now()
	host := client.Asset.Create().SetHostname("source-host").SaveX(ctx)
	current := client.Incident.Create().SetTitle("当前事件").SetGraph(json.RawMessage(`{}`)).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("same-rule").SetSeverity(3).SetAssetID(host.ID).SetIncidentID(current.ID).SaveX(ctx)
	for _, name := range []string{"人工独立结案", "结案人缺失", "结案人为空", "结案人空白", "时间缺失", "备注缺失", "备注空白", "系统结案", "采纳AI研判", "采纳AI建议"} {
		builder := client.Incident.Create().SetTitle(name).SetStatus("false_positive").SetGraph(json.RawMessage(`{}`))
		if name != "结案人缺失" {
			by := "analyst"
			switch name {
			case "结案人为空":
				by = ""
			case "结案人空白":
				by = "  "
			case "系统结案":
				by = "system"
			}
			builder.SetResolvedBy(by)
		}
		if name != "时间缺失" {
			builder.SetResolvedAt(now)
		}
		if name != "备注缺失" {
			note := "人工确认本次操作"
			if name == "备注空白" {
				note = "  "
			}
			builder.SetResolution(note)
		}
		switch name {
		case "采纳AI研判":
			builder.SetResolutionSource("ai_verdict")
		case "采纳AI建议":
			builder.SetResolutionSource("ai_proposal")
		}
		c := builder.SaveX(ctx)
		client.Alert.Create().SetTs(now).SetRuleID("same-rule").SetSeverity(3).SetAssetID(host.ID).SetIncidentID(c.ID).SaveX(ctx)
	}
	out, err := (&Engine{DB: client}).buildContext(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"title":"人工独立结案"`) || strings.Count(out, `"source":"human"`) != 1 {
		t.Fatalf("人工来源筛选错误: %s", out)
	}
	for _, bad := range []string{"结案人缺失", "结案人为空", "结案人空白", "时间缺失", "备注缺失", "备注空白", "系统结案", "采纳AI研判", "采纳AI建议"} {
		if strings.Contains(out, bad) {
			t.Fatalf("未知或AI来源被升级为人工确认: %s", bad)
		}
	}
}

func TestCaseHistoryQueryFailureIsUnknown(t *testing.T) {
	ctx, client := testdb.New(t)
	client.Close()
	var out strings.Builder
	(&Engine{DB: client}).appendCaseHistory(ctx, &out, &ent.Incident{ID: uuid.New()}, []*ent.Alert{{RuleID: "same-rule"}})
	if !strings.Contains(out.String(), "查询失败，覆盖未知") || strings.Contains(out.String(), "本次返回 0 条") || strings.Contains(out.String(), `"source":"human"`) {
		t.Fatalf("查询失败不能变成人工记录不存在: %s", out.String())
	}
}
