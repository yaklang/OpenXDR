package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/ent"
)

func incidentAt(created time.Time, status string, verdictJSON string) *ent.Incident {
	inc := &ent.Incident{CreatedAt: created, Status: status}
	if verdictJSON != "" {
		inc.AiVerdict = json.RawMessage(verdictJSON)
	}
	return inc
}

// retriage 已研判 incident 之后又并入了证据：urgent 为升级类，failures 为重研判连续失败次数
func retriage(verdictJSON string, urgent bool, failures int) *ent.Incident {
	inc := incidentAt(time.Now(), "triaged", verdictJSON)
	triaged, later := time.Now().Add(-10*time.Minute), time.Now()
	inc.TriagedAt, inc.EvidenceAt, inc.TriageFailures = &triaged, &later, failures
	if urgent {
		inc.UrgentAt = &later
	}
	return inc
}

func TestDecide(t *testing.T) {
	n := &Notifier{start: time.Now().Add(-time.Hour), WaitTriage: func() bool { return true }}
	fresh := time.Now()

	cases := []struct {
		name string
		inc  *ent.Incident
		sev  int16
		send bool
		why  string
	}{
		{"历史事件跳过", incidentAt(n.start.Add(-time.Minute), "open", ""), 3, false, "历史事件不补发"},
		{"已关闭跳过", incidentAt(fresh, "closed", ""), 3, false, "已人工处理"},
		{"误报跳过", incidentAt(fresh, "false_positive", ""), 3, false, "已人工处理"},
		{"未研判等待", incidentAt(fresh, "open", ""), 3, false, "wait"},
		{"升级重开等重新研判", incidentAt(fresh, "open", `{"verdict":"benign"}`), 4, false, "wait"},
		{"良性静默", incidentAt(fresh, "triaged", `{"verdict":"benign"}`), 3, false, "AI 判定良性"},
		{"高危良性仍推送待复核", incidentAt(fresh, "triaged", `{"verdict":"benign"}`), 4, true, ""},
		{"恶意推送", incidentAt(fresh, "triaged", `{"verdict":"malicious","confidence":90}`), 3, true, ""},
		{"可疑推送", incidentAt(fresh, "triaged", `{"verdict":"suspicious"}`), 3, true, ""},
		{"研判无法解析也推送", incidentAt(fresh, "triaged", `{"error":"unparseable"}`), 3, true, ""},
		// 普通新证据冷却中：旧结论仍可用，照它决定，不卡在冷却上
		{"冷却中恶意照推", retriage(`{"verdict":"malicious"}`, false, 0), 3, true, ""},
		{"冷却中良性照旧静默", retriage(`{"verdict":"benign"}`, false, 0), 3, false, "AI 判定良性"},
		// 升级类：旧结论不作数，等新结论；研判一直失败就不等了，也不拿旧良性静默
		{"升级等新结论", retriage(`{"verdict":"benign"}`, true, 0), 3, false, "wait"},
		{"升级研判屡败照推", retriage(`{"verdict":"benign"}`, true, giveUpAfter), 3, true, ""},
		{"首次研判屡败照推", func() *ent.Incident { i := incidentAt(fresh, "open", ""); i.TriageFailures = giveUpAfter; return i }(), 3, true, ""},
	}
	for _, c := range cases {
		send, why := n.decide(c.inc, c.sev)
		if send != c.send || why != c.why {
			t.Errorf("%s: want (%v,%q) got (%v,%q)", c.name, c.send, c.why, send, why)
		}
	}
}

func TestDecideNoAI(t *testing.T) {
	n := &Notifier{start: time.Now().Add(-time.Hour), WaitTriage: func() bool { return false }}
	if send, _ := n.decide(incidentAt(time.Now(), "open", ""), 1); !send {
		t.Fatal("AI 未启用时事件应立即推送")
	}
	if send, _ := n.decide(retriage(`{"verdict":"benign"}`, true, 0), 3); !send {
		t.Fatal("AI 未启用时升级的事件不能拿旧的良性结论静默")
	}
}

func TestText(t *testing.T) {
	got := text(Message{
		Title: "可疑进程链", Verdict: "malicious", Confidence: 85,
		Summary:     "存在攻击链\n第二段详细取证依据与证据限制说明",
		ActionCodes: []string{"review_response", "hunt_related"},
		QueryTools:  []string{"process_lineage", "query_events", "query_events"},
		AlertCount:  12, Severity: 4,
		Link: "http://x/?incident=abc", RuleAuthors: []string{"Florian Roth (Nextron Systems)"},
	})
	for _, want := range []string{
		"🚨【OpenXDR】可疑进程链",
		"🤖 AI 判定: 🔴 恶意（置信度 85%）",
		"🔥 最高级别: 高危（告警 12 条）",
		"📌 AI 摘要（模型判断）: 存在攻击链",
		"🔍 AI 自治取证: 已自主完成 3 轮排查（进程血缘、原始事件×2）",
		"⚡ 建议动作: 🛑 审核隔离/阻断响应 / 🎯 按指标横向排查",
		"🏷️ 规则作者: Florian Roth (Nextron Systems)",
		"🔗 处置直达: http://x/?incident=abc",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("正文缺少 %q：\n%s", want, got)
		}
	}
	if strings.Contains(got, "第二段详细取证依据") {
		t.Errorf("IM 通知不应展开次段取证长文：\n%s", got)
	}
}

func TestPayloadFormats(t *testing.T) {
	m := Message{Title: "t", AlertCount: 1}
	cases := []struct {
		format string
		want   string
	}{
		{"dingtalk", `"msgtype":"text"`},
		{"feishu", `"msg_type":"text"`},
		{"wecom", `"msgtype":"text"`},
		{"generic", `"alertCount":1`},
		{"unknown", `"alertCount":1`},
	}
	for _, c := range cases {
		b := payload(c.format, m, text(m))
		if !json.Valid(b) {
			t.Errorf("%s: 不是合法 JSON", c.format)
		}
		if !strings.Contains(string(b), c.want) {
			t.Errorf("%s: 缺少 %s：%s", c.format, c.want, b)
		}
	}
}

func TestWebhookSendText(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"errcode":0}`))
	}))
	defer srv.Close()

	h := &Webhook{}
	target := Target{URL: srv.URL, Format: "dingtalk", LinkBase: "http://x"}
	if err := h.SendTo(context.Background(), target, "每日巡检", "3 台主机正常", "/r/1"); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Text struct{ Content string } `json:"text"`
	}
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatal(err)
	}
	if v.Text.Content != "📋【OpenXDR】每日巡检\n3 台主机正常\n🔗 查看详情: http://x/r/1" {
		t.Errorf("正文不符：%q", v.Text.Content)
	}

	// 未配置 URL：静默不发，也不报错
	if err := h.SendTo(context.Background(), Target{}, "x", "", ""); err != nil {
		t.Errorf("未配置时不应报错：%v", err)
	}
}

// HTTP 200 不等于机器人接受，坏回执必须阻止上层标记已投递。
func TestWebhookReceipt(t *testing.T) {
	for _, tc := range []struct {
		name, format, body string
		status             int
		wantError          bool
	}{
		{"钉钉成功", "dingtalk", `{"errcode":0,"errmsg":"ok"}`, 200, false},
		{"企微拒绝", "wecom", `{"errcode":93000,"errmsg":"secret"}`, 200, true},
		{"企微成功", "wecom", `{"errcode":0}`, 200, false},
		{"飞书成功", "feishu", `{"code":0,"data":{}}`, 200, false},
		{"飞书拒绝", "feishu", `{"code":9499}`, 200, true},
		{"飞书旧版", "feishu", `{"StatusCode":0}`, 200, false},
		{"飞书冲突", "feishu", `{"code":0,"StatusCode":1}`, 200, true},
		{"缺状态", "dingtalk", `{}`, 200, true},
		{"空状态", "dingtalk", `{"errcode":null}`, 200, true},
		{"类型错误", "dingtalk", `{"errcode":"0"}`, 200, true},
		{"坏JSON", "dingtalk", `<html>secret</html>`, 200, true},
		{"尾部垃圾", "feishu", `{"code":0}secret`, 200, true},
		{"空回执", "wecom", ``, 204, true},
		{"超限", "wecom", strings.Repeat(" ", 65537), 200, true},
		{"通用空回执", "generic", ``, 204, false},
		{"通用自定义正文", "generic", `{"errcode":1}`, 200, false},
		{"HTTP失败", "dingtalk", `{"errcode":0}`, 503, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			err := (&Webhook{}).SendTo(context.Background(), Target{URL: srv.URL, Format: tc.format}, "测试", "", "")
			if (err != nil) != tc.wantError {
				t.Fatalf("err=%v, wantError=%v", err, tc.wantError)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatal("回执正文泄漏")
			}
		})
	}
}
