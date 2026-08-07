package notify

import (
	"encoding/json"
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

func TestDecide(t *testing.T) {
	n := &Notifier{start: time.Now().Add(-time.Hour), WaitTriage: true}
	fresh := time.Now()

	cases := []struct {
		name string
		inc  *ent.Incident
		send bool
		why  string
	}{
		{"历史事件跳过", incidentAt(n.start.Add(-time.Minute), "open", ""), false, "历史事件不补发"},
		{"已关闭跳过", incidentAt(fresh, "closed", ""), false, "已人工处理"},
		{"误报跳过", incidentAt(fresh, "false_positive", ""), false, "已人工处理"},
		{"未研判等待", incidentAt(fresh, "open", ""), false, "wait"},
		{"良性静默", incidentAt(fresh, "triaged", `{"verdict":"benign"}`), false, "AI 判定良性"},
		{"恶意推送", incidentAt(fresh, "triaged", `{"verdict":"malicious","confidence":90}`), true, ""},
		{"可疑推送", incidentAt(fresh, "triaged", `{"verdict":"suspicious"}`), true, ""},
		{"研判无法解析也推送", incidentAt(fresh, "triaged", `{"error":"unparseable"}`), true, ""},
	}
	for _, c := range cases {
		send, why := n.decide(c.inc)
		if send != c.send || why != c.why {
			t.Errorf("%s: want (%v,%q) got (%v,%q)", c.name, c.send, c.why, send, why)
		}
	}
}

func TestDecideNoAI(t *testing.T) {
	n := &Notifier{start: time.Now().Add(-time.Hour), WaitTriage: false}
	if send, _ := n.decide(incidentAt(time.Now(), "open", "")); !send {
		t.Fatal("AI 未启用时事件应立即推送")
	}
}

func TestText(t *testing.T) {
	got := text(Message{
		Title: "可疑进程链", Verdict: "malicious", Confidence: 85,
		Summary: "存在攻击链", AlertCount: 12, Severity: 4,
		Link: "http://x/?incident=abc",
	})
	for _, want := range []string{"可疑进程链", "恶意", "85", "12 条", "高危", "存在攻击链", "http://x/?incident=abc"} {
		if !strings.Contains(got, want) {
			t.Errorf("正文缺少 %q：\n%s", want, got)
		}
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
		b := payload(c.format, m)
		if !json.Valid(b) {
			t.Errorf("%s: 不是合法 JSON", c.format)
		}
		if !strings.Contains(string(b), c.want) {
			t.Errorf("%s: 缺少 %s：%s", c.format, c.want, b)
		}
	}
}
