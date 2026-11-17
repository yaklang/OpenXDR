//go:build integration

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

	"openxdr/server/ent/schema"
	"openxdr/server/internal/review"
	"openxdr/server/internal/testdb"
)

// AI 判良性但高危告警没有事实兜底：要人确认，却不逐条推，按天合成一条汇总
func TestSevereBenignDailyDigest(t *testing.T) {
	ctx, client := testdb.New(t)
	var got []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
		_, _ = w.Write([]byte(`{"code":0,"msg":"success"}`))
	}))
	t.Cleanup(hook.Close)
	target := Target{URL: hook.URL, Format: "feishu", LinkBase: "http://console"}
	n := &Notifier{DB: client, Settings: &Settings{DB: client, Default: target}, Client: hook.Client()}
	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	inc := client.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SetCreatedAt(now).SetTriagedAt(now).
		SetTitle("Linux Webshell 特征 @ web").SetAiVerdict(json.RawMessage(`{"verdict":"benign","summary":"运维脚本"}`)).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("r").SetSeverity(4).SetIncidentID(inc.ID).ExecX(ctx)
	if err := n.sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || client.Incident.GetX(ctx, inc.ID).NotifiedAt == nil {
		t.Fatalf("不应逐条推，但要落投递标记：%v", got)
	}
	if err := n.severeBenignDigest(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.Contains(got[0], "高危良性待确认：1 个事件") || !strings.Contains(got[0], "Linux Webshell 特征 @ web") {
		t.Fatalf("应推一条汇总：%v", got)
	}
	if err := n.severeBenignDigest(ctx, now.Add(time.Hour)); err != nil || len(got) != 1 {
		t.Fatal("一天之内不重复推", err, len(got))
	}
	// 进程重启后计时存在库里，不从头算
	fresh := &Notifier{DB: client, Settings: n.Settings, Client: hook.Client()}
	if err := fresh.severeBenignDigest(ctx, now.Add(2*time.Hour)); err != nil || len(got) != 1 {
		t.Fatal("重启后也不应重复推", err, len(got))
	}
	if err := fresh.severeBenignDigest(context.Background(), now.Add(severeBenignEvery+time.Minute)); err != nil || len(got) != 2 {
		t.Fatal("满一天应再推", err, len(got))
	}
}

// 结案审计确定结不掉、已转人工的事件进每日汇总，每行带上结不掉的原因
func TestHandedOffInDailyDigest(t *testing.T) {
	ctx, client := testdb.New(t)
	var got []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
		_, _ = w.Write([]byte(`{"code":0,"msg":"success"}`))
	}))
	t.Cleanup(hook.Close)
	target := Target{URL: hook.URL, Format: "feishu", LinkBase: "http://console"}
	n := &Notifier{DB: client, Settings: &Settings{DB: client, Default: target}, Client: hook.Client()}
	now := time.Now()
	work := &schema.IncidentWork{Version: 1, Owner: "human", Stage: "escalated", Reason: review.HandoffPrefix + "告警 54 条，超过结案审计单次上限 20 条"}
	inc := client.Incident.Create().SetStatus("triaged").SetGraph(json.RawMessage(`{}`)).SetCreatedAt(now).SetTriagedAt(now).
		SetTitle("新进程首次出现 @ raid").SetAiVerdict(json.RawMessage(`{"verdict":"benign"}`)).SetWork(work).SaveX(ctx)
	client.Alert.Create().SetTs(now).SetRuleID("xdr:new-process").SetSeverity(2).SetIncidentID(inc.ID).ExecX(ctx)
	if err := n.severeBenignDigest(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.Contains(got[0], "AI 无法自动结案：1 个事件") || !strings.Contains(got[0], "新进程首次出现 @ raid：告警 54 条") || strings.Contains(got[0], "高危良性待确认") {
		t.Fatalf("应推一条只含转人工事件的汇总：%v", got)
	}
}
