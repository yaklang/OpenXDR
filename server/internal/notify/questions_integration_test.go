//go:build integration

package notify

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/questions"
	"openxdr/server/internal/testdb"
)

// 待答问题每天至多一条群消息：只有数量、按主题一行与控制台链接，没有证据原文与作答令牌；没问题不发
func TestQuestionDailyDigest(t *testing.T) {
	ctx, client := testdb.New(t)
	var got []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
		_, _ = w.Write([]byte(`{"code":0,"msg":"success"}`))
	}))
	t.Cleanup(hook.Close)
	n := &Notifier{DB: client, Settings: &Settings{DB: client, Default: Target{URL: hook.URL, Format: "feishu", LinkBase: "http://console"}}, Client: hook.Client()}
	now := time.Now()
	if err := n.questionDigest(ctx, now); err != nil || len(got) != 0 {
		t.Fatal("没问题不发", err, got)
	}
	g := client.Group.Create().SetName("g").SaveX(ctx)
	for _, d := range []string{"a.gzmpc.com", "b.gzmpc.com", "example.org"} {
		if _, err := questions.Ask(ctx, client, questions.Request{Kind: "authorization", SubjectKind: "domain", Subject: d, Groups: []uuid.UUID{g.ID},
			Note: "command=/bin/sh -c 'curl evil'"}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := n.questionDigest(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.Contains(got[0], "总控待答问题：2 个") || !strings.Contains(got[0], "gzmpc[.]com") ||
		!strings.Contains(got[0], "http://console/control?tab=questions") || strings.Contains(got[0], "curl") || strings.Contains(got[0], "token") {
		t.Fatalf("应推一条只含主题与数量的汇总：%v", got)
	}
	if err := (&Notifier{DB: client, Settings: n.Settings, Client: hook.Client()}).questionDigest(ctx, now.Add(time.Hour)); err != nil || len(got) != 1 {
		t.Fatal("推送时刻存库，重启后一天内也不重复推", err, len(got))
	}
	if err := n.questionDigest(ctx, now.Add(questionsEvery+time.Minute)); err != nil || len(got) != 2 {
		t.Fatal("满一天仍有问题再推", err, len(got))
	}
}
