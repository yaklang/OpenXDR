//go:build integration

package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

// 同一规则在窗口内只即时推第一条，其余到期合成一条汇总；恶意的从不节流，不同规则互不影响
func TestBurstDigest(t *testing.T) {
	_, client := testdb.New(t)
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
	msg := func(title, verdict string) Message {
		return Message{Title: title, Verdict: verdict, Severity: 4, Link: "http://console/?incident=" + title}
	}
	if n.hold(msg("SSH authorized_keys 持久化 @ cache", "benign"), now) {
		t.Fatal("第一条应即时推")
	}
	for _, h := range []string{"gym", "pve1"} {
		if !n.hold(msg("SSH authorized_keys 持久化 @ "+h, "suspicious"), now.Add(time.Minute)) {
			t.Fatalf("%s 应攒下", h)
		}
	}
	if n.hold(msg("SSH authorized_keys 持久化 @ x", "malicious"), now.Add(time.Minute)) {
		t.Fatal("恶意的不节流")
	}
	if n.hold(msg("敏感文件被修改 @ gym", "benign"), now.Add(time.Minute)) {
		t.Fatal("别的规则不受影响")
	}
	n.flush(context.Background(), target, now.Add(5*time.Minute))
	if len(got) != 0 {
		t.Fatal("窗口没到不该推汇总")
	}
	n.flush(context.Background(), target, now.Add(burstWindow))
	if len(got) != 1 || !strings.Contains(got[0], "又有 2 个事件") || !strings.Contains(got[0], "pve1") || !strings.Contains(got[0], "可疑 2") {
		t.Fatalf("汇总不对：%v", got)
	}
	// 汇总推完窗口重新起算：紧接着的同规则事件继续攒
	if !n.hold(msg("SSH authorized_keys 持久化 @ sentry", "benign"), now.Add(burstWindow+time.Minute)) {
		t.Fatal("汇总之后窗口内的仍应攒下")
	}
}
