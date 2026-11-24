package maintenance

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWindowAndParse(t *testing.T) {
	start, end, err := ParseWindow("02:00-05:00")
	if err != nil || start != 2*time.Hour || end != 5*time.Hour {
		t.Fatal(start, end, err)
	}
	for _, bad := range []string{"05:00-02:00", "2-5", "02:00"} {
		if _, _, err := ParseWindow(bad); err == nil {
			t.Fatalf("%s 应拒绝", bad)
		}
	}
	sh := time.FixedZone("CST", 8*3600)
	c := Config{Start: start, End: end, Location: sh}
	if r := c.remaining(time.Date(2026, 11, 10, 3, 30, 0, 0, sh)); r != 90*time.Minute {
		t.Fatalf("3:30 应剩 90 分钟：%v", r)
	}
	if c.remaining(time.Date(2026, 11, 10, 5, 0, 0, 0, sh)) != 0 || c.remaining(time.Date(2026, 11, 10, 1, 59, 0, 0, sh)) != 0 {
		t.Fatal("窗口外应为 0")
	}
	// UTC 18:30 是北京时间 2:30
	if c.remaining(time.Date(2026, 11, 9, 18, 30, 0, 0, time.UTC)) != 150*time.Minute {
		t.Fatal("按维护时区算")
	}
	boot, reboot, failed, cs := parse("Installing...\nBOOT_ID abc-1\nREBOOT_REQUIRED\nCONTAINERS nats server \n")
	if boot != "abc-1" || !reboot || failed != "" || strings.Join(cs, ",") != "nats,server" {
		t.Fatal(boot, reboot, failed, cs)
	}
	if got := absent([]string{"nats", "server", "web"}, []string{"server", "web"}); strings.Join(got, ",") != "nats" {
		t.Fatal(got)
	}
	if _, _, failed, _ := parse("UPGRADE_FAILED 1\nBOOT_ID x\n"); failed == "" {
		t.Fatal("要报出更新失败")
	}
}

func TestStartedIn(t *testing.T) {
	got := startedIn("BOOT_ID x\nSTARTED soulstream-pg\nSTARTED source-sentinel-mysql-1\nCONTAINERS a b\n")
	if len(got) != 2 || got[0] != "soulstream-pg" || got[1] != "source-sentinel-mysql-1" {
		t.Fatal(got)
	}
	if startedIn("BOOT_ID x\nCONTAINERS a\n") != nil {
		t.Fatal("没拉起任何容器时应为空")
	}
}

func TestPatroniClientDisablesProxy(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxy.Close()

	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	c := (&Patroni{}).client()
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr == nil {
		t.Fatalf("Patroni 默认客户端应显式配置 *http.Transport，实际：%T", c.Transport)
	}
	if tr.Proxy != nil {
		t.Fatal("Patroni 默认 Transport 必须禁用 Proxy，避免内网凭据经 HTTP_PROXY 外泄")
	}
	// 验证实际发出请求不经过环境代理
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	resp, err := c.Get(target.URL + "/patroni")
	if err != nil {
		t.Fatalf("直连目标失败：%v", err)
	}
	resp.Body.Close()
	if proxyHits.Load() != 0 {
		t.Fatalf("Patroni 请求不应经过环境代理，命中次数：%d", proxyHits.Load())
	}
}
