package maintenance

import (
	"strings"
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
