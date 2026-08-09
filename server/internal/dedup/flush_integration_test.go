//go:build integration

package dedup

import (
	"testing"
	"time"

	"openxdr/server/internal/testdb"
)

// Flush：把 Hit 累积的计数回写数据库告警行，并更新 last_ts。
func TestDeduperFlush(t *testing.T) {
	ctx, client := testdb.New(t)

	alertID, err := client.Alert.Create().
		SetTs(time.Now()).SetRuleID("r-1").SetSeverity(3).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	d := New(time.Hour)
	d.Track("fp", alertID.ID, time.Now())
	now := time.Now()
	d.Hit("fp", now.Add(5*time.Second))
	d.Hit("fp", now.Add(10*time.Second))
	d.Hit("fp", now.Add(15*time.Second))

	if err := d.Flush(ctx, client); err != nil {
		t.Fatal(err)
	}

	got, err := client.Alert.Get(ctx, alertID.ID)
	if err != nil {
		t.Fatal(err)
	}
	// count 默认 1（首条命中本体），再加 3 次窗口内命中 = 4
	if got.Count != 4 {
		t.Errorf("count = %d, want 4（本体 1 + 窗口内 3）", got.Count)
	}
	// last_ts 就是最后一次 Hit 的时间戳（Postgres 微秒精度，容忍纳秒舍入差）
	want := now.Add(15 * time.Second)
	if got.LastTs == nil || got.LastTs.Sub(want) > time.Microsecond || want.Sub(*got.LastTs) > time.Microsecond {
		t.Errorf("last_ts 应为最后一次命中时间，实际 %v", got.LastTs)
	}

	// 再次 Flush，pending 已清零不再重复计数
	d.Flush(ctx, client)
	got2, _ := client.Alert.Get(ctx, alertID.ID)
	if got2.Count != 4 {
		t.Errorf("重复 Flush 不应二次计数，count = %d, want 4", got2.Count)
	}
}
