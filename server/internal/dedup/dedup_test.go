package dedup

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// 风暴防线第一层：窗口内同指纹归并为一列告警，跨窗口再开新桶。

func TestDeduperWindow(t *testing.T) {
	d := New(10 * time.Minute)
	fp := "rule:abc:host:1.2.3.4"

	// 首次命中：建新告警
	if d.Hit(fp, t0()) {
		t.Fatal("首个命中应建新告警（返回 false）")
	}
	alertID := uuid.New()
	d.Track(fp, alertID, t0())

	// 窗口内命中：归并
	if !d.Hit(fp, t0().Add(5*time.Minute)) {
		t.Fatal("窗口内命中应归并（返回 true）")
	}

	// 恰好等于窗口，视为过期，重建
	if d.Hit(fp, t0().Add(10*time.Minute)) {
		t.Fatal("ts-firstTs >= window 应视为跨窗口，重建")
	}

	// 不同的指纹互不影响
	if d.Hit("other-fp", t0()) {
		t.Fatal("不同指纹应独立建桶")
	}
}

func TestDeduperLastTsUpdated(t *testing.T) {
	d := New(time.Hour)
	fp := "fp"
	d.Track(fp, uuid.New(), t0())
	late := t0().Add(8 * time.Minute)
	d.Hit(fp, late)
	e, ok := d.seen[fp]
	if !ok {
		t.Fatal("tracked 指纹应存在")
	}
	if !e.lastTs.Equal(late) {
		t.Errorf("窗口内命中应更新 lastTs，得到 %v want %v", e.lastTs, late)
	}
	// 更早的命中不把 lastTs 往回拉
	earlier := t0().Add(2 * time.Minute)
	d.Hit(fp, earlier)
	if e.lastTs.Before(late) {
		t.Errorf("lastTs 不应被更早命中拉低，得到 %v", e.lastTs)
	}
}

func TestDeduperPendingCounts(t *testing.T) {
	d := New(time.Hour)
	fp := "fp"
	alertID := uuid.New()
	d.Track(fp, alertID, t0())

	now := t0()
	for i := 0; i < 3; i++ {
		d.Hit(fp, now.Add(time.Duration(i)*time.Minute))
	}
	if d.seen[fp].pending != 3 {
		t.Errorf("窗口内 3 次命中应累计 pending=3，得到 %d", d.seen[fp].pending)
	}
	// 只有 pending > 0 的桶才算有东西要写
	if d.seen["fresh"] != nil {
		t.Error("track 前不应出现无关桶")
	}
}

func TestDeduperTrackOverwrites(t *testing.T) {
	d := New(time.Hour)
	d.Track("fp", uuid.New(), t0())
	// 重建时 track 覆盖旧 entry，重置 pending
	d.Track("fp", uuid.New(), t0().Add(2*time.Hour))
	if d.seen["fp"].pending != 0 {
		t.Errorf("重建 track 应重置 pending，得到 %d", d.seen["fp"].pending)
	}
}

func t0() time.Time { return time.Unix(1_700_000_000, 0) }
