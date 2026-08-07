// Package dedup 告警去重：风暴防线第一层。
// agent、sensor、syslog 三条接入路径共用，任何一条漏掉都是灌爆告警表的口子。
package dedup

import (
	"context"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

// Deduper 窗口内同指纹的告警只留一行，后续命中累加计数。
// 一次端口扫描或暴力破解能触发上万次规则命中，落成上万行告警就是自己制造事件风暴。
type Deduper struct {
	window time.Duration
	seen   map[string]*entry
}

type entry struct {
	alertID uuid.UUID
	firstTs time.Time
	lastTs  time.Time
	pending int
}

func New(window time.Duration) *Deduper {
	return &Deduper{window: window, seen: map[string]*entry{}}
}

// Hit 记录一次命中。返回 true 表示落在已有告警的窗口内，调用方不应再建新告警。
func (d *Deduper) Hit(fingerprint string, ts time.Time) bool {
	e, ok := d.seen[fingerprint]
	if !ok || ts.Sub(e.firstTs) >= d.window {
		return false
	}
	e.pending++
	if ts.After(e.lastTs) {
		e.lastTs = ts
	}
	return true
}

// Track 登记新建的告警，作为后续同指纹命中的归并目标。
func (d *Deduper) Track(fingerprint string, alertID uuid.UUID, ts time.Time) {
	d.seen[fingerprint] = &entry{alertID: alertID, firstTs: ts, lastTs: ts}
}

// Flush 把累积的计数写回数据库。
func (d *Deduper) Flush(ctx context.Context, db *ent.Client) error {
	for _, e := range d.seen {
		if e.pending == 0 {
			continue
		}
		if err := db.Alert.UpdateOneID(e.alertID).
			AddCount(e.pending).
			SetLastTs(e.lastTs).
			Exec(ctx); err != nil {
			return err
		}
		e.pending = 0
	}
	return nil
}
