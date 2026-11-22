// Package dedup 告警去重：风暴防线第一层。
// agent、sensor、syslog 三条接入路径共用，任何一条漏掉都是灌爆告警表的口子。
package dedup

import (
	"context"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/incident"
)

// Deduper 窗口内同指纹的告警只留一行，后续命中累加计数。
// 一次端口扫描或暴力破解能触发上万次规则命中，落成上万行告警就是自己制造事件风暴。
type Deduper struct {
	window time.Duration
	seen   map[string]*entry
	maxTs  time.Time
	now    func() time.Time
}

type entry struct {
	alertID   uuid.UUID
	firstTs   time.Time
	lastTs    time.Time
	trackedAt time.Time
	pending   int
}

func New(window time.Duration) *Deduper {
	return &Deduper{window: window, seen: map[string]*entry{}, now: time.Now}
}

func (d *Deduper) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

func (d *Deduper) advance(ts time.Time) {
	if ts.After(d.maxTs) {
		d.maxTs = ts
	}
}

// Hit 记录一次命中。返回 true 表示落在已有告警的窗口内，调用方不应再建新告警。
func (d *Deduper) Hit(fingerprint string, ts time.Time) bool {
	d.advance(ts)
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
	d.advance(ts)
	d.seen[fingerprint] = &entry{alertID: alertID, firstTs: ts, lastTs: ts, trackedAt: d.clock()}
}

// Flush 把累积的计数写回数据库，并清理已刷盘且超过去重窗口的过期条目，防止长连接内存无限增长。
func (d *Deduper) Flush(ctx context.Context, db *ent.Client) error {
	now := d.clock()
	for fp, e := range d.seen {
		if e.pending > 0 {
			a, err := db.Alert.UpdateOneID(e.alertID).
				AddCount(e.pending).
				SetLastTs(e.lastTs).
				Save(ctx)
			if err != nil {
				return err
			}
			// 指纹只到规则加主机，研判之后并进来的命中可能是研判没看过的另一条命令：
			// 记成新证据让研判重看，不然事件既不重研判、也进不了良性结案，就此挂住
			if a.IncidentID != nil {
				// 首次研判进行中（还是 open）并进来的命中同样要记：研判落库的 triaged_at 是开始时刻，晚到的命中它没看过
				if err := db.Incident.Update().
					Where(incident.IDEQ(*a.IncidentID), incident.Or(
						incident.And(incident.StatusEQ("triaged"), incident.TriagedAtLT(e.lastTs)),
						incident.And(incident.StatusEQ("open"), incident.TriageStartedAtNotNil()))).
					SetEvidenceAt(now).ClearClosureProposal().
					Exec(ctx); err != nil {
					return err
				}
			}
			e.pending = 0
		}
		if e.pending == 0 && d.expired(e, now) {
			delete(d.seen, fp)
		}
	}
	return nil
}

func (d *Deduper) expired(e *entry, now time.Time) bool {
	if d.window <= 0 {
		return true
	}
	return now.Sub(e.trackedAt) >= d.window || d.maxTs.Sub(e.firstTs) >= d.window
}
