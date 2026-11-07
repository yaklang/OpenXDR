package eventarchive

import (
	"github.com/google/uuid"
	"openxdr/server/internal/eventsearch"
	"testing"
	"time"
)

func TestSearchFilters(t *testing.T) {
	ts := time.Now().UTC()
	high := uuid.MustParse("00000000-0000-0000-0000-000000000003")
	low := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	user := "root"
	boundary := Event{Ts: ts, ID: high}
	m := newEventMatcher(Filter{Before: &boundary, Username: user, Fields: eventsearch.Fields{"dstIp": "1.2.3.4", "dstPort": "443"}})
	e := Event{Ts: ts, ID: low, Username: &user, Raw: []byte(`{"dst_endpoint":{"ip":"1.2.3.4","port":443}}`)}
	if !m.match(e) {
		t.Fatal("同时间更小 ID 且字段匹配的事件应命中")
	}
	e.ID = high
	if m.match(e) {
		t.Fatal("游标边界不应重复返回")
	}
	e.ID = low
	e.Ts = ts.Add(time.Second)
	if m.match(e) {
		t.Fatal("游标后的事件不应返回")
	}
	e.Ts = ts
	e.Raw = []byte(`{"dst_endpoint":{"ip":"5.6.7.8","port":443}}`)
	if m.match(e) {
		t.Fatal("目的地址不符不应命中")
	}
	e.Raw = []byte(`{"dst_endpoint":{"ip":"1.2.3.4","port":443}}`)
	e.Username = nil
	if m.match(e) {
		t.Fatal("缺用户名不应命中")
	}
}
