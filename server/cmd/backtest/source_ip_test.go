package main

import (
	"github.com/google/uuid"
	"openxdr/server/internal/temporal"
	"testing"
	"time"
)

func TestSourceIPBacktestDoesNotMixSources(t *testing.T) {
	b := repositoryBacktest(t)
	g := uuid.NullUUID{UUID: uuid.New(), Valid: true}
	a := uuid.NullUUID{UUID: uuid.New(), Valid: true}
	feed := func(n int, ip string) {
		c := candidate{id: uuid.New(), ts: time.Unix(1700000000+int64(n), 0), group: g, asset: a, sourceIP: ip, rules: []string{"d2b870a5-1c34-4738-9f35-0b49bac2cb76"}}
		if err := b.apply(c); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 10; i++ {
		ip := "192.0.2.1"
		if i%2 == 1 {
			ip = "192.0.2.2"
		}
		feed(i, ip)
	}
	s := b.stats["temporal:wazuh-gap-windows-fail-burst"]
	if s.hits != 0 {
		t.Fatal("回测混合了不同来源")
	}
	for i := 10; i < 15; i++ {
		feed(i, "::ffff:192.0.2.1")
	}
	if s.hits != 1 || s.groupBy != temporal.GroupByAssetSourceIP {
		t.Fatal("同源阈值回测未命中")
	}
	feed(16, "")
	if b.skipped["no_source_ip"] != 1 {
		t.Fatal("回测缺少来源未记缺口")
	}
}
