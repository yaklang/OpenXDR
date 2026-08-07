//go:build integration

package grpcsvc

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/internal/dedup"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

const dnsRule = `
id: dns-evil
title: Evil DNS
logsource:
  category: dns
detection:
  selection:
    query.hostname|contains: 'evil'
  condition: selection
`

func loadDNSRule(t *testing.T) *sigma.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dns.yml"), []byte(dnsRule), 0o644); err != nil {
		t.Fatal(err)
	}
	return sigma.LoadDir(dir)
}

// sensor.ingest 主链路：DNS 流 → class 4003 事件落库 → 归属资产 → 命中规则 → 告警；
// 同指纹重复 ingest 被去重，不新增告警。
func TestSensorIngest(t *testing.T) {
	ctx, client := testdb.New(t)

	asset, err := client.Asset.Create().
		SetHostname("probe-a").SetIPAddrs([]string{"10.0.0.5"}).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	s := &SensorServer{DB: client, Rules: loadDNSRule(t), Suppress: suppress.New(client, time.Hour)}
	ded := dedup.New(time.Hour)
	now := time.Now().UnixNano()

	batch := &pb.FlowBatch{
		SensorId: "sensor-1",
		Flows: []*pb.FlowRecord{
			{SrcIp: "10.0.0.5", DstIp: "8.8.8.8", SrcPort: 5353, DstPort: 53,
				StartUnixNs: now, Protocol: 17, DnsQuery: "evil.example.com"},
			{SrcIp: "10.0.0.6", DstIp: "1.2.3.4", SrcPort: 40000, DstPort: 443,
				StartUnixNs: now, Protocol: 6}, // 纯网络流，无 DNS
		},
	}

	if err := s.ingest(ctx, batch, ded); err != nil {
		t.Fatalf("ingest 失败: %v", err)
	}

	// 事件：DNS 流 → 4003，网络流 → 4001
	evts, err := client.Event.Query().Order(ent.Asc("ts")).All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var has4001, has4003 bool
	for _, e := range evts {
		if e.ClassUID == 4001 {
			has4001 = true
		}
		if e.ClassUID == 4003 {
			has4003 = true
		}
	}
	if !has4001 || !has4003 {
		t.Errorf("应同时产生 4001 与 4003 事件，实际 classes 不齐")
	}

	// 归属：10.0.0.5 命中 probe-a
	if evts[0].AssetID == nil || *evts[0].AssetID != asset.ID {
		t.Errorf("DNS 流应归属到 probe-a，得到 %v", evts[0].AssetID)
	}

	// 仅 DNS evil 流命中规则 → 1 条告警
	alerts, err := client.Alert.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].RuleID != "dns-evil" {
		t.Errorf("应恰好命中 1 条 dns-evil 告警，实际 %+v", alerts)
	}

	// 同指纹（同 src ip + rule）重复 ingest → 去重
	before := len(alerts)
	if err := s.ingest(ctx, batch, ded); err != nil {
		t.Fatal(err)
	}
	after, _ := client.Alert.Query().Count(ctx)
	if after != before {
		t.Errorf("重复 ingest 不应新增告警，before=%d after=%d", before, after)
	}
}
