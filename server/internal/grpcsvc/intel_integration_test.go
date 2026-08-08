//go:build integration

package grpcsvc

import (
	"context"
	"testing"
	"time"

	entintel "openxdr/server/ent/intel"
	"openxdr/server/internal/dedup"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

// 情报碰撞主链路：IOC 入库 → sensor 流量撞上恶意 IP 与恶意域名 →
// 产生 intel 告警且与规则告警互不干扰；命中计数回写到情报条目。
func TestIntelMatchOnSensorFlow(t *testing.T) {
	ctx, client := testdb.New(t)

	if err := client.Intel.Create().SetKind(entintel.KindIP).SetValue("6.6.6.6").SetSeverity(5).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.Intel.Create().SetKind(entintel.KindDomain).SetValue("evil.example.com").Exec(ctx); err != nil {
		t.Fatal(err)
	}

	store := intel.New(client, time.Hour)
	store.Reload(ctx)

	s := &SensorServer{DB: client, Rules: sigma.LoadDir(t.TempDir()),
		Suppress: suppress.New(client, time.Hour), Intel: store}
	now := time.Now().UnixNano()

	batch := &pb.FlowBatch{
		SensorId: "sensor-1",
		Flows: []*pb.FlowRecord{
			// 外连恶意 IP
			{SrcIp: "10.0.0.5", DstIp: "6.6.6.6", SrcPort: 40000, DstPort: 443,
				StartUnixNs: now, Protocol: 6},
			// 查询恶意域名的子域
			{SrcIp: "10.0.0.5", DstIp: "8.8.8.8", SrcPort: 5353, DstPort: 53,
				StartUnixNs: now, Protocol: 17, DnsQuery: "c2.evil.example.com"},
			// 干净流量
			{SrcIp: "10.0.0.6", DstIp: "1.1.1.1", SrcPort: 40001, DstPort: 443,
				StartUnixNs: now, Protocol: 6},
		},
	}
	if err := s.ingest(ctx, batch, dedup.New(time.Hour)); err != nil {
		t.Fatalf("ingest 失败: %v", err)
	}

	alerts, err := client.Alert.Query().All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int16{}
	for _, a := range alerts {
		got[a.RuleID] = a.Severity
	}
	if len(alerts) != 2 || got["intel:ip:6.6.6.6"] != 5 || got["intel:domain:evil.example.com"] == 0 {
		t.Fatalf("应恰好产生两条 intel 告警，实际 %+v", got)
	}

	// 命中计数经 flush 回写
	flushIntel(ctx, store, t)
	rows, _ := client.Intel.Query().All(ctx)
	for _, r := range rows {
		if r.MatchedCount != 1 {
			t.Errorf("IOC %s:%s 命中计数应为 1，实际 %d", r.Kind, r.Value, r.MatchedCount)
		}
	}
}

// flush 未导出，借 Run 的退出路径触发回写。
func flushIntel(ctx context.Context, store *intel.Store, t *testing.T) {
	t.Helper()
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { store.Run(runCtx); close(done) }()
	cancel()
	<-done
}
