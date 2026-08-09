//go:build integration

package grpcsvc

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/sigma"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

// fakeFlowStream 是 grpc.ClientStreamingServer 的最小实现，用于驱动 ReportFlows 的接收循环。
type fakeFlowStream struct {
	ctx  context.Context
	msgs []*pb.FlowBatch
	ack  *pb.FlowAck
	seen int
}

func newFakeFlowStream(ctx context.Context, msgs []*pb.FlowBatch) *fakeFlowStream {
	return &fakeFlowStream{ctx: ctx, msgs: msgs}
}

func (f *fakeFlowStream) Recv() (*pb.FlowBatch, error) {
	if f.seen >= len(f.msgs) {
		return nil, io.EOF
	}
	m := f.msgs[f.seen]
	f.seen++
	return m, nil
}
func (f *fakeFlowStream) SendAndClose(a *pb.FlowAck) error { f.ack = a; return nil }
func (f *fakeFlowStream) Context() context.Context         { return f.ctx }
func (f *fakeFlowStream) SetHeader(metadata.MD) error      { return nil }
func (f *fakeFlowStream) SendHeader(metadata.MD) error     { return nil }
func (f *fakeFlowStream) SetTrailer(metadata.MD)           {}
func (f *fakeFlowStream) SendMsg(any) error                { return nil }
func (f *fakeFlowStream) RecvMsg(any) error                { return nil }

var _ grpc.ClientStreamingServer[pb.FlowBatch, pb.FlowAck] = (*fakeFlowStream)(nil)

// sensor 规则加载。
func loadEvilYaml(t *testing.T) *sigma.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dns.yml"), []byte(dnsRule), 0o644); err != nil {
		t.Fatal(err)
	}
	return sigma.LoadDir(dir)
}

// ReportFlows 流式接收多批：第一批评审建告警，第二批同指纹被去重；
// EOF 后 ack 返回接收总数。
func TestSensorReportFlowsStream(t *testing.T) {
	ctx, client := testdb.New(t)
	if _, err := client.Asset.Create().SetHostname("probe-a").SetIPAddrs([]string{"10.0.0.5"}).Save(ctx); err != nil {
		t.Fatal(err)
	}

	s := &SensorServer{
		DB:          client,
		Rules:       loadEvilYaml(t),
		DedupWindow: time.Hour,
		Suppress:    suppress.New(client, time.Hour),
		Intel:       intel.New(client, time.Hour),
	}

	now := time.Now().UnixNano()
	mkFlow := func(dns string) *pb.FlowRecord {
		return &pb.FlowRecord{SrcIp: "10.0.0.5", DstIp: "8.8.8.8", SrcPort: 5353,
			DstPort: 53, StartUnixNs: now, Protocol: 17, DnsQuery: dns}
	}
	// 第一批：1 条命中 evil 的 DNS + 1 条正常 DNS
	// 第二批：同一 DNS 查询重复上报（应去重不新增告警）+ 1 条纯网络流
	stream := newFakeFlowStream(ctx, []*pb.FlowBatch{
		{SensorId: "sensor-1", Flows: []*pb.FlowRecord{mkFlow("evil.example.com"), mkFlow("ok.example.com")}},
		{SensorId: "sensor-1", Flows: []*pb.FlowRecord{mkFlow("evil.example.com"), {SrcIp: "10.0.0.6", DstIp: "1.2.3.4", SrcPort: 40000, DstPort: 443, StartUnixNs: now, Protocol: 6}}},
	})

	before, _ := client.Alert.Query().Count(ctx)
	if err := s.ReportFlows(stream); err != nil {
		t.Fatalf("ReportFlows 失败: %v", err)
	}
	after, _ := client.Alert.Query().Count(ctx)
	if after != before+1 {
		t.Errorf("应新增 1 条告警，before=%d after=%d", before, after)
	}

	// ack 计数：总流数 = 2 + 2 = 4
	if stream.ack == nil || stream.ack.Received != 4 {
		t.Errorf("ack.Received = %v, want 4", stream.ack)
	}
}
