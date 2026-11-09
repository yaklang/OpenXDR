//go:build integration

package grpcsvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"openxdr/server/ent/asset"
	"openxdr/server/internal/dedup"
	"openxdr/server/internal/enroll"
	"openxdr/server/internal/intel"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
	"openxdr/server/pb"
)

type fakeSensorDownload struct {
	ctx  context.Context
	data bytes.Buffer
}

func (f *fakeSensorDownload) Send(c *pb.SensorChunk) error { f.data.Write(c.Data); return nil }
func (f *fakeSensorDownload) Context() context.Context     { return f.ctx }
func (f *fakeSensorDownload) SetHeader(metadata.MD) error  { return nil }
func (f *fakeSensorDownload) SendHeader(metadata.MD) error { return nil }
func (f *fakeSensorDownload) SetTrailer(metadata.MD)       {}
func (f *fakeSensorDownload) SendMsg(any) error            { return nil }
func (f *fakeSensorDownload) RecvMsg(any) error            { return nil }

var _ grpc.ServerStreamingServer[pb.SensorChunk] = (*fakeSensorDownload)(nil)

func sensorSample(seq uint64, state string) string {
	raw, _ := json.Marshal(map[string]any{
		"bootId": "8a2c1f0e-5d1b-4f6e-9a3c-2b7d4e6f8a10", "sequence": seq, "reportedUnixMs": time.Now().UnixMilli(),
		"iface": "eth0", "backend": "afpacket", "workers": 2, "workersAlive": 2,
		"packets": 1000, "flows": 20, "kernelDrops": 0, "queueDrops": 0, "packetRate": 50, "flowRate": 60,
		"capabilities": map[string]any{"capture": map[string]string{"path": "afpacket:eth0", "state": state}},
	})
	return string(raw)
}

// 探针注册挂到同名资产上、不动 agent 的心跳；绑定证书只能以自己的主机名注册与上报；
// 抓包状态按序号只进不退；分发目录版本不同时下发升级，下载按哈希核对。
func TestSensorRegisterHealthUpgrade(t *testing.T) {
	ctx, client := testdb.New(t)
	agentSeen := time.Now().Add(-time.Hour).Truncate(time.Second)
	gw := client.Asset.Create().SetHostname("gw01").SetAgentID(uuid.New()).SetLastSeen(agentSeen).
		SetIPAddrs([]string{"203.0.113.10"}).SaveX(ctx)

	dir := t.TempDir()
	binary := bytes.Repeat([]byte("sensor-v2"), 50_000)
	if err := os.WriteFile(filepath.Join(dir, "openxdr-sensor-linux-amd64"), binary, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binary)
	want := hex.EncodeToString(sum[:])
	srv := &SensorServer{DB: client, Dist: enroll.SensorDist(dir), AutoUpgrade: true}

	if _, err := srv.Register(ctxWithCN("sensor:gw01"), &pb.SensorRegisterRequest{Hostname: "db01"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("探针证书冒名注册应拒绝：%v", err)
	}
	resp, err := srv.Register(ctxWithCN("sensor:gw01"), &pb.SensorRegisterRequest{
		Hostname: "gw01", Version: "0.1.0", Arch: "x86_64", BinarySha256: "old", IpAddrs: []string{"10.9.9.9"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.UpgradeSha256 != want || resp.UpgradePlatform != "linux-amd64" {
		t.Fatalf("版本不同应下发升级：%+v", resp)
	}
	got := client.Asset.GetX(ctx, gw.ID)
	if got.SensorVersion == nil || *got.SensorVersion != "0.1.0" || got.SensorSeen == nil || !got.LastSeen.Equal(agentSeen) {
		t.Fatalf("应记探针版本与心跳、不刷新 agent 心跳：%+v", got)
	}
	if len(got.IPAddrs) != 1 || got.IPAddrs[0] != "203.0.113.10" {
		t.Fatalf("同机有 agent 时地址以 agent 为准：%v", got.IPAddrs)
	}
	if r, _ := srv.Register(ctx, &pb.SensorRegisterRequest{Hostname: "gw01", Arch: "x86_64", BinarySha256: want}); r.UpgradeSha256 != "" {
		t.Error("已是分发版本不应再升级")
	}
	// 只有探针的主机：新建资产并登记地址
	if _, err := srv.Register(ctxWithCN("sensor:tap01"), &pb.SensorRegisterRequest{Hostname: "tap01", IpAddrs: []string{"10.1.1.5"}}); err != nil {
		t.Fatal(err)
	}
	tap := client.Asset.Query().Where(asset.HostnameEQ("tap01")).OnlyX(ctx)
	if tap.AgentID != nil || len(tap.IPAddrs) != 1 || tap.Os == nil || *tap.Os != "linux" {
		t.Fatalf("纯探针主机应建资产并登记地址：%+v", tap)
	}

	// Windows 探针：资产记 windows，按 windows 平台的安装包升级
	winBinary := []byte("sensor-windows")
	if err := os.WriteFile(filepath.Join(dir, "openxdr-sensor-windows-amd64.exe"), winBinary, 0o644); err != nil {
		t.Fatal(err)
	}
	winResp, err := srv.Register(ctxWithCN("sensor:win01"), &pb.SensorRegisterRequest{
		Hostname: "win01", Os: "windows", Arch: "x86_64", BinarySha256: "old"})
	if err != nil {
		t.Fatal(err)
	}
	winSum := sha256.Sum256(winBinary)
	if winResp.UpgradePlatform != "windows-amd64" || winResp.UpgradeSha256 != hex.EncodeToString(winSum[:]) {
		t.Fatalf("Windows 探针应按 windows 安装包升级：%+v", winResp)
	}
	if win := client.Asset.Query().Where(asset.HostnameEQ("win01")).OnlyX(ctx); win.Os == nil || *win.Os != "windows" {
		t.Fatalf("Windows 探针的资产应记 windows：%+v", win)
	}

	stream := &fakeSensorDownload{ctx: ctx}
	if err := srv.DownloadSensor(&pb.SensorDownloadRequest{Platform: "linux-amd64", Sha256: want}, stream); err != nil || !bytes.Equal(stream.data.Bytes(), binary) {
		t.Fatalf("下载应与安装包一致：%v", err)
	}
	if err := srv.DownloadSensor(&pb.SensorDownloadRequest{Platform: "linux-amd64", Sha256: "stale"}, &fakeSensorDownload{ctx: ctx}); err == nil {
		t.Error("哈希不符应拒绝下载")
	}

	report := func(c context.Context, host, raw string) error {
		_, err := srv.ReportHealth(c, &pb.SensorHealthRequest{Hostname: host, HealthJson: raw})
		return err
	}
	if err := report(ctxWithCN("sensor:tap01"), "gw01", sensorSample(1, "active")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("跨主机写状态应拒绝：%v", err)
	}
	if err := report(ctx, "nobody", sensorSample(1, "active")); status.Code(err) != codes.NotFound {
		t.Fatalf("未注册的探针应 NotFound：%v", err)
	}
	if err := report(ctx, "gw01", `{"bootId":"x"}`); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("坏快照应拒绝：%v", err)
	}
	if err := report(ctxWithCN("sensor:gw01"), "gw01", sensorSample(2, "degraded")); err != nil {
		t.Fatal(err)
	}
	if err := report(ctx, "gw01", sensorSample(1, "active")); err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	_ = json.Unmarshal(client.Asset.GetX(ctx, gw.ID).SensorHealth, &saved)
	if saved["sequence"] != float64(2) || saved["receivedAt"] == nil || saved["iface"] != "eth0" {
		t.Fatalf("倒序快照不应覆盖，且应带服务端时间：%v", saved)
	}
	if client.Asset.GetX(ctx, gw.ID).CollectorHealth != nil {
		t.Fatal("探针状态不应写进 agent 的采集状态")
	}
}

// 绑定证书的 sensor_id 必须对得上；公网打进网关的会话归到网关上，只握手的事实写进事件体。
func TestSensorFlowsIdentityAndInboundAttribution(t *testing.T) {
	ctx, client := testdb.New(t)
	gw := client.Asset.Create().SetHostname("gw01").SetOs("linux").SetIPAddrs([]string{"203.0.113.10"}).SaveX(ctx)
	srv := &SensorServer{DB: client, DedupWindow: time.Hour, Rules: loadDNSRule(t),
		Suppress: suppress.New(client, time.Hour), Intel: intel.New(client, time.Hour)}

	stream := newFakeFlowStream(ctxWithCN("sensor:tap01"), []*pb.FlowBatch{{SensorId: "gw01"}})
	if err := srv.ReportFlows(stream); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("冒名上报会话应拒绝：%v", err)
	}

	now := time.Now().UnixNano()
	batch := &pb.FlowBatch{SensorId: "gw01", Flows: []*pb.FlowRecord{
		{SrcIp: "198.51.100.7", DstIp: "203.0.113.10", SrcPort: 40000, DstPort: 443, Protocol: 6, StartUnixNs: now,
			Ja3: "ja3-scan", TlsHandshakeOnly: true},
		{SrcIp: "198.51.100.8", DstIp: "192.0.2.1", SrcPort: 40001, DstPort: 443, Protocol: 6, StartUnixNs: now},
	}}
	if err := srv.ingest(ctx, batch, dedup.New(time.Hour)); err != nil {
		t.Fatal(err)
	}
	events := client.Event.Query().AllX(ctx)
	if len(events) != 2 {
		t.Fatalf("应落两条事件：%d", len(events))
	}
	for _, e := range events {
		var raw map[string]any
		_ = json.Unmarshal(e.Raw, &raw)
		src := raw["src_endpoint"].(map[string]any)["ip"]
		switch src {
		case "198.51.100.7":
			if e.AssetID == nil || *e.AssetID != gw.ID {
				t.Errorf("公网打进网关的会话应归到网关：%v", e.AssetID)
			}
			if tls, _ := raw["tls"].(map[string]any); tls["handshake_only"] != true {
				t.Errorf("应标注只握手：%v", raw["tls"])
			}
		case "198.51.100.8":
			if e.AssetID != nil {
				t.Errorf("两头都不是纳管资产不应归属：%v", e.AssetID)
			}
		}
	}
}
