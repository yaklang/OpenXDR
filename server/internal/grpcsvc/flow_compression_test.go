package grpcsvc

import (
	"bytes"
	"io"
	"testing"

	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/proto"

	"openxdr/server/pb"
)

// 代表性探针批次取真实镜像口上最常见的重复内容：同一批会话共用少数几个
// SNI、JA3 指纹、证书与 User-Agent，gzip 压的正是这些重复字节。
const (
	sampleJA3  = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
	sampleJA3S = "771,4865-4866-4867-49195-49199,0-23-65281,29-23-24"
	sampleUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

// flowSpec 一条会话的可变字段，固定字段在 sampleFlows 里统一补齐。
type flowSpec struct {
	src, dst      string
	sport, dport  uint32
	proto         uint32
	tcpFlags      uint32
	sni, ja3      string
	ja3s          string
	httpHost      string
	httpURI       string
	ua            string
	dnsQuery      string
	dnsRcode      uint32
	dnsAnswers    []string
	subject       string
	issuer        string
	selfSigned    bool
	handshakeOnly bool
}

// sampleFlows 造 32 条会话：TLS 1.2（SNI/JA3/JA3S/证书）、TLS 1.3 只握手、HTTP、DNS 与 NXDOMAIN。
// 同一组会话重复四轮，只有端口、计数与时间戳不同，贴近真实批次的重复度。
func sampleFlows() []*pb.FlowRecord {
	specs := []flowSpec{
		{
			src: "10.20.3.11", dst: "140.82.113.6", sport: 51544, dport: 443, proto: 6, tcpFlags: 0x18,
			sni: "api.github.com", ja3: sampleJA3, ja3s: sampleJA3S,
			subject: "CN=github.com", issuer: "CN=DigiCert TLS RSA SHA256 2020 CA1",
		},
		{
			src: "10.20.3.12", dst: "20.190.151.7", sport: 51602, dport: 443, proto: 6, tcpFlags: 0x18,
			sni: "login.microsoftonline.com", ja3: sampleJA3,
		},
		{
			src: "10.20.3.13", dst: "151.101.1.229", sport: 51688, dport: 443, proto: 6, tcpFlags: 0x11,
			sni: "cdn.jsdelivr.net", ja3: sampleJA3, handshakeOnly: true,
		},
		{
			src: "10.20.3.14", dst: "142.250.72.14", sport: 51730, dport: 80, proto: 6, tcpFlags: 0x18,
			httpHost: "update.googleapis.com", httpURI: "/service/update2/json?cup2key=14:abc", ua: sampleUA,
		},
		{
			src: "10.20.3.21", dst: "203.0.113.10", sport: 51890, dport: 8443, proto: 6, tcpFlags: 0x1b,
			sni: "oa.corp.example", ja3: sampleJA3, ja3s: sampleJA3S,
			subject: "CN=oa.corp.example", issuer: "CN=oa.corp.example", selfSigned: true,
		},
		{
			src: "10.20.3.31", dst: "8.8.8.8", sport: 53001, dport: 53, proto: 17,
			dnsQuery: "example.com", dnsAnswers: []string{"93.184.216.34", "93.184.216.35"},
		},
		{
			src: "10.20.3.32", dst: "10.20.0.10", sport: 53002, dport: 53, proto: 17,
			dnsQuery: "nonexistent.corp.example", dnsRcode: 3,
		},
		{
			src: "10.20.3.41", dst: "52.96.104.18", sport: 51990, dport: 443, proto: 6, tcpFlags: 0x18,
			sni: "outlook.office365.com", ja3: sampleJA3, ja3s: sampleJA3S,
			subject: "CN=outlook.office365.com", issuer: "CN=Microsoft RSA TLS CA 02",
		},
	}
	const baseNS int64 = 1_760_000_000_000_000_000
	out := make([]*pb.FlowRecord, 0, len(specs)*4)
	for round := range 4 {
		for i, s := range specs {
			start := baseNS + int64(round)*60_000_000_000
			out = append(out, &pb.FlowRecord{
				StartUnixNs:       start,
				EndUnixNs:         start + 2_400_000_000,
				SrcIp:             s.src,
				DstIp:             s.dst,
				SrcPort:           s.sport + uint32(round),
				DstPort:           s.dport,
				Protocol:          s.proto,
				SrcPackets:        uint64(6 + i + round),
				SrcBytes:          uint64(880 + 213*i + 7*round),
				DstPackets:        uint64(7 + i + round),
				DstBytes:          uint64(6200 + 1031*i + 11*round),
				TcpFlags:          s.tcpFlags,
				DnsQuery:          s.dnsQuery,
				DnsRcode:          s.dnsRcode,
				DnsAnswers:        s.dnsAnswers,
				TlsSni:            s.sni,
				Ja3:               s.ja3,
				Ja3S:              s.ja3s,
				HttpHost:          s.httpHost,
				HttpUri:           s.httpURI,
				HttpUserAgent:     s.ua,
				TlsCertSubject:    s.subject,
				TlsCertIssuer:     s.issuer,
				TlsCertSelfSigned: s.selfSigned,
				TlsCertNotBefore:  1_753_000_000,
				TlsCertNotAfter:   1_784_000_000,
				TlsHandshakeOnly:  s.handshakeOnly,
			})
		}
	}
	return out
}

// TestFlowBatchGzipRoundTrip 同时验证两件事：
//  1. 服务端确实注册了 gzip 编码器（grpcsvc 的空白导入生效），探针压上来的消息能解；
//  2. 压缩只改线上字节：解压反序列化后，FlowBatch 每条 FlowRecord 逐字段与原始一致。
func TestFlowBatchGzipRoundTrip(t *testing.T) {
	batch := &pb.FlowBatch{SensorId: "sensor-gw01", Flows: sampleFlows(), DroppedPackets: 37}
	raw, err := proto.Marshal(batch)
	if err != nil {
		t.Fatalf("序列化 FlowBatch 失败：%v", err)
	}

	compressor := encoding.GetCompressor("gzip")
	if compressor == nil {
		t.Fatal("服务端没有注册 gzip 编码器：确认 grpcsvc 空白导入了 google.golang.org/grpc/encoding/gzip")
	}
	var wire bytes.Buffer
	zw, err := compressor.Compress(&wire)
	if err != nil {
		t.Fatalf("gzip 压缩失败：%v", err)
	}
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("写入压缩流失败：%v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("关闭压缩流失败：%v", err)
	}
	compressed := wire.Bytes()

	ratio := float64(len(raw)) / float64(len(compressed))
	t.Logf("代表性 FlowBatch（%d 条会话，含 TLS/HTTP/DNS 元数据）：未压缩 %d 字节 → gzip %d 字节，"+
		"压缩比 %.2f:1，节省 %.1f%%",
		len(batch.Flows), len(raw), len(compressed), ratio, 100*(1-float64(len(compressed))/float64(len(raw))))

	if len(compressed) >= len(raw) {
		t.Fatalf("gzip 后应小于原始报文：未压缩 %d 字节，压缩后 %d 字节", len(raw), len(compressed))
	}

	// grpc-go 的 Compressor 同时带 Decompress：注册一个 gzip 编码器，
	// 收发两侧都用它，所以这里用同一个已注册的 compressor 走解压路径。
	zr, err := compressor.Decompress(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("gzip 解压失败：%v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("读取解压流失败：%v", err)
	}
	if !bytes.Equal(plain, raw) {
		t.Fatalf("解压后的字节与原始报文不一致：%d 字节 vs %d 字节", len(plain), len(raw))
	}

	var got pb.FlowBatch
	if err := proto.Unmarshal(plain, &got); err != nil {
		t.Fatalf("解压后反序列化失败：%v", err)
	}
	if !proto.Equal(batch, &got) {
		t.Fatal("压缩往返后的 FlowBatch 与原始消息不等价")
	}
	if got.SensorId != batch.SensorId || got.DroppedPackets != batch.DroppedPackets {
		t.Fatalf("批头字段变了：sensor_id=%q dropped_packets=%d，原始为 %q / %d",
			got.SensorId, got.DroppedPackets, batch.SensorId, batch.DroppedPackets)
	}
	if len(got.Flows) != len(batch.Flows) {
		t.Fatalf("会话条数变了：%d，原始 %d", len(got.Flows), len(batch.Flows))
	}
	for i, want := range batch.Flows {
		have := got.Flows[i]
		// proto.Equal 逐字段比较（含 dns_answers 这类 repeated 与 bool），字段级回归都拦得住
		if !proto.Equal(want, have) {
			t.Fatalf("第 %d 条 FlowRecord 压缩往返后不一致", i)
		}
		// conn_tuple 是资产归属与检测的基准，单独点名比较
		if want.SrcIp != have.SrcIp || want.DstIp != have.DstIp ||
			want.SrcPort != have.SrcPort || want.DstPort != have.DstPort || want.Protocol != have.Protocol {
			t.Fatalf("第 %d 条会话的 conn_tuple 变了：%s:%d→%s:%d/%d 变成 %s:%d→%s:%d/%d",
				i, want.SrcIp, want.SrcPort, want.DstIp, want.DstPort, want.Protocol,
				have.SrcIp, have.SrcPort, have.DstIp, have.DstPort, have.Protocol)
		}
	}
}
